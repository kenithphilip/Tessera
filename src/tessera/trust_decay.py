"""Adaptive trust scoring with time-based decay and anomaly degradation.

TrustLabel signatures are immutable, so decay is computed on the fly from
segment age and observed anomaly counts. This module provides the policy,
the per-server anomaly tracker, and a Context wrapper that presents a
decayed min_trust to the policy engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from tessera.context import Context
from tessera.labels import Origin, TrustLevel, TrustLabel


@dataclass(frozen=True)
class TrustDecayPolicy:
    """Configuration for time-based trust decay and anomaly penalties.

    Args:
        segment_max_age: Segments older than this start losing trust.
        decay_rate: Trust points lost per minute past segment_max_age.
        anomaly_penalty: Trust points deducted per scanner flag.
        min_effective_trust: Floor value; trust never decays below this.
    """

    segment_max_age: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    decay_rate: float = 0.5
    anomaly_penalty: float = 10.0
    min_effective_trust: int = 0


_DEFAULT_POLICY = TrustDecayPolicy()


def effective_trust(
    label: TrustLabel,
    age: timedelta,
    anomaly_count: int = 0,
    policy: TrustDecayPolicy | None = None,
) -> int:
    """Compute time-decayed trust for a single label.

    If the segment is younger than policy.segment_max_age, the original
    trust level is returned unchanged. Past that threshold, trust decays
    linearly at policy.decay_rate points per minute, with an additional
    flat penalty per recorded anomaly.

    Args:
        label: The provenance label whose trust level is the baseline.
        age: How long ago the segment was created.
        anomaly_count: Number of scanner flags recorded for this segment
            or its originating server.
        policy: Decay parameters. Uses module defaults when None.

    Returns:
        The effective trust score, clamped to policy.min_effective_trust.
    """
    p = policy or _DEFAULT_POLICY
    base = int(label.trust_level)

    if age <= p.segment_max_age:
        penalty = anomaly_count * p.anomaly_penalty
        return max(int(base - penalty), p.min_effective_trust)

    overage_minutes = (age - p.segment_max_age).total_seconds() / 60.0
    decay = overage_minutes * p.decay_rate + anomaly_count * p.anomaly_penalty
    return max(int(base - decay), p.min_effective_trust)


class ToolServerTrustTracker:
    """Tracks per-server anomaly counts for trust degradation.

    Each call to record_anomaly increments a counter that feeds into
    effective_trust as the anomaly_count parameter. Call reset after
    manual review to clear a server's history.

    Args:
        policy: Decay parameters. Uses module defaults when None.
    """

    def __init__(self, policy: TrustDecayPolicy | None = None) -> None:
        self._policy = policy or _DEFAULT_POLICY
        self._anomalies: dict[str, int] = {}

    def record_anomaly(self, server_name: str) -> None:
        """Increment the anomaly count for a server.

        Args:
            server_name: Identifier of the tool server.
        """
        self._anomalies[server_name] = self._anomalies.get(server_name, 0) + 1

    def anomaly_count(self, server_name: str) -> int:
        """Return the current anomaly count for a server.

        Args:
            server_name: Identifier of the tool server.

        Returns:
            Number of recorded anomalies, or 0 if none.
        """
        return self._anomalies.get(server_name, 0)

    def effective_server_trust(
        self, server_name: str, base_trust: TrustLevel, age: timedelta
    ) -> int:
        """Compute decayed trust for a server's outputs.

        Builds a synthetic label from base_trust and delegates to
        effective_trust with this server's anomaly count.

        Args:
            server_name: Identifier of the tool server.
            base_trust: The static trust level assigned to this server.
            age: Age of the segment being evaluated.

        Returns:
            The effective trust score after decay and anomaly penalties.
        """
        label = TrustLabel(
            origin=Origin.TOOL, principal=server_name, trust_level=base_trust
        )
        return effective_trust(
            label, age, self.anomaly_count(server_name), self._policy
        )

    def reset(self, server_name: str) -> None:
        """Clear the anomaly count for a server (e.g. after manual review).

        Args:
            server_name: Identifier of the tool server.
        """
        self._anomalies.pop(server_name, None)


class DecayAwareContext:
    """Wraps a Context and provides a decayed min_trust property.

    TrustLabel does not carry a timestamp field (the nonce is random, not
    time-based). Until TrustLabel gains a timestamp, segment ages must be
    supplied explicitly via segment_ages. When not provided, all segments
    are treated as age-zero (no decay applied).

    This object can be passed to Policy.evaluate() in place of a raw
    Context when the caller wants time-decay semantics.

    Args:
        context: The underlying Context to wrap.
        policy: Decay parameters. Uses module defaults when None.
        segment_ages: Mapping of segment index to age. Segments not in
            the map are treated as age-zero.
        tracker: Optional server tracker for anomaly-based degradation.
            When provided, anomaly counts are looked up by each segment's
            label.principal.
    """

    def __init__(
        self,
        context: Context,
        policy: TrustDecayPolicy | None = None,
        segment_ages: dict[int, timedelta] | None = None,
        tracker: ToolServerTrustTracker | None = None,
    ) -> None:
        self._context = context
        self._policy = policy or _DEFAULT_POLICY
        self._segment_ages = segment_ages or {}
        self._tracker = tracker

    @property
    def segments(self) -> list:
        """Delegate to the wrapped context's segments."""
        return self._context.segments

    @property
    def principal(self) -> str | None:
        """Delegate to the wrapped context's principal.

        PolicyInput.from_evaluation needs this field. Decay affects trust
        levels, not identity, so the underlying value passes through.
        """
        return self._context.principal

    @property
    def max_trust(self) -> TrustLevel:
        """Delegate to the wrapped context's max_trust.

        Decay can only reduce trust, never raise it, so max_trust is
        passed through unchanged.
        """
        return self._context.max_trust

    @property
    def effective_readers(self) -> frozenset[str] | None:
        """Delegate to the wrapped context's effective_readers.

        Readers are a per-segment attribute independent of trust decay.
        """
        return self._context.effective_readers

    @property
    def min_trust(self) -> TrustLevel:
        """Minimum effective trust across all segments after decay.

        Iterates each segment, computes its effective trust using the
        supplied age (defaulting to zero) and any anomaly count from
        the tracker, then returns the minimum as a TrustLevel.

        Returns:
            The lowest decayed trust level, mapped back to the nearest
            TrustLevel enum value at or below the computed score.
        """
        if not self._context.segments:
            return TrustLevel.SYSTEM

        scores: list[int] = []
        for idx, seg in enumerate(self._context.segments):
            age = self._segment_ages.get(idx, timedelta(0))
            anomalies = 0
            if self._tracker is not None:
                anomalies = self._tracker.anomaly_count(seg.label.principal)
            score = effective_trust(seg.label, age, anomalies, self._policy)
            scores.append(score)

        min_score = min(scores)
        # Map back to the highest TrustLevel enum value at or below min_score.
        for level in sorted(TrustLevel, reverse=True):
            if int(level) <= min_score:
                return level
        return TrustLevel.UNTRUSTED
