"""MCP Security Score: per-server composite trust signal.

The score is a deterministic 0-100 number recomputed on every
``tools/list`` response. It composes the inputs Tessera already
collects:

- Trust tier (COMMUNITY=0 / VERIFIED=50 / ATTESTED=100)
- Drift signals (no drift = full credit; per-alert deductions)
- Critical-args coverage (per spec table)
- Sigstore Rekor proof age
- Recent SecurityEvent counts for the server

The number is NOT a probability; it is an operator-readable
ranking score. The thresholds (warn at 60, deny at 40) are in the
operator-facing CLI, not here.

Reference
---------

- :mod:`tessera.mcp.tier` (tier source)
- :mod:`tessera.mcp.drift` (drift signals)
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.4
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

from tessera.events import EventKind
from tessera.mcp.tier import TierAssignment, TrustTier


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """Per-server inputs the score formula consumes."""

    server_id: str
    tier: TierAssignment
    drift_alert_kinds: tuple[EventKind, ...] = ()
    rekor_age_days: float | None = None
    critical_args_specs_present: bool = False
    recent_denials_24h: int = 0
    tools_count: int = 0


@dataclass(frozen=True, slots=True)
class ScoreBreakdown:
    """Per-component contributions to the final score.

    Attributes:
        tier_component: 0..40 contribution from trust tier.
        drift_component: 0..20 contribution from drift signals
            (full 20 when no recent drift; deductions per alert kind).
        rekor_component: 0..15 contribution from Rekor proof age
            freshness (0 if no proof; full 15 when < 30 days).
        critical_args_component: 0..15 contribution from
            critical-args spec coverage.
        denials_component: 0..10 deduction for recent policy denials
            (full 10 when zero; 0 when more than 10 in the last
            24h).
    """

    tier_component: float
    drift_component: float
    rekor_component: float
    critical_args_component: float
    denials_component: float

    @property
    def total(self) -> float:
        return (
            self.tier_component
            + self.drift_component
            + self.rekor_component
            + self.critical_args_component
            + self.denials_component
        )


@dataclass(frozen=True, slots=True)
class SecurityScore:
    """Final per-server score and the breakdown that produced it."""

    server_id: str
    score: float
    breakdown: ScoreBreakdown
    computed_at: str  # ISO-8601 UTC

    def to_otel_attributes(self) -> dict[str, float | str]:
        """Return the score as OTel span attributes for export."""
        return {
            "tessera.mcp.security_score": self.score,
            "tessera.mcp.security_score.tier": self.breakdown.tier_component,
            "tessera.mcp.security_score.drift": self.breakdown.drift_component,
            "tessera.mcp.security_score.rekor": self.breakdown.rekor_component,
            "tessera.mcp.security_score.critical_args": (
                self.breakdown.critical_args_component
            ),
            "tessera.mcp.security_score.denials": (
                self.breakdown.denials_component
            ),
            "tessera.mcp.server_id": self.server_id,
        }


def _tier_component(tier: TrustTier) -> float:
    return {
        TrustTier.COMMUNITY: 0.0,
        TrustTier.VERIFIED: 25.0,
        TrustTier.ATTESTED: 40.0,
    }[tier]


def _drift_component(alerts: Iterable[EventKind]) -> float:
    deductions = {
        EventKind.MCP_DRIFT_SHAPE: 10.0,
        EventKind.MCP_DRIFT_LATENCY: 5.0,
        EventKind.MCP_DRIFT_DISTRIBUTION: 5.0,
    }
    score = 20.0
    for kind in alerts:
        score -= deductions.get(kind, 0.0)
    return max(score, 0.0)


def _rekor_component(rekor_age_days: float | None) -> float:
    if rekor_age_days is None:
        return 0.0
    if rekor_age_days <= 7:
        return 15.0
    if rekor_age_days <= 30:
        # Linear taper from 15 at 7 days to 7.5 at 30 days.
        return 15.0 - 7.5 * ((rekor_age_days - 7) / 23)
    if rekor_age_days <= 90:
        # Continued taper to 0 at 90 days.
        return max(7.5 - 7.5 * ((rekor_age_days - 30) / 60), 0.0)
    return 0.0


def _critical_args_component(present: bool) -> float:
    return 15.0 if present else 0.0


def _denials_component(recent_denials: int) -> float:
    if recent_denials == 0:
        return 10.0
    if recent_denials >= 10:
        return 0.0
    return 10.0 - recent_denials


def compute(inputs: ScoreInputs) -> SecurityScore:
    """Run the score formula on one set of inputs."""
    breakdown = ScoreBreakdown(
        tier_component=_tier_component(inputs.tier.tier),
        drift_component=_drift_component(inputs.drift_alert_kinds),
        rekor_component=_rekor_component(inputs.rekor_age_days),
        critical_args_component=_critical_args_component(
            inputs.critical_args_specs_present
        ),
        denials_component=_denials_component(inputs.recent_denials_24h),
    )
    from datetime import datetime, timezone

    return SecurityScore(
        server_id=inputs.server_id,
        score=round(breakdown.total, 2),
        breakdown=breakdown,
        computed_at=datetime.now(timezone.utc).isoformat(),
    )


def warn_threshold() -> float:
    """Default operator-facing warn threshold (60)."""
    return 60.0


def deny_threshold() -> float:
    """Default operator-facing deny threshold (40)."""
    return 40.0


__all__ = [
    "ScoreBreakdown",
    "ScoreInputs",
    "SecurityScore",
    "compute",
    "deny_threshold",
    "warn_threshold",
]
