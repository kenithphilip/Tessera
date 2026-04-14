"""Adaptive cooldown escalation based on human denial patterns.

Tracks human rejection timestamps in a rolling window per session.
When the rejection rate exceeds configured thresholds, the escalation
level increases, tightening the policy posture:

    Level 0 (< low_threshold denials): no effect
    Level 1 (>= low_threshold denials): ALLOW becomes REQUIRE_APPROVAL
    Level 2 (>= high_threshold denials): all calls require explicit confirmation

Only counts explicit human rejections from approval resolution, not
automated policy DENY decisions.

Source attribution: TrustRateLimiter pattern from ClawReins
(TrustRateLimiter.ts).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class EscalationState:
    """Current escalation posture.

    Attributes:
        level: 0 (normal), 1 (elevated), or 2 (maximum).
        denial_count: number of denials in the current window.
        window_seconds: the rolling window duration.
    """

    level: int
    denial_count: int
    window_seconds: float


class CooldownEscalator:
    """Adaptive policy escalation based on human denial rate.

    Usage::

        escalator = CooldownEscalator()
        escalator.record_denial()
        escalator.record_denial()
        escalator.record_denial()
        state = escalator.state()
        assert state.level == 1  # 3 denials in 10 minutes
    """

    def __init__(
        self,
        *,
        window: timedelta = timedelta(minutes=10),
        low_threshold: int = 3,
        high_threshold: int = 5,
    ) -> None:
        self._window = window
        self._low_threshold = low_threshold
        self._high_threshold = high_threshold
        self._denials: deque[datetime] = deque()

    def record_denial(self, at: datetime | None = None) -> EscalationState:
        """Record a human denial and return the updated escalation state.

        Args:
            at: The timestamp of the denial. Defaults to now (UTC).

        Returns:
            The current EscalationState after recording.
        """
        ts = at or datetime.now(timezone.utc)
        self._denials.append(ts)
        self._expire(ts)
        return self._state(ts)

    def state(self, at: datetime | None = None) -> EscalationState:
        """Return the current escalation state without recording.

        Args:
            at: The reference time. Defaults to now (UTC).

        Returns:
            The current EscalationState.
        """
        ts = at or datetime.now(timezone.utc)
        self._expire(ts)
        return self._state(ts)

    def reset(self) -> None:
        """Clear all denial history."""
        self._denials.clear()

    def _expire(self, now: datetime) -> None:
        cutoff = now - self._window
        while self._denials and self._denials[0] < cutoff:
            self._denials.popleft()

    def _state(self, now: datetime) -> EscalationState:
        count = len(self._denials)
        if count >= self._high_threshold:
            level = 2
        elif count >= self._low_threshold:
            level = 1
        else:
            level = 0
        return EscalationState(
            level=level,
            denial_count=count,
            window_seconds=self._window.total_seconds(),
        )
