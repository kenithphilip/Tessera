"""Token budget enforcement for denial-of-wallet defense.

Tracks cumulative token usage per principal within a sliding window.
When a principal exceeds their budget, subsequent requests are denied
with a TOKEN_BUDGET_EXCEEDED SecurityEvent.

This addresses OWASP LLM10 (Unbounded Consumption) by providing
per-principal resource controls at the proxy layer.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any


@dataclass(frozen=True)
class BudgetStatus:
    """Current budget state for a principal.

    Attributes:
        principal: The identity being tracked.
        used: Tokens consumed in the current window.
        remaining: Tokens remaining before denial.
        limit: The configured budget limit.
        window_seconds: The rolling window duration.
        exceeded: True if the budget is exhausted.
    """

    principal: str
    used: int
    remaining: int
    limit: int
    window_seconds: float
    exceeded: bool


@dataclass
class _UsageEntry:
    tokens: int
    timestamp: datetime


class TokenBudget:
    """Per-principal per-window token budget enforcement.

    Thread-safe. Tracks token consumption in a rolling time window
    and denies requests that would exceed the budget.

    Args:
        max_tokens: Maximum tokens per principal per window.
        window: Rolling window duration. Default 24 hours.

    Usage::

        budget = TokenBudget(max_tokens=100_000)
        if budget.consume("alice", 5000):
            # allowed, proceed with LLM call
            ...
        else:
            # budget exceeded, deny
            ...
    """

    def __init__(
        self,
        max_tokens: int,
        window: timedelta = timedelta(hours=24),
    ) -> None:
        self._max_tokens = max_tokens
        self._window = window
        self._usage: dict[str, list[_UsageEntry]] = defaultdict(list)
        self._lock = Lock()

    def consume(self, principal: str, tokens: int, at: datetime | None = None) -> bool:
        """Attempt to consume tokens from a principal's budget.

        Args:
            principal: The identity consuming tokens.
            tokens: Number of tokens to consume.
            at: Timestamp of consumption. Defaults to now (UTC).

        Returns:
            True if the consumption was allowed, False if budget exceeded.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._expire(principal, ts)
            current = sum(e.tokens for e in self._usage[principal])
            if current + tokens > self._max_tokens:
                return False
            self._usage[principal].append(_UsageEntry(tokens=tokens, timestamp=ts))
            return True

    def remaining(self, principal: str, at: datetime | None = None) -> int:
        """Return remaining tokens for a principal.

        Args:
            principal: The identity to check.
            at: Reference time. Defaults to now (UTC).

        Returns:
            Number of tokens remaining in the current window.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._expire(principal, ts)
            used = sum(e.tokens for e in self._usage[principal])
            return max(0, self._max_tokens - used)

    def status(self, principal: str, at: datetime | None = None) -> BudgetStatus:
        """Return the full budget status for a principal.

        Args:
            principal: The identity to check.
            at: Reference time. Defaults to now (UTC).

        Returns:
            BudgetStatus with current usage and limit information.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._expire(principal, ts)
            used = sum(e.tokens for e in self._usage[principal])
            remaining = max(0, self._max_tokens - used)
            return BudgetStatus(
                principal=principal,
                used=used,
                remaining=remaining,
                limit=self._max_tokens,
                window_seconds=self._window.total_seconds(),
                exceeded=remaining == 0,
            )

    def reset(self, principal: str | None = None) -> None:
        """Reset token usage.

        Args:
            principal: If provided, reset only this principal.
                If None, reset all principals.
        """
        with self._lock:
            if principal is None:
                self._usage.clear()
            else:
                self._usage.pop(principal, None)

    def _expire(self, principal: str, now: datetime) -> None:
        cutoff = now - self._window
        entries = self._usage[principal]
        self._usage[principal] = [e for e in entries if e.timestamp >= cutoff]


@dataclass(frozen=True)
class CallRateStatus:
    """Current tool call rate state for a session.

    Attributes:
        session_id: The session being tracked.
        calls_in_window: Number of tool calls in the current window.
        calls_remaining: Calls remaining before denial.
        max_calls: The configured limit.
        window_seconds: The rolling window duration.
        exceeded: True if the rate limit is exhausted.
    """

    session_id: str
    calls_in_window: int
    calls_remaining: int
    max_calls: int
    window_seconds: float
    exceeded: bool


class ToolCallRateLimit:
    """Per-session tool call rate limiting with burst detection.

    Enforces three independent limits:
    1. Window rate: max calls per rolling window (default 50/5min)
    2. Burst detection: max calls in a short burst window (default
       10 in 5 seconds). Triggers a cooldown period.
    3. Session lifetime: max total calls across the entire session
       (default 500). Absolute cap.

    Thread-safe. Tracks calls independently per session.

    References:
    - Log-To-Leak (OpenReview 2025): injected prompts covertly force
      agents to invoke logging tools for exfiltration
    - Hossain et al. (2025): rate limiting + guard agents = 100% mitigation

    Args:
        max_calls: Maximum tool calls per session per window.
        window: Rolling window duration. Default 5 minutes.
        burst_threshold: Maximum calls in burst_window before cooldown.
        burst_window: Short window for burst detection. Default 5 seconds.
        cooldown: Pause duration after burst detection. Default 30 seconds.
        session_lifetime_max: Absolute cap on total calls per session.
            None means no lifetime limit.

    Usage::

        limiter = ToolCallRateLimit(max_calls=20, burst_threshold=8)

        # Before each tool execution:
        allowed, reason = limiter.check("session_abc", "search_hotels")
        if not allowed:
            raise RateLimitExceeded(reason)
    """

    def __init__(
        self,
        max_calls: int = 50,
        window: timedelta = timedelta(minutes=5),
        burst_threshold: int = 10,
        burst_window: timedelta = timedelta(seconds=5),
        cooldown: timedelta = timedelta(seconds=30),
        session_lifetime_max: int | None = 500,
    ) -> None:
        self._max_calls = max_calls
        self._window = window
        self._burst_threshold = burst_threshold
        self._burst_window = burst_window
        self._cooldown = cooldown
        self._session_lifetime_max = session_lifetime_max
        self._calls: dict[str, list[_CallEntry]] = defaultdict(list)
        self._total_calls: dict[str, int] = defaultdict(int)
        self._burst_alerts: dict[str, int] = defaultdict(int)
        self._cooldown_until: dict[str, datetime] = {}
        self._lock = Lock()

    def allow(
        self,
        session_id: str,
        tool_name: str = "",
        at: datetime | None = None,
    ) -> bool:
        """Check and record a tool call. Returns False if rate exceeded.

        For backward compatibility. Use check() for detailed reasons.
        """
        allowed, _ = self.check(session_id, tool_name, at)
        return allowed

    def check(
        self,
        session_id: str,
        tool_name: str = "",
        at: datetime | None = None,
    ) -> tuple[bool, str | None]:
        """Check and record a tool call with detailed reason.

        Args:
            session_id: The session making the call.
            tool_name: The tool being called (for logging).
            at: Timestamp. Defaults to now (UTC).

        Returns:
            Tuple of (allowed, reason_if_blocked). reason is None if allowed.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            # Check cooldown
            if session_id in self._cooldown_until:
                if ts < self._cooldown_until[session_id]:
                    remaining = (self._cooldown_until[session_id] - ts).total_seconds()
                    return False, f"cooldown active: {remaining:.0f}s remaining after burst"
                else:
                    del self._cooldown_until[session_id]

            # Check session lifetime limit
            if (self._session_lifetime_max is not None
                    and self._total_calls[session_id] >= self._session_lifetime_max):
                self._emit_exceeded(session_id, tool_name)
                return False, (
                    f"session lifetime limit: {self._total_calls[session_id]}/"
                    f"{self._session_lifetime_max}"
                )

            # Check window rate
            self._expire(session_id, ts)
            if len(self._calls[session_id]) >= self._max_calls:
                self._emit_exceeded(session_id, tool_name)
                return False, (
                    f"rate limit: {len(self._calls[session_id])}/"
                    f"{self._max_calls} per {self._window.total_seconds():.0f}s"
                )

            # Check burst (include current call in the count)
            burst_cutoff = ts - self._burst_window
            burst_count = sum(
                1 for c in self._calls[session_id] if c.timestamp > burst_cutoff
            ) + 1  # +1 for the call being evaluated now
            if burst_count >= self._burst_threshold:
                self._burst_alerts[session_id] += 1
                self._cooldown_until[session_id] = ts + self._cooldown
                self._emit_burst(session_id, tool_name, burst_count)
                return False, (
                    f"burst detected: {burst_count} calls in "
                    f"{self._burst_window.total_seconds():.0f}s, "
                    f"cooldown {self._cooldown.total_seconds():.0f}s"
                )

            # Record the call
            self._calls[session_id].append(_CallEntry(
                tool_name=tool_name, timestamp=ts,
            ))
            self._total_calls[session_id] += 1
            return True, None

    def status(self, session_id: str, at: datetime | None = None) -> CallRateStatus:
        """Return the current rate limit status for a session.

        Args:
            session_id: The session to check.
            at: Reference time. Defaults to now (UTC).

        Returns:
            CallRateStatus with current count and limit.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._expire(session_id, ts)
            count = len(self._calls[session_id])
            remaining = max(0, self._max_calls - count)
            return CallRateStatus(
                session_id=session_id,
                calls_in_window=count,
                calls_remaining=remaining,
                max_calls=self._max_calls,
                window_seconds=self._window.total_seconds(),
                exceeded=remaining == 0,
            )

    def reset(self, session_id: str | None = None) -> None:
        """Reset call history.

        Args:
            session_id: If provided, reset only this session.
                If None, reset all sessions.
        """
        with self._lock:
            if session_id is None:
                self._calls.clear()
            else:
                self._calls.pop(session_id, None)

    def _expire(self, session_id: str, now: datetime) -> None:
        cutoff = now - self._window
        entries = self._calls[session_id]
        self._calls[session_id] = [e for e in entries if e.timestamp >= cutoff]

    def _emit_exceeded(self, session_id: str, tool_name: str) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=session_id,
                detail={
                    "scanner": "tool_call_rate_limit",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "max_calls": self._max_calls,
                    "window_seconds": self._window.total_seconds(),
                    "total_calls": self._total_calls.get(session_id, 0),
                    "reason": "per-session tool call rate limit exceeded",
                },
            )
        )

    def _emit_burst(self, session_id: str, tool_name: str, burst_count: int) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=session_id,
                detail={
                    "scanner": "tool_call_rate_limit",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "burst_count": burst_count,
                    "burst_threshold": self._burst_threshold,
                    "burst_window_seconds": self._burst_window.total_seconds(),
                    "cooldown_seconds": self._cooldown.total_seconds(),
                    "burst_alerts_total": self._burst_alerts.get(session_id, 0),
                    "reason": "burst detected, cooldown initiated",
                },
            )
        )


@dataclass
class _CallEntry:
    tool_name: str
    timestamp: datetime
