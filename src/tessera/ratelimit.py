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
    """Per-session tool call rate limiting.

    An injection could trigger thousands of read-only tool calls to
    exfiltrate data in volume. Token budgets (TokenBudget) track
    cumulative LLM cost but not how many tool calls the agent makes.
    This class enforces a hard cap on tool calls per session per
    rolling window.

    Thread-safe. Tracks calls independently per session.

    Args:
        max_calls: Maximum tool calls per session per window.
        window: Rolling window duration. Default 5 minutes.

    Usage::

        limiter = ToolCallRateLimit(max_calls=20, window=timedelta(minutes=5))

        # Before each tool execution:
        if not limiter.allow("session_abc", "search_hotels"):
            raise RateLimitExceeded("too many tool calls")
    """

    def __init__(
        self,
        max_calls: int = 50,
        window: timedelta = timedelta(minutes=5),
    ) -> None:
        self._max_calls = max_calls
        self._window = window
        self._calls: dict[str, list[_CallEntry]] = defaultdict(list)
        self._lock = Lock()

    def allow(
        self,
        session_id: str,
        tool_name: str = "",
        at: datetime | None = None,
    ) -> bool:
        """Check and record a tool call. Returns False if rate exceeded.

        Args:
            session_id: The session making the call.
            tool_name: The tool being called (for logging).
            at: Timestamp. Defaults to now (UTC).

        Returns:
            True if the call is allowed, False if rate limit exceeded.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._expire(session_id, ts)
            if len(self._calls[session_id]) >= self._max_calls:
                self._emit_exceeded(session_id, tool_name)
                return False
            self._calls[session_id].append(_CallEntry(
                tool_name=tool_name, timestamp=ts,
            ))
            return True

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
                    "reason": "per-session tool call rate limit exceeded",
                },
            )
        )


@dataclass
class _CallEntry:
    tool_name: str
    timestamp: datetime
