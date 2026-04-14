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
