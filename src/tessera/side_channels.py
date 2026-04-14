"""Mitigations for side-channel information leaks in agent systems.

Neither CaMeL nor Microsoft AGT defends against three classes of
side-channel leak that arise when tainted data influences control flow:

1. Loop-counting attacks: an attacker encodes information in the
   iteration count of a loop whose bound depends on tainted input.
2. Exception-based information leaks: different error types or messages
   reveal whether a denied operation matched a real resource, exposing
   existence or permission metadata.
3. Timing channels: observable latency differences between allow and deny
   paths leak policy decisions to a network observer.

This module provides mitigations, not proofs. Timing channels in
particular are difficult to fully close due to network jitter, OS
scheduling, and GC pauses. The constant-time dispatch adds a floor but
does not eliminate all timing variation. Use these alongside, not instead
of, the primary policy and quarantine primitives.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Generic,
    Iterator,
    TypeVar,
)

from tessera.events import EventKind, SecurityEvent, emit as emit_event

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Loop-counting mitigation
# ---------------------------------------------------------------------------


class LoopBoundExceeded(Exception):
    """Raised when a tainted loop exceeds its iteration cap."""


class LoopGuard:
    """Caps iteration count when the loop bound depends on tainted data.

    When ``tainted=True``, the guard enforces ``max_iterations`` and emits
    a ``SecurityEvent`` before raising ``LoopBoundExceeded``. When
    ``tainted=False``, the guard is a zero-cost passthrough.

    Args:
        max_iterations: Upper bound on iterations for tainted loops.
    """

    def __init__(self, max_iterations: int = 100) -> None:
        self._max_iterations = max_iterations

    def guard(self, iterable: Any, *, tainted: bool = False) -> Iterator:
        """Wrap *iterable* with an optional iteration cap.

        Args:
            iterable: Any iterable to wrap.
            tainted: If True, enforce the iteration limit.

        Yields:
            Items from *iterable*, up to ``max_iterations`` when tainted.

        Raises:
            LoopBoundExceeded: If tainted and the cap is exceeded.
        """
        if not tainted:
            yield from iterable
            return

        count = 0
        for item in iterable:
            count += 1
            if count > self._max_iterations:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.CONTENT_INJECTION_DETECTED,
                        principal=None,
                        detail={
                            "reason": "loop_bound_exceeded",
                            "max_iterations": self._max_iterations,
                        },
                    )
                )
                raise LoopBoundExceeded(
                    f"Tainted loop exceeded {self._max_iterations} iterations"
                )
            yield item


# ---------------------------------------------------------------------------
# Structured result (eliminates exception-type information leak)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StructuredResult(Generic[T]):
    """Result type that does not leak information through exception type or message.

    Both success and failure paths return the same structure so an
    observer cannot distinguish them by type, traceback depth, or
    exception class name.

    Attributes:
        success: Whether the operation succeeded.
        value: The result value (meaningful only when ``success`` is True).
        error_code: Generic error code, not a detailed message.
    """

    success: bool
    value: T | None
    error_code: str

    @classmethod
    def ok(cls, value: T) -> StructuredResult[T]:
        """Create a success result.

        Args:
            value: The successful return value.

        Returns:
            A StructuredResult with ``success=True``.
        """
        return cls(success=True, value=value, error_code="")

    @classmethod
    def fail(cls, error_code: str = "tool_error") -> StructuredResult[Any]:
        """Create a failure result.

        Args:
            error_code: A generic code such as ``"tool_error"``,
                ``"denied"``, or ``"timeout"``.

        Returns:
            A StructuredResult with ``success=False`` and ``value=None``.
        """
        return cls(success=False, value=None, error_code=error_code)


# ---------------------------------------------------------------------------
# Constant-time dispatch (timing-channel mitigation)
# ---------------------------------------------------------------------------


class ConstantTimeDispatch:
    """Wraps tool dispatch to normalize timing.

    Adds a latency floor so that fast-path (allow) and slow-path (deny)
    responses take at least ``min_latency_ms`` milliseconds. If the
    wrapped function already exceeds the floor, no artificial delay is
    added.

    Args:
        min_latency_ms: Minimum dispatch latency in milliseconds.
    """

    def __init__(self, min_latency_ms: float = 100.0) -> None:
        self._min_latency_s = min_latency_ms / 1000.0

    async def dispatch(
        self, fn: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any
    ) -> T:
        """Call *fn* and pad to the minimum latency (async).

        Args:
            fn: An async callable.
            *args: Positional arguments forwarded to *fn*.
            **kwargs: Keyword arguments forwarded to *fn*.

        Returns:
            The return value of *fn*.
        """
        start = time.monotonic()
        result = await fn(*args, **kwargs)
        elapsed = time.monotonic() - start
        remaining = self._min_latency_s - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)
        return result

    def sync_dispatch(
        self, fn: Callable[..., T], *args: Any, **kwargs: Any
    ) -> T:
        """Call *fn* and pad to the minimum latency (sync).

        Args:
            fn: A synchronous callable.
            *args: Positional arguments forwarded to *fn*.
            **kwargs: Keyword arguments forwarded to *fn*.

        Returns:
            The return value of *fn*.
        """
        start = time.monotonic()
        result = fn(*args, **kwargs)
        elapsed = time.monotonic() - start
        remaining = self._min_latency_s - elapsed
        if remaining > 0:
            time.sleep(remaining)
        return result
