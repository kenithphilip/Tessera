"""Per-session :class:`Context` store with TTL and bounded-size eviction.

Multi-tenant proxies must not share one :class:`Context` across users.
The taint-tracking invariant (``min_trust`` across all segments drives
the verdict) means a web-tainted segment from user A can deny a tool
call from user B if both share the same Context. That is the bug this
module exists to prevent.

The store is intentionally small: a thread-safe map from session id to
``Context`` plus a last-touched timestamp, with lazy eviction on access
(no background thread). Sessions silently expire after
``ttl_seconds`` of inactivity. When the soft cap ``max_sessions`` is
hit on insert, the least-recently-used session is evicted to make room.

Design choices
--------------
- **Lazy eviction.** No background thread. ``evict_expired()`` is called
  on every ``get()`` and runs in O(n) over the session map. Acceptable
  because session counts are typically small (hundreds, not millions);
  proxies under heavier load should call ``evict_expired()`` on a timer.
- **Touch on read.** ``get()`` updates the last-touched timestamp.
  Callers that want a peek without touching can use ``has()``.
- **No persistence.** Sessions are in-memory. Process restart resets
  every session to a fresh ``Context``, which is the correct default
  (a process restart is also the boundary where any cached secrets,
  delegations, or trust state are forgotten).
- **No locking inside Context.** The lock guards the dict; the per-
  session ``Context`` is not itself thread-safe. If a single session
  is shared across concurrent threads, the caller must synchronize.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from tessera.context import Context


@dataclass
class _Entry:
    context: Context
    last_touched_monotonic: float


class SessionContextStore:
    """Thread-safe per-session :class:`Context` store.

    Args:
        ttl_seconds: Inactive session lifetime. After this many seconds
            with no ``get()`` or write, the session is evicted on the
            next ``evict_expired()`` or ``get()`` call. Default 1 hour.
        max_sessions: Soft upper bound on stored sessions. When a new
            session would push the count over this cap, the
            least-recently-used session is evicted first. Default
            10,000. Set to ``0`` to disable the cap.
        clock: Optional monotonic-clock callable (returns float seconds).
            Override in tests to control eviction without sleeping.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        max_sessions: int = 10000,
        clock=None,
        on_evict=None,
    ) -> None:
        """
        Args:
            on_evict: Optional callback ``f(session_id) -> None`` invoked
                whenever a session is evicted (TTL or LRU). Lets the
                caller clean up adjacent per-session state. Exceptions
                from the callback are swallowed so eviction always
                completes.
        """
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_sessions < 0:
            raise ValueError("max_sessions must be non-negative")
        self._ttl = float(ttl_seconds)
        self._max_sessions = int(max_sessions)
        self._lock = threading.Lock()
        # OrderedDict so we can move-to-end on touch and pop oldest on cap.
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._clock = clock or time.monotonic
        self._evictions = 0
        self._on_evict = on_evict

    def get(self, session_id: str) -> Context:
        """Return the Context for ``session_id``, creating it if missing.

        Updates the last-touched timestamp. Runs lazy eviction of any
        sessions that have exceeded ``ttl_seconds`` of inactivity, and
        enforces ``max_sessions`` if needed.
        """
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string")
        now = self._clock()
        evicted: list[str] = []
        with self._lock:
            expired = self._evict_expired_locked(now)
            evicted.extend(expired)
            entry = self._entries.get(session_id)
            if entry is None:
                entry = _Entry(context=Context(), last_touched_monotonic=now)
                self._entries[session_id] = entry
                if (
                    self._max_sessions > 0
                    and len(self._entries) > self._max_sessions
                ):
                    # Evict the LRU entry. popitem(last=False) removes
                    # the oldest insertion-order entry; since we
                    # move_to_end on touch below, that's the LRU.
                    lru_id, _ = self._entries.popitem(last=False)
                    self._evictions += 1
                    evicted.append(lru_id)
            else:
                entry.last_touched_monotonic = now
                self._entries.move_to_end(session_id, last=True)
        # Fire callbacks outside the lock so callee cannot deadlock us.
        self._fire_evictions(evicted)
        return entry.context

    def has(self, session_id: str) -> bool:
        """True if a session exists and is not expired. Does not touch."""
        now = self._clock()
        with self._lock:
            entry = self._entries.get(session_id)
            if entry is None:
                return False
            return (now - entry.last_touched_monotonic) <= self._ttl

    def reset(self, session_id: str) -> None:
        """Drop ``session_id``. Idempotent. Fires the eviction callback."""
        with self._lock:
            existed = self._entries.pop(session_id, None) is not None
        if existed:
            self._fire_evictions([session_id])

    def reset_all(self) -> None:
        """Drop every session. Fires the eviction callback per session."""
        with self._lock:
            ids = list(self._entries.keys())
            self._entries.clear()
        self._fire_evictions(ids)

    def evict_expired(self) -> int:
        """Force a sweep of expired sessions. Returns the count evicted."""
        now = self._clock()
        with self._lock:
            evicted = self._evict_expired_locked(now)
        self._fire_evictions(evicted)
        return len(evicted)

    def session_ids(self) -> list[str]:
        """Snapshot of currently-active session ids (LRU first, MRU last)."""
        with self._lock:
            return list(self._entries.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def evictions(self) -> int:
        """Cumulative count of LRU + TTL evictions since construction."""
        return self._evictions

    # -- internal -----------------------------------------------------

    def _evict_expired_locked(self, now: float) -> list[str]:
        """Walk entries, remove any older than TTL. Returns evicted ids.

        Caller holds the lock.
        """
        if not self._entries:
            return []
        cutoff = now - self._ttl
        # OrderedDict iteration is insertion-order, but touch reorders
        # to the end; older-than-cutoff entries cluster at the front.
        # We can stop at the first non-expired entry.
        evicted: list[str] = []
        while self._entries:
            session_id, entry = next(iter(self._entries.items()))
            if entry.last_touched_monotonic > cutoff:
                break
            del self._entries[session_id]
            evicted.append(session_id)
            self._evictions += 1
        return evicted

    def _fire_evictions(self, session_ids: list[str]) -> None:
        """Invoke the eviction callback once per session id. Swallows
        callback exceptions so a buggy callback cannot break the store."""
        if not self._on_evict or not session_ids:
            return
        for sid in session_ids:
            try:
                self._on_evict(sid)
            except Exception:  # noqa: BLE001
                pass


__all__ = ["SessionContextStore"]
