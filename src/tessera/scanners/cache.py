"""LRU cache for scanner results.

Cache key is the SHA-256 hex digest of the input text, so large
strings are not held in memory by the cache itself. Thread-safe
via an explicit lock around the internal OrderedDict.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
from typing import Callable


@dataclass(frozen=True)
class CacheStats:
    """Snapshot of cache hit/miss statistics."""

    hits: int
    misses: int
    size: int
    maxsize: int
    hit_rate: float


class ScannerCache:
    """LRU cache keyed by SHA-256 digest of scanner input text.

    Args:
        maxsize: Maximum number of cached entries.
    """

    def __init__(self, maxsize: int = 1024) -> None:
        self._maxsize = maxsize
        self._hits = 0
        self._misses = 0
        self._lock = Lock()
        self._cache: OrderedDict[str, float] = OrderedDict()

    def get_or_compute(self, text: str, scorer: Callable[[str], float]) -> float:
        """Return cached score or compute, cache, and return it."""
        key = hashlib.sha256(text.encode()).hexdigest()
        scorer_key = f"{key}:{id(scorer)}"

        with self._lock:
            if scorer_key in self._cache:
                self._cache.move_to_end(scorer_key)
                self._hits += 1
                return self._cache[scorer_key]

        score = scorer(text)

        with self._lock:
            self._cache[scorer_key] = score
            self._cache.move_to_end(scorer_key)
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)
            self._misses += 1

        return score

    @property
    def stats(self) -> CacheStats:
        """Return a snapshot of cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                size=len(self._cache),
                maxsize=self._maxsize,
                hit_rate=self._hits / total if total > 0 else 0.0,
            )

    def clear(self) -> None:
        """Clear all cached entries and reset statistics."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
