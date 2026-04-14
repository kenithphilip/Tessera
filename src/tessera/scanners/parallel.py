"""Parallel scanner execution and per-call scanner selection.

Runs multiple scanner functions concurrently using a thread pool
executor, since most scanners are CPU-bound (heuristic) or
I/O-bound (ML model inference). Includes a registry for named
scanners with per-call selection.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from tessera.scanners.cache import ScannerCache


@dataclass(frozen=True)
class ParallelScanResult:
    """Aggregated result from running multiple scanners."""

    max_score: float
    scores: dict[str, float]
    elapsed_ms: float


async def run_scanners_parallel(
    text: str,
    scanners: list[Callable[[str], float]],
    cache: ScannerCache | None = None,
) -> ParallelScanResult:
    """Run multiple scanners concurrently and return the maximum score.

    Each scanner is dispatched to the default thread pool executor
    since scanners are typically CPU-bound or I/O-bound.

    Args:
        text: Input text to scan.
        scanners: List of scorer callables returning 0.0-1.0.
        cache: Optional ScannerCache for result caching.

    Returns:
        ParallelScanResult with the max score, per-scanner scores,
        and wall-clock elapsed time in milliseconds.
    """
    if not scanners:
        return ParallelScanResult(max_score=0.0, scores={}, elapsed_ms=0.0)

    loop = asyncio.get_running_loop()
    start = time.monotonic()

    def _run_one(scanner: Callable[[str], float]) -> tuple[str, float]:
        name = getattr(scanner, "__name__", None) or scanner.__qualname__
        if cache is not None:
            score = cache.get_or_compute(text, scanner)
        else:
            score = scanner(text)
        return name, score

    tasks = [loop.run_in_executor(None, _run_one, s) for s in scanners]
    results = await asyncio.gather(*tasks)

    scores: dict[str, float] = {}
    for name, score in results:
        scores[name] = score

    elapsed_ms = (time.monotonic() - start) * 1000.0
    max_score = max(scores.values()) if scores else 0.0

    return ParallelScanResult(
        max_score=max_score,
        scores=scores,
        elapsed_ms=elapsed_ms,
    )


@dataclass
class ScannerRegistry:
    """Registry of named scanners for per-call selection."""

    _scanners: dict[str, Callable[[str], float]] = field(default_factory=dict)

    def register(self, name: str, scanner: Callable[[str], float]) -> None:
        """Register a scanner under the given name."""
        self._scanners[name] = scanner

    def select(self, names: list[str] | None = None) -> list[Callable[[str], float]]:
        """Return scanners matching the given names. None returns all."""
        if names is None:
            return list(self._scanners.values())
        return [self._scanners[n] for n in names if n in self._scanners]

    async def run(
        self,
        text: str,
        names: list[str] | None = None,
        cache: ScannerCache | None = None,
    ) -> ParallelScanResult:
        """Select and run scanners in parallel.

        Args:
            text: Input text to scan.
            names: Scanner names to run. None runs all registered scanners.
            cache: Optional ScannerCache for result caching.

        Returns:
            ParallelScanResult with aggregated scores.
        """
        selected = self.select(names)
        return await run_scanners_parallel(text, selected, cache=cache)
