"""Probe runner + aggregator.

Dispatches each :class:`tessera.redteam.Probe` through a scorer
function and aggregates per-corpus precision / recall / F1 plus
per-category breakdowns. Designed to feed the same metrics
the :mod:`benchmarks.scanner_eval` harness emits, so an external
auditor's ``run`` output is directly comparable to Tessera's
own scorecard ``benchmarks.scanner_eval`` block.

Scorer protocol: ``Callable[[str], float]`` returning a value in
``[0.0, 1.0]`` where higher means more likely malicious. The
runner thresholds the score (default ``0.5``) into a binary
detection decision and computes precision/recall against
``Probe.expects_detection``.
"""

from __future__ import annotations

import importlib
import statistics
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Callable

from tessera.redteam.loader import Probe

ScoreFn = Callable[[str], float]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of running one probe through a scorer."""

    probe_id: str
    category: str
    expected_outcome: str
    expected_detection: bool
    score: float
    detected: bool
    latency_ms: float
    error: str | None = None


@dataclass(frozen=True)
class CategoryStats:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass(frozen=True)
class AggregatedReport:
    scanner_name: str
    threshold: float
    total: int
    detected: int
    precision: float
    recall: float
    f1: float
    per_category: dict[str, CategoryStats]
    latency_ms_p50: float
    latency_ms_p99: float
    errors: int
    elapsed_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner_name,
            "threshold": self.threshold,
            "total": self.total,
            "detected": self.detected,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "latency_ms_p50": round(self.latency_ms_p50, 3),
            "latency_ms_p99": round(self.latency_ms_p99, 3),
            "errors": self.errors,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "per_category": {
                name: {
                    "tp": s.tp,
                    "fp": s.fp,
                    "fn": s.fn,
                    "tn": s.tn,
                    "precision": round(s.precision, 4),
                    "recall": round(s.recall, 4),
                    "f1": round(s.f1, 4),
                }
                for name, s in sorted(self.per_category.items())
            },
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_scorer(dotted_path: str) -> ScoreFn:
    """Resolve a dotted-path string (``module.submodule.attr``) to a callable.

    Used by the CLI to let auditors specify any scorer importable
    from the Tessera namespace, e.g.
    ``tessera.scanners.heuristic.injection_score``.
    """
    module_path, _, attr = dotted_path.rpartition(".")
    if not module_path:
        raise ValueError(f"scorer must be a dotted path, got {dotted_path!r}")
    module = importlib.import_module(module_path)
    fn = getattr(module, attr, None)
    if fn is None or not callable(fn):
        raise ValueError(f"{dotted_path} does not resolve to a callable")
    return fn  # type: ignore[return-value]


def run(
    probes: Iterable[Probe],
    *,
    scorer: ScoreFn,
    threshold: float = 0.5,
) -> list[ProbeResult]:
    """Run each probe through the scorer.

    The runner is intentionally serial: red-team corpora are
    small (~10^3 entries) and serial execution makes the per-probe
    timing readings stable. If concurrency becomes a need, a
    follow-up can add ``parallelism`` via a ThreadPoolExecutor;
    today the latency budget is dominated by the scorer itself
    not by orchestration overhead.
    """
    results: list[ProbeResult] = []
    for probe in probes:
        started = time.perf_counter()
        error: str | None = None
        score = 0.0
        try:
            score = float(scorer(probe.payload))
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        elapsed = (time.perf_counter() - started) * 1000.0
        detected = error is None and score >= threshold
        results.append(
            ProbeResult(
                probe_id=probe.probe_id,
                category=probe.category,
                expected_outcome=probe.expected_outcome,
                expected_detection=probe.expects_detection,
                score=score,
                detected=detected,
                latency_ms=elapsed,
                error=error,
            )
        )
    return results


def aggregate(
    results: list[ProbeResult],
    *,
    scanner_name: str,
    threshold: float,
    elapsed_seconds: float,
) -> AggregatedReport:
    """Roll up per-probe results into an :class:`AggregatedReport`."""
    if not results:
        return AggregatedReport(
            scanner_name=scanner_name,
            threshold=threshold,
            total=0,
            detected=0,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            per_category={},
            latency_ms_p50=0.0,
            latency_ms_p99=0.0,
            errors=0,
            elapsed_seconds=elapsed_seconds,
        )

    by_category: dict[str, list[ProbeResult]] = defaultdict(list)
    for r in results:
        by_category[r.category].append(r)

    per_category: dict[str, CategoryStats] = {}
    for cat, items in by_category.items():
        tp = sum(1 for r in items if r.expected_detection and r.detected)
        fp = sum(1 for r in items if not r.expected_detection and r.detected)
        fn = sum(1 for r in items if r.expected_detection and not r.detected)
        tn = sum(1 for r in items if not r.expected_detection and not r.detected)
        per_category[cat] = CategoryStats(tp=tp, fp=fp, fn=fn, tn=tn)

    total_tp = sum(s.tp for s in per_category.values())
    total_fp = sum(s.fp for s in per_category.values())
    total_fn = sum(s.fn for s in per_category.values())
    overall_precision = (
        total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    )
    overall_recall = (
        total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    )
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall)
        else 0.0
    )

    latencies = sorted(r.latency_ms for r in results)
    p50 = latencies[len(latencies) // 2]
    p99_index = max(0, int(len(latencies) * 0.99) - 1)
    p99 = latencies[p99_index] if latencies else 0.0
    errors = sum(1 for r in results if r.error)

    return AggregatedReport(
        scanner_name=scanner_name,
        threshold=threshold,
        total=len(results),
        detected=sum(1 for r in results if r.detected),
        precision=overall_precision,
        recall=overall_recall,
        f1=overall_f1,
        per_category=per_category,
        latency_ms_p50=p50,
        latency_ms_p99=p99,
        errors=errors,
        elapsed_seconds=elapsed_seconds,
    )
