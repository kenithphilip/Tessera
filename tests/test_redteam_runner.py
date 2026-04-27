"""Tests for ``tessera.redteam.runner``.

Covers:
- ``run`` produces one ProbeResult per probe with timing recorded.
- Scorer exception is captured per-probe (no propagation; the
  result is marked detected=False with the exception in error).
- ``aggregate`` computes precision/recall/F1 against expected
  outcomes correctly on a hand-computed fixture.
- per_category breakdowns roll up per category.
- p50 / p99 latency are derived from the result list.
- ``resolve_scorer`` resolves dotted paths.
- ``run`` against the real bundled corpus + the heuristic scanner
  produces a populated AggregatedReport.
"""

from __future__ import annotations

import time

import pytest

from tessera.redteam import Probe, aggregate, run
from tessera.redteam.runner import (
    AggregatedReport,
    CategoryStats,
    ProbeResult,
    resolve_scorer,
)


def _probe(
    probe_id: str = "EXAMPLE_2b3c4d5e-0002-4000-8000-000000000001",
    category: str = "prompt_injection",
    expected: str = "refuse",
) -> Probe:
    return Probe(
        probe_id=probe_id,
        category=category,
        payload="payload",
        expected_outcome=expected,
        source="test",
        license="MIT",
        submitted_at="2026-04-26",
    )


# ---------------------------------------------------------------------------
# run() shape
# ---------------------------------------------------------------------------


def test_run_one_probe_returns_one_result():
    probes = [_probe()]
    results = run(probes, scorer=lambda s: 0.9, threshold=0.5)
    assert len(results) == 1
    r = results[0]
    assert r.probe_id == probes[0].probe_id
    assert r.detected is True
    assert r.score == pytest.approx(0.9)
    assert r.latency_ms >= 0.0
    assert r.error is None


def test_run_below_threshold_marks_undetected():
    results = run([_probe()], scorer=lambda s: 0.4, threshold=0.5)
    assert results[0].detected is False


def test_run_scorer_exception_captured():
    def boom(_: str) -> float:
        raise RuntimeError("scorer crashed")

    results = run([_probe()], scorer=boom, threshold=0.5)
    assert results[0].detected is False
    assert results[0].error == "RuntimeError: scorer crashed"
    # Score is left at 0 when the scorer raised.
    assert results[0].score == 0.0


# ---------------------------------------------------------------------------
# aggregate() math
# ---------------------------------------------------------------------------


def test_aggregate_precision_recall_f1_hand_computed():
    """Hand-built fixture so the math is checkable line by line.

    8 probes total: 5 expect detection, 3 don't.
    Scorer flags 6 of them (4 of the 5 that expect detection,
    2 of the 3 that don't).

    TP=4, FP=2, FN=1, TN=1
    precision = 4 / (4+2) = 0.667
    recall    = 4 / (4+1) = 0.8
    f1        = 2*0.667*0.8 / (0.667+0.8) = 0.727...
    """
    results = [
        ProbeResult(probe_id="p1", category="prompt_injection",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.9, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p2", category="prompt_injection",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.8, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p3", category="prompt_injection",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.7, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p4", category="exfil",
                    expected_outcome="block", expected_detection=True,
                    score=0.9, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p5", category="exfil",
                    expected_outcome="block", expected_detection=True,
                    score=0.1, detected=False, latency_ms=1.0),
        ProbeResult(probe_id="p6", category="prompt_injection",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.0, detected=False, latency_ms=1.0),
        # 2 entries that don't expect detection (a benign-shaped
        # probe; not present in the v1 corpus but supported by the
        # type system).
        ProbeResult(probe_id="p7", category="prompt_injection",
                    expected_outcome="ALLOW_HYPOTHETICAL", expected_detection=False,
                    score=0.9, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p8", category="prompt_injection",
                    expected_outcome="ALLOW_HYPOTHETICAL", expected_detection=False,
                    score=0.0, detected=False, latency_ms=1.0),
    ]
    # Adjust expected/recall counts: with the FP probe p7 + p8
    # benign:
    # prompt_injection: TP=2 (p1,p2), FP=1 (p7), FN=1 (p6), TN=1 (p8)
    #   actually p3 is also TP, so TP=3, FP=1, FN=1, TN=1
    # exfil: TP=1 (p4), FP=0, FN=1 (p5), TN=0
    #
    # Overall: TP=4, FP=1, FN=2, TN=1
    # precision = 4/(4+1) = 0.8
    # recall    = 4/(4+2) = 0.667
    report = aggregate(results, scanner_name="test", threshold=0.5,
                       elapsed_seconds=0.1)
    assert report.precision == pytest.approx(0.8, rel=1e-2)
    assert report.recall == pytest.approx(0.6667, rel=1e-2)
    assert report.f1 == pytest.approx(0.7272, rel=1e-2)
    assert report.total == 8
    # report.detected counts every probe the scanner flagged
    # (TP + FP), not just the true positives.
    assert report.detected == 5


def test_aggregate_per_category_breakdown():
    results = [
        ProbeResult(probe_id="p1", category="prompt_injection",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.9, detected=True, latency_ms=1.0),
        ProbeResult(probe_id="p2", category="exfil",
                    expected_outcome="block", expected_detection=True,
                    score=0.1, detected=False, latency_ms=1.0),
    ]
    report = aggregate(results, scanner_name="t", threshold=0.5,
                       elapsed_seconds=0.0)
    pi_stats = report.per_category["prompt_injection"]
    ex_stats = report.per_category["exfil"]
    assert pi_stats.tp == 1 and pi_stats.fn == 0
    assert ex_stats.tp == 0 and ex_stats.fn == 1
    assert pi_stats.recall == 1.0
    assert ex_stats.recall == 0.0


def test_aggregate_handles_empty_results():
    report = aggregate([], scanner_name="t", threshold=0.5, elapsed_seconds=0.0)
    assert report.total == 0
    assert report.precision == 0.0
    assert report.recall == 0.0
    assert report.per_category == {}


def test_aggregate_latency_percentiles():
    results = [
        ProbeResult(probe_id=f"p{i}", category="x",
                    expected_outcome="refuse", expected_detection=True,
                    score=0.9, detected=True, latency_ms=float(i))
        for i in range(1, 101)
    ]
    report = aggregate(results, scanner_name="t", threshold=0.5,
                       elapsed_seconds=0.5)
    # p50 is the middle element.
    assert report.latency_ms_p50 == 51.0
    # p99 falls on or near index 98 (floor).
    assert 98.0 <= report.latency_ms_p99 <= 100.0


def test_to_dict_round_trip_keys():
    report = aggregate([], scanner_name="t", threshold=0.5, elapsed_seconds=0.0)
    d = report.to_dict()
    for k in ("scanner", "threshold", "total", "precision", "recall", "f1",
              "latency_ms_p50", "latency_ms_p99", "errors", "elapsed_seconds",
              "per_category"):
        assert k in d


# ---------------------------------------------------------------------------
# resolve_scorer
# ---------------------------------------------------------------------------


def test_resolve_scorer_resolves_heuristic_injection_score():
    scorer = resolve_scorer("tessera.scanners.heuristic.injection_score")
    assert callable(scorer)
    assert isinstance(scorer("hello"), float)


def test_resolve_scorer_rejects_non_dotted():
    with pytest.raises(ValueError, match="dotted path"):
        resolve_scorer("nodot")


def test_resolve_scorer_rejects_missing_attribute():
    with pytest.raises((AttributeError, ValueError)):
        resolve_scorer("tessera.scanners.heuristic.does_not_exist_123")


# ---------------------------------------------------------------------------
# Real corpus end-to-end smoke
# ---------------------------------------------------------------------------


def test_run_real_corpus_through_heuristic():
    from tessera.redteam import load_corpus
    from tessera.scanners.heuristic import injection_score

    probes = load_corpus("tensor_trust")
    started = time.perf_counter()
    results = run(probes, scorer=injection_score, threshold=0.5)
    report = aggregate(
        results,
        scanner_name="tessera.scanners.heuristic.injection_score",
        threshold=0.5,
        elapsed_seconds=time.perf_counter() - started,
    )
    assert report.total == len(probes)
    assert 0.0 <= report.precision <= 1.0
    assert 0.0 <= report.recall <= 1.0
    assert "prompt_injection" in report.per_category or "exfil" in report.per_category
