"""Scanner Recall@k%FPR evaluation harness.

Provides a labeled dataset of 60 benign and 60 malicious strings,
statistical metric functions (Recall@FPR, AUC-ROC, Precision@Recall),
and a ScannerEvaluator that runs any scorer callable against the dataset.

Usage::

    from benchmarks.scanner_eval import ScannerEvaluator
    from tessera.scanners.heuristic import injection_score

    evaluator = ScannerEvaluator()
    result = evaluator.score(injection_score, "heuristic")
    print(result.summary())
"""

from __future__ import annotations

from benchmarks.scanner_eval.datasets import (
    BENIGN_SAMPLES,
    MALICIOUS_SAMPLES,
    LabeledDataset,
    default_dataset,
)
from benchmarks.scanner_eval.evaluator import ScannerEvaluator, ScannerResult
from benchmarks.scanner_eval.metrics import recall_at_fpr

__all__ = [
    "BENIGN_SAMPLES",
    "MALICIOUS_SAMPLES",
    "LabeledDataset",
    "ScannerEvaluator",
    "ScannerResult",
    "default_dataset",
    "recall_at_fpr",
]


def _run_heuristic_benchmark() -> None:
    from tessera.scanners.heuristic import injection_score

    runner = ScannerEvaluator()
    result = runner.evaluate(injection_score, "tessera.heuristic")
    print(result.summary())


BENCHMARKS = [
    ("Heuristic scanner Recall@1%FPR", _run_heuristic_benchmark),
]
