"""Standalone runner for the scanner Recall@k%FPR evaluation harness.

Usage::

    python -m benchmarks.scanner_eval

Prints a formatted table of results for the Tessera heuristic scanner
against the default 60-benign + 60-malicious evaluation dataset.
"""

from __future__ import annotations

import sys

from benchmarks.scanner_eval.datasets import default_dataset
from benchmarks.scanner_eval.evaluator import ScannerEvaluator
from tessera.scanners.heuristic import injection_score


def main() -> int:
    dataset = default_dataset()
    runner = ScannerEvaluator()
    result = runner.evaluate(injection_score, "tessera.heuristic", dataset=dataset)

    header = (
        f"{'Scanner':<30}  "
        f"{'Recall@1%FPR':>14}  "
        f"{'AchievedFPR':>12}  "
        f"{'AUC-ROC':>8}  "
        f"{'P@97.5R':>8}  "
        f"{'Threshold':>10}  "
        f"{'Benign':>7}  "
        f"{'Malicious':>9}"
    )
    separator = "-" * len(header)
    row = (
        f"{result.scanner_name:<30}  "
        f"{result.recall_at_1pct_fpr:>14.3f}  "
        f"{result.achieved_fpr:>12.4f}  "
        f"{result.auc_roc:>8.3f}  "
        f"{result.precision_at_975_recall:>8.3f}  "
        f"{result.threshold_used:>10.4f}  "
        f"{result.total_benign:>7d}  "
        f"{result.total_malicious:>9d}"
    )

    print("\nScanner Evaluation Results")
    print(separator)
    print(header)
    print(separator)
    print(row)
    print(separator)
    return 0


if __name__ == "__main__":
    sys.exit(main())
