"""Scanner evaluator: compute Recall@1%FPR and related metrics for a scorer function.

A scorer is any callable that takes a string and returns a float 0.0-1.0
where higher scores indicate more likely injection content. The evaluator
runs the scorer over a LabeledDataset and returns a ScannerResult with
the key statistical metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from benchmarks.scanner_eval.datasets import LabeledDataset, default_dataset
from benchmarks.scanner_eval.metrics import auc_roc, precision_at_recall, recall_at_fpr


@dataclass
class ScannerResult:
    """Evaluation result for one scorer function.

    Attributes:
        scanner_name: Name of the scorer.
        recall_at_1pct_fpr: Recall achieved when FPR <= 1%.
        achieved_fpr: Actual FPR at the Recall@1%FPR threshold.
        auc_roc: Area under the ROC curve.
        precision_at_975_recall: Precision when recall >= 97.5%.
        total_benign: Number of benign samples evaluated.
        total_malicious: Number of malicious samples evaluated.
        threshold_used: Score threshold at which Recall@1%FPR was measured.
    """

    scanner_name: str
    recall_at_1pct_fpr: float
    achieved_fpr: float
    auc_roc: float
    precision_at_975_recall: float
    total_benign: int
    total_malicious: int
    threshold_used: float

    def summary(self) -> str:
        """Return a human-readable summary line."""
        return (
            f"{self.scanner_name:30s}  "
            f"Recall@1%FPR={self.recall_at_1pct_fpr:.3f}  "
            f"AUC-ROC={self.auc_roc:.3f}  "
            f"P@97.5R={self.precision_at_975_recall:.3f}  "
            f"benign={self.total_benign}  malicious={self.total_malicious}"
        )


def _find_threshold_at_fpr(
    scores: list[float],
    labels: list[int],
    target_fpr: float,
) -> float:
    """Find the score threshold that achieves recall_at_fpr for reporting."""
    n_neg = sum(1 for l in labels if l == 0)
    if n_neg == 0:
        return 1.0
    for threshold in sorted(set(scores), reverse=True):
        fp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 0)
        if fp / n_neg <= target_fpr:
            return threshold
    return max(scores)


class ScannerEvaluator:
    """Evaluate a scorer function against a labeled injection dataset.

    Args:
        target_fpr: FPR budget for Recall@k%FPR (default 0.01 = 1%).
        target_recall: Recall level for Precision@recall metric (default 0.975).
    """

    def __init__(
        self,
        *,
        target_fpr: float = 0.01,
        target_recall: float = 0.975,
    ) -> None:
        self._target_fpr = target_fpr
        self._target_recall = target_recall

    def evaluate(
        self,
        scorer: Callable[[str], float],
        name: str,
        dataset: LabeledDataset | None = None,
    ) -> ScannerResult:
        """Evaluate a scorer function against the labeled dataset.

        Args:
            scorer: Callable that takes a string and returns a float 0.0-1.0.
                Higher scores indicate more likely injection content.
            name: Human-readable name for the scanner/scorer.
            dataset: LabeledDataset to evaluate against. Uses the default
                60-benign + 60-malicious dataset if None.

        Returns:
            ScannerResult with all computed metrics.
        """
        if dataset is None:
            dataset = default_dataset()

        scores = dataset.scores(scorer)
        labels = dataset.labels

        recall, achieved_fpr = recall_at_fpr(scores, labels, self._target_fpr)
        auc = auc_roc(scores, labels)
        prec = precision_at_recall(scores, labels, self._target_recall)
        threshold = _find_threshold_at_fpr(scores, labels, self._target_fpr)

        total_benign = sum(1 for l in labels if l == 0)
        total_malicious = sum(1 for l in labels if l == 1)

        return ScannerResult(
            scanner_name=name,
            recall_at_1pct_fpr=recall,
            achieved_fpr=achieved_fpr,
            auc_roc=auc,
            precision_at_975_recall=prec,
            total_benign=total_benign,
            total_malicious=total_malicious,
            threshold_used=threshold,
        )
