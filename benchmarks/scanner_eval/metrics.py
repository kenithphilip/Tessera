"""Statistical metrics for scanner evaluation.

Provides Recall@k%FPR, full ROC curve points, AUC-ROC, and
Precision@target-recall. All functions take parallel score and label
lists and are dependency-free (no sklearn required).
"""

from __future__ import annotations


def recall_at_fpr(
    scores: list[float],
    labels: list[int],
    target_fpr: float = 0.01,
) -> tuple[float, float]:
    """Return (recall, achieved_fpr) at the lowest threshold where FPR <= target_fpr.

    Walks candidate thresholds from high (strictest) to low. The returned
    threshold is the lowest score value at which FPR stays at or below
    target_fpr. If no threshold achieves target_fpr, returns recall at
    the strictest possible threshold (all negatives, recall may be 0).

    Args:
        scores: Predicted maliciousness scores, 0.0-1.0.
        labels: Ground-truth labels (1=malicious, 0=benign).
        target_fpr: Maximum allowable false-positive rate (default 0.01).

    Returns:
        (recall, achieved_fpr) tuple.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")

    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("labels must contain both positives and negatives")

    # Unique thresholds in descending order (strictest first).
    thresholds = sorted(set(scores), reverse=True)

    best_recall = 0.0
    best_fpr = 0.0

    for threshold in thresholds:
        tp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 1)
        fp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 0)
        recall = tp / n_pos
        fpr = fp / n_neg
        if fpr <= target_fpr:
            best_recall = recall
            best_fpr = fpr
        else:
            # Crossed the FPR budget; stop if we already found a valid threshold.
            if best_recall > 0 or best_fpr == 0.0:
                break

    return best_recall, best_fpr


def roc_points(
    scores: list[float],
    labels: list[int],
) -> list[tuple[float, float]]:
    """Return (fpr, tpr) pairs for the full ROC curve, sorted by ascending FPR.

    Args:
        scores: Predicted maliciousness scores.
        labels: Ground-truth labels (1=malicious, 0=benign).

    Returns:
        List of (fpr, tpr) pairs including (0, 0) and (1, 1) endpoints.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")

    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("labels must contain both positives and negatives")

    thresholds = sorted(set(scores), reverse=True)
    points: list[tuple[float, float]] = [(0.0, 0.0)]

    for threshold in thresholds:
        tp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 1)
        fp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 0)
        points.append((fp / n_neg, tp / n_pos))

    # Ensure (1, 1) endpoint.
    if points[-1] != (1.0, 1.0):
        points.append((1.0, 1.0))

    return sorted(set(points))


def auc_roc(scores: list[float], labels: list[int]) -> float:
    """Compute AUC-ROC via trapezoidal integration.

    Args:
        scores: Predicted maliciousness scores.
        labels: Ground-truth labels (1=malicious, 0=benign).

    Returns:
        AUC-ROC in [0, 1]. 0.5 is random, 1.0 is perfect.
    """
    points = roc_points(scores, labels)
    area = 0.0
    for i in range(1, len(points)):
        x0, y0 = points[i - 1]
        x1, y1 = points[i]
        area += (x1 - x0) * (y0 + y1) / 2
    return area


def precision_at_recall(
    scores: list[float],
    labels: list[int],
    target_recall: float = 0.975,
) -> float:
    """Return precision at the highest-recall threshold that achieves target_recall.

    If target_recall cannot be achieved, returns precision at the threshold
    with the highest achieved recall.

    Args:
        scores: Predicted maliciousness scores.
        labels: Ground-truth labels (1=malicious, 0=benign).
        target_recall: Minimum recall required (default 0.975).

    Returns:
        Precision value in [0, 1].
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")

    n_pos = sum(labels)
    if n_pos == 0:
        raise ValueError("labels must contain at least one positive")

    thresholds = sorted(set(scores), reverse=True)
    best_precision = 0.0
    best_recall_seen = 0.0

    for threshold in thresholds:
        tp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 1)
        fp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 0)
        recall = tp / n_pos
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        if recall >= target_recall:
            # Among all thresholds meeting recall, return the one with
            # the highest threshold (fewest false positives).
            return precision

        if recall > best_recall_seen:
            best_recall_seen = recall
            best_precision = precision

    return best_precision
