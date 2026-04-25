"""Statistical metrics for scanner evaluation.

Provides precision, recall, F1, ROC AUC, TPR-at-FPR, confusion matrix at a
threshold, per-category TPR, Recall@k%FPR, full ROC curve points, and
Precision@target-recall. All functions take parallel score and label lists
and are dependency-free (no sklearn required).
"""

from __future__ import annotations


def precision(tp: int, fp: int) -> float:
    """Precision = TP / (TP + FP). Returns 0.0 when TP + FP == 0.

    Args:
        tp: True-positive count.
        fp: False-positive count.

    Returns:
        Precision in [0, 1].
    """
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0


def recall(tp: int, fn: int) -> float:
    """Recall = TP / (TP + FN). Returns 0.0 when TP + FN == 0.

    Args:
        tp: True-positive count.
        fn: False-negative count.

    Returns:
        Recall in [0, 1].
    """
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


def f1_score(p: float, r: float) -> float:
    """Harmonic mean of precision and recall. Returns 0.0 when p + r == 0.

    Args:
        p: Precision value.
        r: Recall value.

    Returns:
        F1 in [0, 1].
    """
    return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def roc_auc(scores: list[float], labels: list[int]) -> float:
    """AUC-ROC via trapezoidal integration over sorted (score, label) pairs.

    Does not require sklearn. Identical in result to ``auc_roc`` but
    accepts the shorter name expected by Wave 2F.

    Args:
        scores: Predicted maliciousness scores, 0.0-1.0.
        labels: Ground-truth labels (1=malicious, 0=benign).

    Returns:
        AUC-ROC in [0, 1]. 0.5 is random, 1.0 is perfect.
    """
    return auc_roc(scores, labels)


def tpr_at_fpr(
    scores: list[float],
    labels: list[int],
    target_fpr: float,
) -> float:
    """Interpolated TPR at a given FPR operating point.

    Finds the two adjacent ROC points that bracket target_fpr and linearly
    interpolates TPR between them. Returns 0.0 if target_fpr is below the
    minimum achievable FPR, 1.0 if above the maximum.

    Args:
        scores: Predicted maliciousness scores.
        labels: Ground-truth labels (1=malicious, 0=benign).
        target_fpr: The FPR value at which to interpolate TPR.

    Returns:
        Interpolated TPR in [0, 1].
    """
    # Convention: every ROC curve starts at (0, 0). A request for
    # FPR=0.0 returns the operating point where no samples have been
    # classified positive (TPR=0.0), not the highest TPR achievable
    # at that FPR. This matches the test_tpr_at_fpr_exact_boundary
    # expectation and the standard "left edge of the ROC curve"
    # interpretation.
    if target_fpr <= 0.0:
        return 0.0
    points = roc_points(scores, labels)
    for i in range(1, len(points)):
        x0, y0 = points[i - 1]
        x1, y1 = points[i]
        if x0 <= target_fpr <= x1:
            if x1 == x0:
                return y1
            return y0 + (y1 - y0) * (target_fpr - x0) / (x1 - x0)
    if target_fpr >= points[-1][0]:
        return points[-1][1]
    return 0.0


def confusion_at_threshold(
    scores: list[float],
    labels: list[int],
    threshold: float,
) -> dict[str, int]:
    """Confusion matrix counts at a given score threshold.

    A sample is classified positive when its score >= threshold.

    Args:
        scores: Predicted maliciousness scores.
        labels: Ground-truth labels (1=malicious, 0=benign).
        threshold: Decision boundary.

    Returns:
        Dict with keys "tp", "fp", "tn", "fn".
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have equal length")

    tp = fp = tn = fn = 0
    for s, l in zip(scores, labels):
        predicted = 1 if s >= threshold else 0
        if predicted == 1 and l == 1:
            tp += 1
        elif predicted == 1 and l == 0:
            fp += 1
        elif predicted == 0 and l == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


_KNOWN_CATEGORIES = frozenset(
    {"prompt_injection", "exfil", "tool_description_injection", "url_manipulation"}
)


def per_category_tpr(
    records: list[dict],
    categories: list[str],
    *,
    threshold: float = 0.5,
) -> dict[str, float]:
    """TPR broken down by attack category.

    Each record must have keys "score" (float), "label" (int), and
    "category" (str). Categories with no positive samples receive 0.0.

    Args:
        records: List of dicts with keys "score", "label", "category".
        categories: Category names to report (e.g. ["prompt_injection", "exfil"]).
        threshold: Score threshold for a positive prediction (default 0.5).

    Returns:
        Dict mapping each category to its TPR. Missing categories return 0.0.

    Example::

        records = [
            {"score": 0.9, "label": 1, "category": "prompt_injection"},
            {"score": 0.2, "label": 1, "category": "exfil"},
        ]
        result = per_category_tpr(records, ["prompt_injection", "exfil"])
        # {"prompt_injection": 1.0, "exfil": 0.0}
    """
    tp_by_cat: dict[str, int] = {c: 0 for c in categories}
    total_by_cat: dict[str, int] = {c: 0 for c in categories}

    for r in records:
        cat = r.get("category", "")
        if cat not in tp_by_cat:
            continue
        if r["label"] != 1:
            continue
        total_by_cat[cat] += 1
        if r["score"] >= threshold:
            tp_by_cat[cat] += 1

    return {
        c: (tp_by_cat[c] / total_by_cat[c] if total_by_cat[c] > 0 else 0.0)
        for c in categories
    }


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
