"""Tests for metrics, corpora, and report modules (Wave 2F).

Covers precision/recall edge cases, roc_auc boundary values, tpr_at_fpr
interpolation, per_category_tpr with missing categories, and an end-to-end
corpus-to-markdown flow.
"""

from __future__ import annotations

import math

import pytest

from benchmarks.scanner_eval.corpora import (
    Corpus,
    load_corpus,
    load_lakera_gandalf,
    load_tensor_trust,
    load_tessera_community_v1,
)
from benchmarks.scanner_eval.metrics import (
    confusion_at_threshold,
    f1_score,
    per_category_tpr,
    precision,
    recall,
    roc_auc,
    tpr_at_fpr,
)
from benchmarks.scanner_eval.report import EvaluationResult, evaluate, format_markdown


# ---- precision / recall edge cases ----------------------------------------


def test_precision_all_positive() -> None:
    assert precision(10, 0) == pytest.approx(1.0)


def test_precision_all_negative() -> None:
    # all predicted negative means tp=0 fp=0 -> division by zero -> 0.0
    assert precision(0, 0) == 0.0


def test_precision_mixed() -> None:
    assert precision(3, 1) == pytest.approx(0.75)


def test_recall_all_positive() -> None:
    assert recall(10, 0) == pytest.approx(1.0)


def test_recall_all_negative() -> None:
    assert recall(0, 0) == 0.0


def test_recall_mixed() -> None:
    assert recall(2, 2) == pytest.approx(0.5)


def test_f1_zero_denom() -> None:
    assert f1_score(0.0, 0.0) == 0.0


def test_f1_perfect() -> None:
    assert f1_score(1.0, 1.0) == pytest.approx(1.0)


def test_f1_mixed() -> None:
    p, r = 0.8, 0.6
    expected = 2 * p * r / (p + r)
    assert f1_score(p, r) == pytest.approx(expected)


# ---- roc_auc boundary values -----------------------------------------------


def test_roc_auc_perfect_classifier() -> None:
    # Perfect: all positives score above all negatives.
    scores = [0.9, 0.8, 0.7, 0.1, 0.2, 0.3]
    labels = [1, 1, 1, 0, 0, 0]
    assert roc_auc(scores, labels) == pytest.approx(1.0)


def test_roc_auc_worst_classifier() -> None:
    # Inverted: all negatives score above all positives.
    scores = [0.1, 0.2, 0.3, 0.9, 0.8, 0.7]
    labels = [1, 1, 1, 0, 0, 0]
    assert roc_auc(scores, labels) == pytest.approx(0.0)


def test_roc_auc_random_classifier() -> None:
    # Alternating: AUC should be near 0.5.
    import random

    rng = random.Random(42)
    n = 200
    scores = [rng.random() for _ in range(n)]
    labels = [rng.randint(0, 1) for _ in range(n)]
    # Ensure both classes present.
    labels[0] = 0
    labels[1] = 1
    auc = roc_auc(scores, labels)
    assert 0.3 <= auc <= 0.7, f"Expected ~0.5, got {auc}"


def test_roc_auc_requires_both_classes() -> None:
    with pytest.raises(ValueError):
        roc_auc([0.9, 0.8], [1, 1])


# ---- tpr_at_fpr interpolation ----------------------------------------------


def test_tpr_at_fpr_exact_boundary() -> None:
    scores = [0.9, 0.8, 0.3, 0.2]
    labels = [1, 1, 0, 0]
    # At FPR=0 TPR should be 0, at FPR=1 TPR should be 1.
    assert tpr_at_fpr(scores, labels, 0.0) == pytest.approx(0.0)
    assert tpr_at_fpr(scores, labels, 1.0) == pytest.approx(1.0)


def test_tpr_at_fpr_perfect_classifier_at_low_fpr() -> None:
    scores = [0.9, 0.8, 0.1, 0.2]
    labels = [1, 1, 0, 0]
    # Perfect classifier: at FPR=0.01 should still achieve TPR=1.0
    # because the positive scores are well above the negative scores.
    tpr = tpr_at_fpr(scores, labels, 0.01)
    assert tpr == pytest.approx(1.0)


def test_tpr_at_fpr_above_max() -> None:
    scores = [0.9, 0.1, 0.8, 0.2]
    labels = [1, 0, 1, 0]
    # target_fpr > 1.0 should return the last TPR (1.0).
    assert tpr_at_fpr(scores, labels, 1.5) == pytest.approx(1.0)


# ---- confusion_at_threshold ------------------------------------------------


def test_confusion_at_threshold_basic() -> None:
    scores = [0.9, 0.4, 0.8, 0.2]
    labels = [1, 1, 0, 0]
    cm = confusion_at_threshold(scores, labels, 0.5)
    assert cm["tp"] == 1
    assert cm["fn"] == 1
    assert cm["fp"] == 1
    assert cm["tn"] == 1


def test_confusion_at_threshold_all_positive() -> None:
    scores = [0.9, 0.9]
    labels = [1, 0]
    cm = confusion_at_threshold(scores, labels, 0.5)
    assert cm["tp"] == 1
    assert cm["fp"] == 1
    assert cm["tn"] == 0
    assert cm["fn"] == 0


def test_confusion_length_mismatch() -> None:
    with pytest.raises(ValueError):
        confusion_at_threshold([0.5], [1, 0], 0.5)


# ---- per_category_tpr ------------------------------------------------------


def test_per_category_tpr_basic() -> None:
    records = [
        {"score": 0.9, "label": 1, "category": "prompt_injection"},
        {"score": 0.4, "label": 1, "category": "prompt_injection"},
        {"score": 0.8, "label": 1, "category": "exfil"},
        {"score": 0.3, "label": 0, "category": "exfil"},
    ]
    result = per_category_tpr(records, ["prompt_injection", "exfil"])
    assert result["prompt_injection"] == pytest.approx(0.5)  # 1/2
    assert result["exfil"] == pytest.approx(1.0)             # 1/1 positives


def test_per_category_tpr_missing_category() -> None:
    records: list[dict] = []
    result = per_category_tpr(records, ["url_manipulation"])
    assert result["url_manipulation"] == pytest.approx(0.0)


def test_per_category_tpr_ignores_unknown_categories() -> None:
    records = [{"score": 0.9, "label": 1, "category": "unknown_type"}]
    result = per_category_tpr(records, ["prompt_injection"])
    assert result["prompt_injection"] == pytest.approx(0.0)


def test_per_category_tpr_only_negatives() -> None:
    records = [{"score": 0.9, "label": 0, "category": "exfil"}]
    result = per_category_tpr(records, ["exfil"])
    assert result["exfil"] == pytest.approx(0.0)


# ---- corpora loading -------------------------------------------------------


def test_load_tessera_community_v1() -> None:
    corpus = load_tessera_community_v1()
    assert corpus.name == "tessera_community_v1"
    assert len(corpus.payloads) >= 10
    assert all("text" in p and "label" in p for p in corpus.payloads)


def test_load_lakera_gandalf() -> None:
    corpus = load_lakera_gandalf()
    assert corpus.name == "lakera_gandalf"
    assert len(corpus.payloads) >= 10


def test_load_tensor_trust() -> None:
    corpus = load_tensor_trust()
    assert corpus.name == "tensor_trust"
    assert len(corpus.payloads) >= 10


def test_load_corpus_missing_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_corpus("does_not_exist_corpus_xyz")


# ---- end-to-end: no-op scanner -> markdown ---------------------------------


def test_end_to_end_noop_scanner_markdown() -> None:
    corpus = load_tessera_community_v1()

    def noop_scorer(text: str) -> float:
        return 0.0

    result = evaluate(noop_scorer, corpus, scanner_name="noop")
    assert isinstance(result, EvaluationResult)
    assert result.scanner_name == "noop"
    assert result.corpus_name == "tessera_community_v1"
    # All scores are 0.0: at threshold 0.5 all predicted negative.
    for tm in result.per_threshold:
        if tm.threshold > 0.0:
            assert tm.tp == 0
            assert tm.fp == 0

    md = format_markdown([result])
    assert "# Scanner Evaluation Report" in md
    assert "noop" in md
    assert "tessera_community_v1" in md
    # Markdown table header present
    assert "| Corpus |" in md
    assert "| AUC-ROC |" in md
