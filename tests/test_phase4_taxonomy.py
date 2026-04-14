"""Tests for Phase 4.1: injection variant taxonomy corpus and runner."""

from __future__ import annotations

import pytest

from benchmarks.injection_taxonomy.corpus import INJECTION_CASES
from benchmarks.injection_taxonomy.runner import TaxonomyReport, TaxonomyRunner
from benchmarks.injection_taxonomy.taxonomy import (
    InjectionType,
    InjectionVariant,
    RiskCategory,
)


# ---------------------------------------------------------------------------
# Corpus completeness (fast, no runner needed)
# ---------------------------------------------------------------------------


def test_all_injection_variants_represented() -> None:
    """Every InjectionVariant must appear at least once in the corpus."""
    present = {c.injection_variant for c in INJECTION_CASES}
    missing = set(InjectionVariant) - present
    assert not missing, f"Missing variants: {missing}"


def test_all_risk_categories_represented() -> None:
    """Every RiskCategory must appear at least once in the corpus."""
    present = {c.risk_category for c in INJECTION_CASES}
    missing = set(RiskCategory) - present
    assert not missing, f"Missing risk categories: {missing}"


def test_both_injection_types_represented() -> None:
    """Both DIRECT and INDIRECT injection types must be present."""
    types = {c.injection_type for c in INJECTION_CASES}
    assert InjectionType.DIRECT in types
    assert InjectionType.INDIRECT in types


def test_corpus_size() -> None:
    """Corpus must contain exactly 48 cases."""
    assert len(INJECTION_CASES) == 48


def test_all_case_ids_unique() -> None:
    """Every case must have a unique ID."""
    ids = [c.id for c in INJECTION_CASES]
    assert len(ids) == len(set(ids)), "Duplicate IDs found in corpus"


def test_all_cases_expected_blocked() -> None:
    """All corpus cases should have expected_blocked=True."""
    not_blocked = [c.id for c in INJECTION_CASES if not c.expected_blocked]
    assert not not_blocked, f"Cases with expected_blocked=False: {not_blocked}"


# ---------------------------------------------------------------------------
# TaxonomyRunner: single shared run (the runner calls injection_score 48
# times, each doing a 1700-phrase sliding window. Running it once is ~19s;
# running it 8 times blows the suite to 150s. Share one result.)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def taxonomy_report() -> TaxonomyReport:
    return TaxonomyRunner().run()


def test_runner_benign_baselines_all_allowed(taxonomy_report: TaxonomyReport) -> None:
    not_allowed = [r.case.id for r in taxonomy_report.results if not r.baseline_allowed]
    assert not not_allowed, f"Benign baselines denied for: {not_allowed}"


def test_runner_policy_blocks_all_cases(taxonomy_report: TaxonomyReport) -> None:
    not_blocked = [r.case.id for r in taxonomy_report.results if not r.policy_blocked]
    assert not not_blocked, (
        f"Policy failed to block {len(not_blocked)} cases: {not_blocked}"
    )


def test_runner_policy_only_apr_is_one(taxonomy_report: TaxonomyReport) -> None:
    assert taxonomy_report.policy_only_apr == pytest.approx(1.0)


def test_runner_report_total_count(taxonomy_report: TaxonomyReport) -> None:
    assert taxonomy_report.total == len(INJECTION_CASES)


def test_runner_report_by_variant_keys(taxonomy_report: TaxonomyReport) -> None:
    assert set(taxonomy_report.by_variant.keys()) == set(InjectionVariant)


def test_runner_report_by_risk_keys(taxonomy_report: TaxonomyReport) -> None:
    assert set(taxonomy_report.by_risk.keys()) == set(RiskCategory)


def test_runner_report_by_type_keys(taxonomy_report: TaxonomyReport) -> None:
    assert set(taxonomy_report.by_type.keys()) == set(InjectionType)


def test_runner_report_breakdown_totals_sum_to_corpus(taxonomy_report: TaxonomyReport) -> None:
    variant_total = sum(e.total for e in taxonomy_report.by_variant.values())
    assert variant_total == len(INJECTION_CASES)


def test_runner_report_apr_gte_policy_only_apr(taxonomy_report: TaxonomyReport) -> None:
    assert taxonomy_report.apr >= taxonomy_report.policy_only_apr


def test_runner_report_utility_score_is_one(taxonomy_report: TaxonomyReport) -> None:
    assert taxonomy_report.utility_score == pytest.approx(1.0)
