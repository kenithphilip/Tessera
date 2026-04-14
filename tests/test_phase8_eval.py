"""Tests for Phase 8 evaluation infrastructure.

8.1: CyberSecEval-compatible benchmark suite
8.2: End-to-end injection resistance test
"""

from __future__ import annotations

import pytest

from benchmarks.cyberseceval.dataset import CYBERSECEVAL_DATASET, CyberSecEvalCase
from benchmarks.cyberseceval.runner import (
    CyberSecEvalReport,
    CyberSecEvalRunner,
    TypeBreakdown,
)
from benchmarks.e2e_injection.runner import E2EReport, E2ERunner
from benchmarks.e2e_injection.scenarios import SCENARIOS, InjectionScenario


# -----------------------------------------------------------------------
# 8.1 CyberSecEval
# -----------------------------------------------------------------------


class TestCyberSecEvalDataset:
    """Verify dataset structure and coverage."""

    def test_dataset_has_40_cases(self) -> None:
        assert len(CYBERSECEVAL_DATASET) == 40

    def test_all_cases_are_cyberseceval_case(self) -> None:
        for case in CYBERSECEVAL_DATASET:
            assert isinstance(case, CyberSecEvalCase)

    def test_injection_types_represented(self) -> None:
        types = {c.injection_type for c in CYBERSECEVAL_DATASET}
        assert "direct" in types
        assert "indirect" in types

    def test_direct_count(self) -> None:
        direct = [c for c in CYBERSECEVAL_DATASET if c.injection_type == "direct"]
        assert len(direct) == 20

    def test_indirect_count(self) -> None:
        indirect = [c for c in CYBERSECEVAL_DATASET if c.injection_type == "indirect"]
        assert len(indirect) == 20

    def test_all_variants_represented(self) -> None:
        variants = {c.injection_variant for c in CYBERSECEVAL_DATASET}
        expected = {
            "naive",
            "ignore_instructions",
            "fake_completion",
            "context_switch",
            "encoding_attack",
        }
        assert variants == expected

    def test_each_variant_has_8_cases(self) -> None:
        from collections import Counter
        counts = Counter(c.injection_variant for c in CYBERSECEVAL_DATASET)
        for variant, count in counts.items():
            assert count == 8, f"{variant} has {count} cases, expected 8"

    def test_all_risk_categories_represented(self) -> None:
        risks = {c.risk_category for c in CYBERSECEVAL_DATASET}
        expected = {
            "data_exfiltration",
            "unauthorized_action",
            "privilege_escalation",
            "information_disclosure",
        }
        assert risks == expected

    def test_each_risk_has_10_cases(self) -> None:
        from collections import Counter
        counts = Counter(c.risk_category for c in CYBERSECEVAL_DATASET)
        for risk, count in counts.items():
            assert count == 10, f"{risk} has {count} cases, expected 10"

    def test_all_expected_blocked(self) -> None:
        for case in CYBERSECEVAL_DATASET:
            assert case.expected_blocked is True

    def test_unique_ids(self) -> None:
        ids = [c.id for c in CYBERSECEVAL_DATASET]
        assert len(ids) == len(set(ids))


# Share one CyberSecEvalReport across all runner tests.
@pytest.fixture(scope="module")
def cyberseceval_report() -> CyberSecEvalReport:
    return CyberSecEvalRunner().run()


class TestCyberSecEvalRunner:
    """Verify runner produces correct metrics."""

    def test_report_total(self, cyberseceval_report: CyberSecEvalReport) -> None:
        assert isinstance(cyberseceval_report, CyberSecEvalReport)
        assert cyberseceval_report.total == 40

    def test_policy_only_apr_is_1(self, cyberseceval_report: CyberSecEvalReport) -> None:
        assert cyberseceval_report.policy_only_apr == 1.0

    def test_utility_score_is_1(self, cyberseceval_report: CyberSecEvalReport) -> None:
        assert cyberseceval_report.utility_score == 1.0

    def test_apr_at_least_policy_only(self, cyberseceval_report: CyberSecEvalReport) -> None:
        assert cyberseceval_report.apr >= cyberseceval_report.policy_only_apr

    def test_by_type_keys(self, cyberseceval_report: CyberSecEvalReport) -> None:
        assert "direct" in cyberseceval_report.by_type
        assert "indirect" in cyberseceval_report.by_type

    def test_by_variant_keys(self, cyberseceval_report: CyberSecEvalReport) -> None:
        expected = {"naive", "ignore_instructions", "fake_completion", "context_switch", "encoding_attack"}
        assert set(cyberseceval_report.by_variant.keys()) == expected

    def test_by_risk_keys(self, cyberseceval_report: CyberSecEvalReport) -> None:
        expected = {"data_exfiltration", "unauthorized_action", "privilege_escalation", "information_disclosure"}
        assert set(cyberseceval_report.by_risk.keys()) == expected

    def test_to_cyberseceval_format(self, cyberseceval_report: CyberSecEvalReport) -> None:
        formatted = cyberseceval_report.to_cyberseceval_format()
        assert isinstance(formatted, list)
        assert len(formatted) == 40
        expected_keys = {
            "test_case_prompt", "injected_prompt", "injection_type", "injection_variant",
            "risk_category", "target_tool", "expected_blocked", "policy_blocked",
            "scanner_blocked", "injection_score", "baseline_allowed", "blocked",
        }
        for entry in formatted:
            assert isinstance(entry, dict)
            assert set(entry.keys()) == expected_keys

    def test_summary_is_string(self, cyberseceval_report: CyberSecEvalReport) -> None:
        s = cyberseceval_report.summary()
        assert isinstance(s, str)
        assert "CyberSecEval" in s

    def test_breakdown_types(self, cyberseceval_report: CyberSecEvalReport) -> None:
        for b in cyberseceval_report.by_type.values():
            assert isinstance(b, TypeBreakdown)


# -----------------------------------------------------------------------
# 8.2 E2E Injection Resistance
# -----------------------------------------------------------------------


class TestE2EScenarios:
    """Verify scenario structure and coverage."""

    def test_scenarios_has_30_items(self) -> None:
        assert len(SCENARIOS) == 30

    def test_all_scenarios_are_injection_scenario(self) -> None:
        for s in SCENARIOS:
            assert isinstance(s, InjectionScenario)

    def test_all_vectors_represented(self) -> None:
        vectors = {s.injection_vector for s in SCENARIOS}
        expected = {
            "tool_description", "tool_output", "web_content",
            "rag_document", "mcp_baseline_drift", "unicode_steganography",
        }
        assert vectors == expected

    def test_tool_description_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "tool_description") == 5

    def test_tool_output_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "tool_output") == 8

    def test_web_content_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "web_content") == 5

    def test_rag_document_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "rag_document") == 5

    def test_mcp_drift_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "mcp_baseline_drift") == 4

    def test_unicode_count(self) -> None:
        assert sum(1 for s in SCENARIOS if s.injection_vector == "unicode_steganography") == 3

    def test_unique_ids(self) -> None:
        ids = [s.id for s in SCENARIOS]
        assert len(ids) == len(set(ids))


# Share one E2EReport across all runner tests.
@pytest.fixture(scope="module")
def e2e_report() -> E2EReport:
    return E2ERunner().run()


class TestE2ERunner:
    """Verify runner produces correct metrics."""

    def test_report_type(self, e2e_report: E2EReport) -> None:
        assert isinstance(e2e_report, E2EReport)

    def test_report_total(self, e2e_report: E2EReport) -> None:
        assert e2e_report.total == 30

    def test_detection_rate_above_threshold(self, e2e_report: E2EReport) -> None:
        assert e2e_report.detection_rate > 0.8

    def test_block_rate_above_threshold(self, e2e_report: E2EReport) -> None:
        assert e2e_report.block_rate > 0.5

    def test_by_vector_has_all_keys(self, e2e_report: E2EReport) -> None:
        expected = {
            "tool_description", "tool_output", "web_content",
            "rag_document", "mcp_baseline_drift", "unicode_steganography",
        }
        assert set(e2e_report.by_vector.keys()) == expected

    def test_tool_description_detected_via_scan_tool(self, e2e_report: E2EReport) -> None:
        td_results = [r for r in e2e_report.results if r.scenario.injection_vector == "tool_description"]
        detected = [r for r in td_results if r.detected]
        assert len(detected) >= 4
        for r in detected:
            assert r.detection_method == "scan_tool"

    def test_unicode_detected_via_scan_unicode(self, e2e_report: E2EReport) -> None:
        uni_results = [r for r in e2e_report.results if r.scenario.injection_vector == "unicode_steganography"]
        for r in uni_results:
            assert r.detected is True
            assert r.detection_method == "scan_unicode_tags"

    def test_mcp_drift_detected(self, e2e_report: E2EReport) -> None:
        mcp_results = [r for r in e2e_report.results if r.scenario.injection_vector == "mcp_baseline_drift"]
        for r in mcp_results:
            assert r.detected is True
            assert r.detection_method == "mcp_baseline"

    def test_summary_is_string(self, e2e_report: E2EReport) -> None:
        s = e2e_report.summary()
        assert isinstance(s, str)
        assert "E2E" in s
