"""Plan verifier tests.

Validates heuristic intent-to-tool-pattern matching and sequence
verification scoring.
"""

from __future__ import annotations

import pytest

from tessera.plan_verifier import (
    PlanVerificationResult,
    ToolSequenceSpec,
    infer_spec_from_prompt,
    verify_sequence,
)


def test_search_prompt_forbids_send():
    spec = infer_spec_from_prompt("find hotels in Paris")
    assert "send_*" in spec.forbidden_patterns
    result = verify_sequence(spec, ["send_email"])
    assert not result.passed
    assert "send_email" in result.unexpected_tools


def test_send_prompt_allows_send():
    spec = infer_spec_from_prompt("send email to alice")
    assert "send_*" in spec.required_patterns
    result = verify_sequence(spec, ["send_email"])
    assert result.passed
    assert result.unexpected_tools == ()


def test_forbidden_tool_detected():
    spec = ToolSequenceSpec(
        required_patterns=("search_*",),
        forbidden_patterns=("delete_*",),
        max_calls=None,
    )
    result = verify_sequence(spec, ["search_web", "delete_file"])
    assert not result.passed
    assert "delete_file" in result.unexpected_tools
    assert any("delete_file" in v for v in result.violations)


def test_max_calls_exceeded():
    spec = ToolSequenceSpec(
        required_patterns=(),
        forbidden_patterns=(),
        max_calls=2,
    )
    result = verify_sequence(spec, ["a", "b", "c"])
    assert not result.passed
    assert any("limit is 2" in v for v in result.violations)
    assert result.score == pytest.approx(0.2)


def test_clean_sequence_passes():
    spec = ToolSequenceSpec(
        required_patterns=("search_*",),
        forbidden_patterns=("delete_*",),
        max_calls=10,
    )
    result = verify_sequence(spec, ["search_web", "search_docs"])
    assert result.passed
    assert result.violations == ()
    assert result.unexpected_tools == ()
    assert result.score == pytest.approx(0.0)


def test_score_accumulates():
    spec = ToolSequenceSpec(
        required_patterns=(),
        forbidden_patterns=("bad_*",),
        max_calls=1,
    )
    result = verify_sequence(spec, ["bad_a", "bad_b", "bad_c"])
    # 3 forbidden matches (0.3 each = 0.9) + max_calls exceeded (0.2) = 1.1, capped to 1.0
    assert result.score == pytest.approx(1.0)
    assert len(result.violations) == 4  # 3 forbidden + 1 max_calls
