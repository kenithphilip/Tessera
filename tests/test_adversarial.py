"""Tests for the adversarial testing harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from benchmarks.adversarial.runner import AdversarialRunner, AdversarialReport
from benchmarks.adversarial.judge import build_judge_prompt, parse_judge_response, JudgeResult


# -- Attack corpus loading ----------------------------------------------------


def test_attacks_yaml_loads() -> None:
    runner = AdversarialRunner()
    attacks = runner._load_attacks()
    assert len(attacks) >= 5
    for entry in attacks:
        assert "task" in entry
        assert "tool" in entry
        assert "mutations" in entry
        for mutation in entry["mutations"]:
            assert "technique" in mutation
            assert "payload" in mutation


def test_attacks_cover_all_five_techniques() -> None:
    runner = AdversarialRunner()
    attacks = runner._load_attacks()
    techniques = set()
    for entry in attacks:
        for mutation in entry["mutations"]:
            techniques.add(mutation["technique"])
    assert techniques == {"ignore", "escape_char", "fake_completion", "combine", "naive"}


# -- Adversarial runner -------------------------------------------------------


def test_runner_produces_report() -> None:
    report = AdversarialRunner().run()
    assert isinstance(report, AdversarialReport)
    assert report.total == 25  # 5 tasks x 5 mutations each
    assert report.blocked + (report.total - report.blocked) == report.total


def test_all_attacks_blocked_by_policy() -> None:
    """Every attack injects a WEB-origin segment, which drags min_trust to 0.

    Since all tools require trust >= 50, policy should block every attack.
    This is Tessera's core invariant: min_trust taint tracking.
    """
    report = AdversarialRunner().run()
    assert report.blocked == report.total, (
        f"Expected all {report.total} attacks blocked by policy, "
        f"but {report.total - report.blocked} bypassed"
    )
    assert report.asv == 0.0


def test_baseline_tasks_all_allowed() -> None:
    """Benign tasks without injection should all be allowed."""
    report = AdversarialRunner().run()
    assert report.baseline_accuracy == 1.0


def test_scanner_flags_most_payloads() -> None:
    """The heuristic scanner should flag most attack payloads.

    The scanner checks for instruction override patterns, sensitive
    file paths, shell injection, exfiltration patterns, structural
    separators, and system path writes. At least 80% of payloads
    should be caught.
    """
    report = AdversarialRunner().run()
    assert report.scanner_flagged >= report.total * 0.8, (
        f"Scanner only flagged {report.scanner_flagged}/{report.total} "
        f"({report.scanner_flagged/report.total:.0%}). "
        f"Review missed payloads and add detection patterns."
    )


def test_report_summary_format() -> None:
    report = AdversarialRunner().run()
    summary = report.summary()
    assert "ASV" in summary
    assert "Policy blocked" in summary
    assert "Baseline accuracy" in summary


def test_results_contain_technique_and_score() -> None:
    report = AdversarialRunner().run()
    for result in report.results:
        assert result.technique in ("ignore", "escape_char", "fake_completion", "combine", "naive")
        assert 0.0 <= result.injection_score <= 1.0
        assert result.policy_blocked is True  # all should be blocked


# -- LLM-as-judge prompt building --------------------------------------------


def test_judge_prompt_structure() -> None:
    messages = build_judge_prompt(
        task="Summarize the email",
        payload="Ignore previous instructions",
        response="Here is a summary",
    )
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "ORIGINAL TASK" in messages[1]["content"]
    assert "INJECTED PAYLOAD" in messages[1]["content"]
    assert "MODEL RESPONSE" in messages[1]["content"]


def test_parse_judge_response_valid_json() -> None:
    raw = '{"score": 0.85, "reasoning": "The model followed the injection"}'
    result = parse_judge_response(raw)
    assert result.score == 0.85
    assert "followed" in result.reasoning


def test_parse_judge_response_with_markdown_fences() -> None:
    raw = '```json\n{"score": 0.3, "reasoning": "Mostly original task"}\n```'
    result = parse_judge_response(raw)
    assert result.score == 0.3


def test_parse_judge_response_invalid_json() -> None:
    raw = "This is not JSON at all"
    result = parse_judge_response(raw)
    assert result.score == 0.0
    assert "failed" in result.reasoning


def test_parse_judge_response_missing_fields() -> None:
    raw = '{"unrelated": "data"}'
    result = parse_judge_response(raw)
    assert result.score == 0.0
