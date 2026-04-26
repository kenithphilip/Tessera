"""Mocked-API integration tests for ``benchmarks.agentdojo_live.run_gemini``.

Mirrors the test pattern in ``tests/test_run_openai.py``. Live-API
verification is the operator's responsibility (see
``docs/benchmarks/REAL_RUN_RUNBOOK.md``).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("agentdojo")


def test_run_gemini_cell_returns_error_dict_when_api_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing GOOGLE_API_KEY (and GEMINI_API_KEY) must surface as
    ``error`` field on the metrics dict."""
    from benchmarks.agentdojo_live.run_gemini import run_gemini_cell

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    out = run_gemini_cell(
        model="gemini-2.5-pro",
        suite_name="travel",
        attack_name="important_instructions",
        seed=0,
        max_pairs=1,
    )
    assert "GOOGLE_API_KEY" in out["error"]
    assert out["utility_attempt"] == 0.0
    assert out["raw_runs"] == []
    for k in (
        "utility_attempt", "targeted_asr", "attack_prevention_rate",
        "utility_delta", "raw_runs", "elapsed_seconds", "error",
    ):
        assert k in out


def test_run_gemini_cell_accepts_legacy_gemini_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Either GOOGLE_API_KEY or the legacy GEMINI_API_KEY satisfies
    the env-var preflight."""
    from benchmarks.agentdojo_live.run_gemini import run_gemini_cell

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key-not-real")
    # The next failure mode is google-genai not installed (or, if
    # installed, an HTTP error). Either way the cell returns a clean
    # error dict; we only assert the env-var preflight passed.
    out = run_gemini_cell(
        model="gemini-2.5-pro",
        suite_name="travel",
        attack_name="important_instructions",
        seed=0,
        max_pairs=1,
    )
    # Must not be the API-key-missing error.
    assert "GOOGLE_API_KEY" not in (out.get("error") or "")


def test_run_gemini_cell_unknown_attack_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-not-real")
    from benchmarks.agentdojo_live.run_gemini import run_gemini_cell

    out = run_gemini_cell(
        model="gemini-2.5-pro",
        suite_name="travel",
        attack_name="bogus-attack-name",
        seed=0,
        max_pairs=1,
    )
    assert out["error"] is not None
    assert "bogus-attack-name" in out["error"]


def test_run_gemini_cell_dispatches_through_run_trial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end shape test mirroring the OpenAI runner. The
    google-genai SDK is mocked so this test runs in environments
    that don't have it installed."""
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-key-not-real")

    fake_pipeline_query_calls: list[tuple] = []

    def _fake_query(prompt, runtime, env):
        fake_pipeline_query_calls.append((prompt, runtime, env))
        messages = [{"role": "assistant", "content": "ok"}]
        return None, None, env, messages, None

    # Patch _build_genai_client so we don't need google-genai installed.
    fake_client = MagicMock(name="genai.Client")
    with patch(
        "benchmarks.agentdojo_live.run_gemini._build_genai_client",
        return_value=fake_client,
    ), patch(
        "benchmarks.agentdojo_live.run_gemini.GoogleLLM",
        return_value=MagicMock(name="GoogleLLM"),
    ), patch(
        "benchmarks.agentdojo_live.run_haiku.AgentPipeline",
    ) as mock_pipeline_cls:
        mock_pipeline = MagicMock()
        mock_pipeline.query = _fake_query
        mock_pipeline_cls.return_value = mock_pipeline

        from benchmarks.agentdojo_live.run_gemini import run_gemini_cell
        out = run_gemini_cell(
            model="gemini-2.5-pro",
            suite_name="travel",
            attack_name="important_instructions",
            seed=0,
            max_pairs=1,
        )

    assert out["error"] is None
    assert isinstance(out["utility_attempt"], float)
    assert isinstance(out["targeted_asr"], float)
    assert 0.0 <= out["attack_prevention_rate"] <= 1.0
    assert isinstance(out["raw_runs"], list)
    assert out["elapsed_seconds"] >= 0
    assert len(fake_pipeline_query_calls) >= 1
