"""Mocked-API integration tests for ``benchmarks.agentdojo_live.run_cohere``.

Mirrors the test pattern in ``tests/test_run_openai.py`` and
``tests/test_run_gemini.py``. Live-API verification is the operator's
responsibility (see ``docs/benchmarks/REAL_RUN_RUNBOOK.md``).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("agentdojo")


def test_run_cohere_cell_returns_error_dict_when_api_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from benchmarks.agentdojo_live.run_cohere import run_cohere_cell

    monkeypatch.delenv("COHERE_API_KEY", raising=False)
    out = run_cohere_cell(
        model="command-r7b-12-2024",
        suite_name="travel",
        attack_name="important_instructions",
        seed=0,
        max_pairs=1,
    )
    assert out["error"] == "COHERE_API_KEY not set"
    assert out["utility_attempt"] == 0.0
    assert out["raw_runs"] == []
    for k in (
        "utility_attempt", "targeted_asr", "attack_prevention_rate",
        "utility_delta", "raw_runs", "elapsed_seconds", "error",
    ):
        assert k in out


def test_run_cohere_cell_unknown_attack_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("COHERE_API_KEY", "fake-key-not-real")
    from benchmarks.agentdojo_live.run_cohere import run_cohere_cell

    out = run_cohere_cell(
        model="command-r7b-12-2024",
        suite_name="travel",
        attack_name="bogus-attack-name",
        seed=0,
        max_pairs=1,
    )
    assert out["error"] is not None
    assert "bogus-attack-name" in out["error"]


def test_run_cohere_cell_dispatches_through_run_trial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end shape test mirroring the OpenAI runner. The
    cohere SDK is mocked so this test runs in environments that
    don't have it installed."""
    monkeypatch.setenv("COHERE_API_KEY", "fake-key-not-real")

    fake_pipeline_query_calls: list[tuple] = []

    def _fake_query(prompt, runtime, env):
        fake_pipeline_query_calls.append((prompt, runtime, env))
        messages = [{"role": "assistant", "content": "ok"}]
        return None, None, env, messages, None

    fake_client = MagicMock(name="cohere.Client")
    with patch(
        "benchmarks.agentdojo_live.run_cohere._build_cohere_client",
        return_value=fake_client,
    ), patch(
        "benchmarks.agentdojo_live.run_cohere.CohereLLM",
        return_value=MagicMock(name="CohereLLM"),
    ), patch(
        "benchmarks.agentdojo_live.run_haiku.AgentPipeline",
    ) as mock_pipeline_cls:
        mock_pipeline = MagicMock()
        mock_pipeline.query = _fake_query
        mock_pipeline_cls.return_value = mock_pipeline

        from benchmarks.agentdojo_live.run_cohere import run_cohere_cell
        out = run_cohere_cell(
            model="command-r7b-12-2024",
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
