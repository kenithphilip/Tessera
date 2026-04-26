"""Mocked-API integration tests for ``benchmarks.agentdojo_live.run_openai``.

These tests do not call the real OpenAI API. They patch the
``openai.OpenAI`` client so the trial machinery exercises end-to-end
without external dependencies, and verify the returned cell metrics
have the expected shape.

Live-API verification is the operator's responsibility: see
``docs/benchmarks/REAL_RUN_RUNBOOK.md``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# Skip the entire module when agentdojo is not installed (it's an
# optional extra). Mirrors the pattern in tests/test_phase4_agentdojo.py.
pytest.importorskip("agentdojo")
pytest.importorskip("openai")


def test_canonical_model_resolves_friendly_aliases() -> None:
    """The friendly aliases (gpt-5, gpt-4.1) should map to gpt-4o; any
    other gpt-*/o1*/o3* id passes through verbatim so operators can
    target a specific snapshot."""
    from benchmarks.agentdojo_live.run_openai import _canonical_model
    assert _canonical_model("gpt-5") == "gpt-4o"
    assert _canonical_model("gpt-4.1") == "gpt-4o"
    assert _canonical_model("gpt-4o") == "gpt-4o"
    assert _canonical_model("gpt-4o-mini") == "gpt-4o-mini"
    # Pass-through preserves snapshot ids.
    assert _canonical_model("gpt-4o-2024-08-06") == "gpt-4o-2024-08-06"
    assert _canonical_model("o1-preview") == "o1-preview"


def test_run_openai_cell_returns_error_dict_when_api_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing OPENAI_API_KEY must surface as ``error`` field on the
    metrics dict, not raise. submit.py's run_cell relies on this
    contract: the dispatcher catches Exceptions but expects clean
    metric shapes from the per-provider runners."""
    from benchmarks.agentdojo_live.run_openai import run_openai_cell

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = run_openai_cell(
        model="gpt-4o-mini",
        suite_name="travel",
        attack_name="important_instructions",
        seed=0,
        max_pairs=1,
    )
    assert out["error"] == "OPENAI_API_KEY not set"
    assert out["utility_attempt"] == 0.0
    assert out["raw_runs"] == []
    # All metric fields must be present so the caller can serialise
    # without KeyError.
    for k in (
        "utility_attempt", "targeted_asr", "attack_prevention_rate",
        "utility_delta", "raw_runs", "elapsed_seconds", "error",
    ):
        assert k in out


def test_run_openai_cell_unknown_attack_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-test-key-not-real")
    from benchmarks.agentdojo_live.run_openai import run_openai_cell

    out = run_openai_cell(
        model="gpt-4o-mini",
        suite_name="travel",
        attack_name="bogus-attack-name",
        seed=0,
        max_pairs=1,
    )
    assert out["error"] is not None
    assert "bogus-attack-name" in out["error"]


def test_run_openai_cell_dispatches_through_run_trial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end shape test: patch the OpenAI client + AgentDojo
    pipeline so run_openai_cell exercises every path (build_pipeline,
    benign trial loop, injection trial loop, metric aggregation)
    without external API calls.

    The test asserts the metric dict has the right shape and that the
    pipeline.query mock was invoked at least once per benign trial."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-test-key-not-real")

    # Mock the agentdojo pipeline.query to return a synthetic
    # (assistant_text, ...) tuple so run_trial computes utility_pass
    # against the first user task without invoking a real LLM.
    fake_pipeline_query_calls: list[tuple] = []

    def _fake_query(prompt, runtime, env):
        fake_pipeline_query_calls.append((prompt, runtime, env))
        # Return tuple shape expected by run_trial:
        # (_, _, post_env, messages, _)
        messages = [{"role": "assistant", "content": "ok"}]
        return None, None, env, messages, None

    with patch("openai.OpenAI") as mock_openai_cls, \
         patch("benchmarks.agentdojo_live.run_haiku.AgentPipeline") as mock_pipeline_cls:
        mock_openai_cls.return_value = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.query = _fake_query
        mock_pipeline_cls.return_value = mock_pipeline

        from benchmarks.agentdojo_live.run_openai import run_openai_cell
        out = run_openai_cell(
            model="gpt-4o-mini",
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
    # At minimum the benign loop should have invoked the patched
    # pipeline once (max_pairs=1).
    assert len(fake_pipeline_query_calls) >= 1


def test_build_pipeline_constructs_openai_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """build_pipeline must wrap an ``OpenAILLM`` with the canonical
    model id, then delegate to ``build_pipeline_with_llm``. This pins
    the alias-resolution + delegation contract."""
    from benchmarks.agentdojo_live import run_openai as ro

    captured: dict = {}

    def _fake_openai_llm(*, client, model, temperature):
        captured["model"] = model
        captured["temperature"] = temperature
        return MagicMock(name="OpenAILLM")

    def _fake_build_with_llm(llm):
        captured["llm"] = llm
        return MagicMock(name="pipeline"), MagicMock(name="labeler"), MagicMock(name="guard")

    monkeypatch.setattr(ro, "OpenAILLM", _fake_openai_llm)
    monkeypatch.setattr(ro, "build_pipeline_with_llm", _fake_build_with_llm)

    fake_client = MagicMock()
    pipeline, labeler, guard = ro.build_pipeline(fake_client, "gpt-5")

    assert captured["model"] == "gpt-4o"  # alias resolved
    assert captured["temperature"] == 0.0
    assert captured["llm"] is not None
    assert pipeline is not None
