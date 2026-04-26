"""Tests for the AgentDojo live-submission driver."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.agentdojo_live import submit
from benchmarks.agentdojo_live.defense_adapter import (
    MeshDefensePipeline,
    defense_pipeline_factory,
)


# --- Matrix generation ------------------------------------------------------


def test_generate_cells_yields_full_cartesian() -> None:
    cells = list(
        submit.generate_cells(
            ["m1", "m2"], ["s1"], ["a1", "a2"], [0, 1, 2]
        )
    )
    # 2 models * 1 suite * 2 attacks * 3 seeds = 12 cells.
    assert len(cells) == 12


def test_generate_cells_carries_defense_label() -> None:
    cells = list(
        submit.generate_cells(["m1"], ["s1"], ["a1"], [0], defense="custom")
    )
    assert all(c.defense == "custom" for c in cells)


def test_default_matrix_size_matches_brief() -> None:
    cells = list(
        submit.generate_cells(
            submit.DEFAULT_MODELS,
            submit.DEFAULT_SUITES,
            submit.DEFAULT_ATTACKS,
            submit.DEFAULT_SEEDS,
        )
    )
    # 5 models x 4 suites x 2 attacks x 3 seeds = 120, matching the brief.
    assert len(cells) == 120


# --- Cell execution (dry-run path) ------------------------------------------


def test_run_cell_dry_run_returns_placeholders() -> None:
    cell = submit.CellSpec(
        model="m", suite="travel", attack="ii", seed=0, defense="tessera"
    )
    result = submit.run_cell(cell, dry_run=True)
    assert result.error is None
    assert result.attack_prevention_rate == 1.0
    assert result.utility_attempt == 0.5
    assert result.raw_runs == [{"dry_run": True}]


def test_run_cell_unknown_model_is_recorded_as_error() -> None:
    """A model the dispatcher can't route to any provider records a
    clear 'no provider routing' error rather than crashing."""
    cell = submit.CellSpec(
        model="totally-unknown-7b", suite="travel", attack="important_instructions",
        seed=0, defense="tessera",
    )
    result = submit.run_cell(cell, dry_run=False)
    assert result.error is not None
    assert "totally-unknown-7b" in result.error
    assert "no provider routing" in result.error


# --- Aggregation ------------------------------------------------------------


def test_summarize_groups_by_suite() -> None:
    cells = list(
        submit.generate_cells(["m"], ["a", "b"], ["x"], [0])
    )
    results = [submit.run_cell(c, dry_run=True) for c in cells]
    summary = submit.summarize(results)
    assert set(summary["suites"].keys()) == {"a", "b"}
    assert summary["total_cells"] == 2
    assert summary["completed_cells"] == 2
    assert summary["errored_cells"] == 0


def test_summarize_handles_all_errored_cells() -> None:
    cell = submit.CellSpec(
        model="m", suite="travel", attack="ii", seed=0, defense="bogus"
    )
    result = submit.run_cell(cell, dry_run=False)
    summary = submit.summarize([result])
    assert summary["errored_cells"] == 1
    assert summary["completed_cells"] == 0
    assert summary["suites"]["travel"]["completed"] == 0


# --- JSONL output -----------------------------------------------------------


def test_write_jsonl_round_trips(tmp_path: Path) -> None:
    cell = submit.CellSpec(
        model="m", suite="travel", attack="ii", seed=0, defense="tessera"
    )
    result = submit.run_cell(cell, dry_run=True)
    summary = submit.summarize([result])
    out = tmp_path / "out.jsonl"
    submit.write_jsonl(out, [result], summary)
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    parsed_cell = json.loads(lines[0])
    parsed_summary = json.loads(lines[1])
    assert parsed_cell["cell"]["suite"] == "travel"
    assert "_summary" in parsed_summary


# --- CLI main() -------------------------------------------------------------


def test_main_dry_run_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "matrix.jsonl"
    rc = submit.main([
        "--dry-run",
        "--models", "m1",
        "--suites", "travel",
        "--attacks", "important_instructions",
        "--seeds", "0",
        "--out", str(out),
    ])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "Matrix:" in captured
    # Output file written.
    assert out.exists()


def test_main_anthropic_model_without_api_key_returns_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An Anthropic model in the matrix without the key set bails out
    with rc=2. Non-Anthropic models bypass the check."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "no.jsonl"
    rc = submit.main([
        "--models", "claude-haiku-4-5",
        "--suites", "travel",
        "--attacks", "important_instructions",
        "--seeds", "0",
        "--out", str(out),
    ])
    assert rc == 2


def test_main_unrecognised_model_runs_without_any_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A matrix that uses only unrecognised model names (no provider
    routing) doesn't trigger any provider env-var preflight, so it
    proceeds and records per-cell unimplemented errors."""
    for k in (
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
        "GEMINI_API_KEY", "COHERE_API_KEY",
        "TESSERA_BENCH_OPENAI_COMPATIBLE_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    out = tmp_path / "noimpl.jsonl"
    rc = submit.main([
        "--models", "totally-unknown-model-xyz",
        "--suites", "travel",
        "--attacks", "important_instructions",
        "--seeds", "0",
        "--out", str(out),
    ])
    assert rc == 0
    summary_path = out.with_suffix(".summary.json")
    assert summary_path.exists()


def test_main_openai_model_without_openai_key_returns_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """gpt-* in the matrix without OPENAI_API_KEY is rejected by the
    provider-aware preflight."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = tmp_path / "no.jsonl"
    rc = submit.main([
        "--models", "gpt-4o",
        "--suites", "travel",
        "--attacks", "important_instructions",
        "--seeds", "0",
        "--out", str(out),
    ])
    assert rc == 2


# --- Defense adapter --------------------------------------------------------


def test_defense_factory_builds_pipeline() -> None:
    class _StubInner:
        def query(
            self, prompt, runtime, env, messages=None, extra_args=None
        ):
            return ("ok",)

    inner = _StubInner()
    p = defense_pipeline_factory(inner, trust_key=b"k" * 32)
    assert isinstance(p, MeshDefensePipeline)
    assert p.trust_key == b"k" * 32


def test_defense_factory_reads_env_when_no_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TESSERA_DEFENSE_TRUST_KEY", "abc123")

    class _StubInner:
        def query(
            self, prompt, runtime, env, messages=None, extra_args=None
        ):
            return ("ok",)

    p = defense_pipeline_factory(_StubInner())
    assert p.trust_key == b"abc123"


def test_defense_pipeline_query_delegates() -> None:
    class _StubInner:
        called = False

        def query(
            self, prompt, runtime, env, messages=None, extra_args=None
        ):
            _StubInner.called = True
            return (prompt, runtime, env)

    p = defense_pipeline_factory(_StubInner(), trust_key=b"k" * 32)
    out = p.query("hello", "rt", "env")
    assert out == ("hello", "rt", "env")
    assert _StubInner.called is True
