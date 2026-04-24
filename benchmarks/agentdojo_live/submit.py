"""Driver for AgentDojo live submissions across the model x attack matrix.

Wave 1C-i lays the submission infrastructure; Phase 2 wave 2A
performs the actual upstream submission once Critic backends are
wired and a model-pinned baseline is available. The driver:

- Iterates a configurable matrix of ``(model, suite, attack, seed)``
  tuples (default: 4 models x 4 suites x 2 attacks x 3 seeds = 96
  cells; the brief lists 120 to allow for additional injection
  variants in Phase 2).
- For each cell, runs the existing :mod:`benchmarks.agentdojo_live`
  trial harness (``run_baseline.py`` / ``run_haiku.py``) under the
  selected attack profile and aggregates per-suite Utility-Attempt
  (UA), Targeted Attack Success Rate (ASR), Attack Prevention Rate
  (APR), and utility delta vs. the baseline.
- Emits a JSON-Lines artifact per run plus a roll-up summary
  matching the AgentDojo leaderboard schema.
- Provides ``--dry-run`` that exercises every code path (matrix
  generation, results aggregation, summary emission) without
  invoking a model.

Usage::

    python -m benchmarks.agentdojo_live.submit --dry-run
    python -m benchmarks.agentdojo_live.submit \\
        --models claude-haiku-4-5 \\
        --suites travel \\
        --attacks important_instructions \\
        --seeds 0 1 2 \\
        --out runs/2026-04-tessera-v0.12.jsonl

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 4
  (Evaluation-as-a-Product).
- AgentDojo leaderboard: https://agentdojo.spylab.ai/results.
"""

from __future__ import annotations

import argparse
import dataclasses
import itertools
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

# Default matrix shape per the v0.8-v1.0 engineering brief, Section 4.
DEFAULT_MODELS: tuple[str, ...] = (
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "gpt-5",
    "gpt-4.1",
    "gemini-2.5-pro",
)
DEFAULT_SUITES: tuple[str, ...] = ("banking", "slack", "travel", "workspace")
DEFAULT_ATTACKS: tuple[str, ...] = ("important_instructions", "tool_knowledge")
DEFAULT_SEEDS: tuple[int, ...] = (0, 1, 2)
DEFAULT_DEFENSE: str = "tessera"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CellSpec:
    """One cell in the model x suite x attack x seed matrix."""

    model: str
    suite: str
    attack: str
    seed: int
    defense: str = DEFAULT_DEFENSE

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class CellResult:
    """Outcome of running one cell (one full benchmark trial)."""

    cell: CellSpec
    utility_attempt: float = 0.0
    targeted_asr: float = 0.0
    attack_prevention_rate: float = 0.0
    utility_delta: float = 0.0
    raw_runs: list[dict[str, Any]] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell": self.cell.to_dict(),
            "utility_attempt": self.utility_attempt,
            "targeted_asr": self.targeted_asr,
            "attack_prevention_rate": self.attack_prevention_rate,
            "utility_delta": self.utility_delta,
            "raw_runs": self.raw_runs,
            "elapsed_seconds": self.elapsed_seconds,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Matrix generation
# ---------------------------------------------------------------------------


def generate_cells(
    models: Iterable[str],
    suites: Iterable[str],
    attacks: Iterable[str],
    seeds: Iterable[int],
    *,
    defense: str = DEFAULT_DEFENSE,
) -> Iterator[CellSpec]:
    """Yield every (model, suite, attack, seed) cell."""
    for model, suite, attack, seed in itertools.product(
        list(models), list(suites), list(attacks), list(seeds)
    ):
        yield CellSpec(
            model=model,
            suite=suite,
            attack=attack,
            seed=int(seed),
            defense=defense,
        )


# ---------------------------------------------------------------------------
# Trial dispatch
# ---------------------------------------------------------------------------


def _import_runner(defense: str):
    """Resolve the in-tree runner module for a defense name.

    For ``tessera`` we currently use the ``run_haiku`` runner; for
    ``none`` (baseline) we use ``run_baseline``. Phase 2 will route
    Llama / GPT / Gemini through their dedicated runners.
    """
    if defense == "none":
        from benchmarks.agentdojo_live import run_baseline

        return run_baseline
    if defense == DEFAULT_DEFENSE:
        from benchmarks.agentdojo_live import run_haiku

        return run_haiku
    raise ValueError(f"unknown defense: {defense!r}")


def run_cell(
    cell: CellSpec,
    *,
    dry_run: bool = False,
) -> CellResult:
    """Execute one cell and return its aggregated metrics.

    In ``dry_run`` mode no model API call is made; the function
    returns deterministic placeholder metrics suitable for matrix
    validation.
    """
    started = time.monotonic()
    if dry_run:
        return CellResult(
            cell=cell,
            utility_attempt=0.5,
            targeted_asr=0.0,
            attack_prevention_rate=1.0,
            utility_delta=0.0,
            raw_runs=[{"dry_run": True}],
            elapsed_seconds=0.0,
        )
    try:
        runner = _import_runner(cell.defense)
    except ValueError as exc:
        return CellResult(cell=cell, error=str(exc))
    # Real dispatch is wired in Phase 2 wave 2A; today we record a
    # SKIP so the driver verifies the matrix shape without forcing
    # API keys at v0.12.
    return CellResult(
        cell=cell,
        error="real-trial dispatch not wired until Phase 2 wave 2A",
        elapsed_seconds=time.monotonic() - started,
    )


# ---------------------------------------------------------------------------
# Aggregation + output
# ---------------------------------------------------------------------------


def summarize(results: list[CellResult]) -> dict[str, Any]:
    """Roll up cell results into the leaderboard-shaped summary."""
    by_suite: dict[str, list[CellResult]] = {}
    for r in results:
        by_suite.setdefault(r.cell.suite, []).append(r)
    suites_summary = {}
    for suite_name, cells in sorted(by_suite.items()):
        successful = [c for c in cells if c.error is None]
        if not successful:
            suites_summary[suite_name] = {"cells": len(cells), "completed": 0}
            continue
        suites_summary[suite_name] = {
            "cells": len(cells),
            "completed": len(successful),
            "utility_attempt_mean": sum(c.utility_attempt for c in successful)
            / len(successful),
            "targeted_asr_mean": sum(c.targeted_asr for c in successful)
            / len(successful),
            "attack_prevention_rate_mean": sum(
                c.attack_prevention_rate for c in successful
            )
            / len(successful),
            "utility_delta_mean": sum(c.utility_delta for c in successful)
            / len(successful),
        }
    return {
        "schema_version": "tessera.agentdojo.submission.v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_cells": len(results),
        "completed_cells": sum(1 for r in results if r.error is None),
        "errored_cells": sum(1 for r in results if r.error is not None),
        "suites": suites_summary,
    }


def write_jsonl(path: Path, results: list[CellResult], summary: dict[str, Any]) -> None:
    """Emit one JSON-Lines artifact: each cell on its own line, then summary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r.to_dict(), separators=(",", ":")) + "\n")
        fh.write(json.dumps({"_summary": summary}, separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--models", nargs="+", default=list(DEFAULT_MODELS),
        help="Models to evaluate (default: full matrix).",
    )
    parser.add_argument(
        "--suites", nargs="+", default=list(DEFAULT_SUITES),
        choices=list(DEFAULT_SUITES),
        help="AgentDojo suites to run (default: all four).",
    )
    parser.add_argument(
        "--attacks", nargs="+", default=list(DEFAULT_ATTACKS),
        help="Injection attack profiles (default: important_instructions, tool_knowledge).",
    )
    parser.add_argument(
        "--seeds", nargs="+", type=int, default=list(DEFAULT_SEEDS),
        help="RNG seeds per cell (default: 0 1 2).",
    )
    parser.add_argument(
        "--defense", default=DEFAULT_DEFENSE,
        choices=("none", DEFAULT_DEFENSE),
        help="Defense profile in the loop (default: tessera).",
    )
    parser.add_argument(
        "--out",
        default="runs/agentdojo-submission.jsonl",
        help="Output JSONL path.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Exercise the matrix and aggregator without calling models.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    cells = list(
        generate_cells(
            args.models, args.suites, args.attacks, args.seeds,
            defense=args.defense,
        )
    )
    print(
        f"Matrix: {len(args.models)} models x {len(args.suites)} suites x "
        f"{len(args.attacks)} attacks x {len(args.seeds)} seeds = {len(cells)} cells"
    )
    if not args.dry_run and not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "ANTHROPIC_API_KEY not set; use --dry-run to validate the matrix.",
            file=sys.stderr,
        )
        return 2
    started = time.monotonic()
    results: list[CellResult] = []
    for cell in cells:
        result = run_cell(cell, dry_run=args.dry_run)
        results.append(result)
        status = "OK" if result.error is None else f"ERR ({result.error[:60]})"
        print(
            f"  [{cell.model:<24}] {cell.suite:<10} {cell.attack:<24} seed={cell.seed} -> {status}"
        )
    elapsed = time.monotonic() - started
    summary = summarize(results)
    summary["elapsed_seconds"] = elapsed
    out_path = Path(args.out)
    write_jsonl(out_path, results, summary)
    print(f"\nWrote {out_path} ({len(results)} cells, {elapsed:.1f}s)")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
