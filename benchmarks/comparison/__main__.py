"""Run the head-to-head comparison benchmark and emit a markdown report.

Usage::

    python -m benchmarks.comparison              # print to stdout
    python -m benchmarks.comparison -o out.md    # also write to file
    python -m benchmarks.comparison --rounds 10  # more stable numbers
"""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone

from benchmarks.comparison import (
    strategy_baseline,
    strategy_camel,
    strategy_tessera,
)
from benchmarks.comparison.report import comparison_table, injection_resistance_summary
from benchmarks.harness import render_markdown, run_all

STRATEGIES = [
    ("Baseline (no security)", strategy_baseline),
    ("Tessera (dual-LLM)", strategy_tessera),
    ("CaMeL (interpreter)", strategy_camel),
]


def _environment_header() -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"- **Python:** {platform.python_version()}\n"
        f"- **Platform:** {platform.platform()}\n"
        f"- **Processor:** {platform.processor() or 'unknown'}\n"
        f"- **Run at:** {now}\n"
    )


def _preamble() -> str:
    return (
        "# Head-to-head comparison: Baseline vs Tessera vs CaMeL\n\n"
        "Measures the per-request security-layer overhead of three strategies "
        "processing the same financial analyst workload. All strategies use "
        "deterministic LLM stubs, isolating the security overhead from model "
        "latency.\n\n"
        "## Workload\n\n"
        "A financial analyst assistant extracts Q3 earnings data from a "
        "scraped document containing an embedded prompt injection, then "
        "emails a summary. The injection tries to redirect email to an "
        "attacker address.\n\n"
        "## Environment\n\n"
        + _environment_header()
        + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.comparison")
    parser.add_argument(
        "-o",
        "--output",
        help="Also write the markdown report to this path.",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=7,
        help="Number of timing rounds per benchmark (default: 7).",
    )
    args = parser.parse_args(argv)

    out: list[str] = [_preamble()]
    all_results: dict[str, list] = {}

    for title, module in STRATEGIES:
        results = run_all(module.BENCHMARKS, rounds=args.rounds)
        all_results[title] = results
        out.append(render_markdown(title, results))

    out.append(comparison_table(all_results))
    out.append(injection_resistance_summary())

    report = "\n".join(out)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
