"""CLI runner for the AgentDojo APR evaluation.

Usage::

    python -m benchmarks.agentdojo              # markdown to stdout
    python -m benchmarks.agentdojo --json       # JSON to stdout
    python -m benchmarks.agentdojo -o out.md    # write markdown to file
"""

from __future__ import annotations

import argparse
import sys

from benchmarks.agentdojo import AGENTDOJO_AVAILABLE, AgentDojoHarness
from benchmarks.agentdojo.report import render_json, render_markdown


def main(argv: list[str] | None = None) -> int:
    """Run the harness and print the APR report."""
    parser = argparse.ArgumentParser(prog="python -m benchmarks.agentdojo")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of markdown.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Also write the report to this path.",
    )
    args = parser.parse_args(argv)

    if AGENTDOJO_AVAILABLE:
        print(
            "Note: agentdojo package detected. "
            "This run uses the built-in standalone task suite.",
            file=sys.stderr,
        )

    harness = AgentDojoHarness()
    report = harness.run()

    output = render_json(report) if args.json else render_markdown(report)
    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)

    return 0 if report.passes_threshold() else 1


if __name__ == "__main__":
    sys.exit(main())
