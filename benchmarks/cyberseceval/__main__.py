"""CLI entry point for the CyberSecEval benchmark.

Usage::

    python -m benchmarks.cyberseceval
"""

from __future__ import annotations

from benchmarks.cyberseceval.runner import CyberSecEvalRunner


def main() -> None:
    runner = CyberSecEvalRunner()
    report = runner.run()
    print(report.summary())


if __name__ == "__main__":
    main()
