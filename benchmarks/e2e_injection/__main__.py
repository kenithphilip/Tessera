"""CLI entry point for the E2E injection resistance benchmark.

Usage::

    python -m benchmarks.e2e_injection
"""

from __future__ import annotations

from benchmarks.e2e_injection.runner import E2ERunner


def main() -> None:
    runner = E2ERunner()
    report = runner.run()
    print(report.summary())


if __name__ == "__main__":
    main()
