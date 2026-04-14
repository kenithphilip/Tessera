"""Run the AgentDojo replay evaluator and print results.

Usage: python -m benchmarks.agentdojo_replay [--suite banking] [--attack direct]
"""

from __future__ import annotations

import argparse

from benchmarks.agentdojo_replay.evaluator import ReplayEvaluator


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentDojo replay evaluator")
    parser.add_argument("--suite", nargs="*", default=None, help="Suite names (default: all)")
    parser.add_argument("--attack", nargs="*", default=None, help="Attack names (default: all)")
    parser.add_argument("--threshold", type=float, default=0.75, help="Injection threshold")
    args = parser.parse_args()

    evaluator = ReplayEvaluator(
        suites=args.suite,
        attacks=args.attack,
        injection_threshold=args.threshold,
    )
    report = evaluator.run()
    print(report.summary())


if __name__ == "__main__":
    main()
