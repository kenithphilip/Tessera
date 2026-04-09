"""Minimal timeit-based harness for the Tessera benchmark suite.

Each benchmark module exposes ``BENCHMARKS``, a list of ``(name, callable)``
tuples. The harness runs each one through ``timeit.Timer.autorange`` to pick
an iteration count, then repeats the timing several times to report stable
per-call statistics.

Output is a markdown table so the results can be pasted into a PR, a doc,
or an issue without post-processing.
"""

from __future__ import annotations

import statistics
import timeit
from dataclasses import dataclass
from typing import Callable, Iterable


@dataclass(frozen=True)
class Result:
    name: str
    median_us: float
    min_us: float
    stdev_us: float
    ops_per_sec: int
    iterations: int
    rounds: int


def _warmup(fn: Callable[[], None], rounds: int = 200) -> None:
    for _ in range(rounds):
        fn()


def run_one(name: str, fn: Callable[[], None], rounds: int = 7) -> Result:
    """Time a single benchmark callable.

    Args:
        name: Label for the benchmark row.
        fn: Zero-argument callable to time. Setup should be closed over.
        rounds: How many timing rounds to perform (median is reported).

    Returns:
        A Result with per-call latency statistics in microseconds.
    """
    _warmup(fn)
    timer = timeit.Timer(fn)
    # autorange picks the smallest n such that total time >= 0.2s. This
    # keeps sub-microsecond ops out of the timer-resolution noise floor.
    iterations, _ = timer.autorange()
    raw = timer.repeat(repeat=rounds, number=iterations)
    per_call_us = [(t / iterations) * 1_000_000 for t in raw]
    return Result(
        name=name,
        median_us=statistics.median(per_call_us),
        min_us=min(per_call_us),
        stdev_us=statistics.pstdev(per_call_us) if len(per_call_us) > 1 else 0.0,
        ops_per_sec=int(iterations / min(raw)),
        iterations=iterations,
        rounds=rounds,
    )


def run_all(
    benchmarks: Iterable[tuple[str, Callable[[], None]]],
    rounds: int = 7,
) -> list[Result]:
    return [run_one(name, fn, rounds=rounds) for name, fn in benchmarks]


def render_markdown(section: str, results: list[Result]) -> str:
    """Render a section of results as a GitHub-flavored markdown table."""
    lines = [
        f"### {section}",
        "",
        "| Operation | Median | Min | Stdev | Ops/sec |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for r in results:
        lines.append(
            f"| {r.name} "
            f"| {r.median_us:,.2f} us "
            f"| {r.min_us:,.2f} us "
            f"| {r.stdev_us:,.2f} us "
            f"| {r.ops_per_sec:,} |"
        )
    lines.append("")
    return "\n".join(lines)


def summary_table(all_sections: dict[str, list[Result]]) -> str:
    """Produce a compact summary of the median of every measured operation."""
    lines = [
        "### Summary (median per-call latency)",
        "",
        "| Section | Operation | Median |",
        "| --- | --- | ---: |",
    ]
    for section, results in all_sections.items():
        for r in results:
            lines.append(f"| {section} | {r.name} | {r.median_us:,.2f} us |")
    lines.append("")
    return "\n".join(lines)
