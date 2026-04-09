"""Run the full Tessera benchmark suite and emit a markdown report.

Usage::

    python -m benchmarks              # print to stdout
    python -m benchmarks -o out.md    # also write to file
    python -m benchmarks --rounds 10  # more stable numbers, slower run
"""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone

from benchmarks import bench_context, bench_e2e, bench_labels, bench_policy, bench_quarantine
from benchmarks.harness import render_markdown, run_all, summary_table

SECTIONS = [
    ("Labels (HMAC sign/verify)", bench_labels),
    ("Context (segments, min_trust, render)", bench_context),
    ("Policy (allow and deny)", bench_policy),
    ("Quarantine (Pydantic validation)", bench_quarantine),
    ("End-to-end request path", bench_e2e),
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
        "# Tessera benchmark results\n\n"
        "Microbenchmarks for the Tessera primitives. All measurements are "
        "per-call wall-clock time under `timeit`, warmed up, with the "
        "minimum of seven rounds (unless `--rounds` says otherwise) used "
        "as the headline. See `benchmarks/README.md` for methodology.\n\n"
        "## Environment\n\n"
        + _environment_header()
        + "\n"
    )


def _framing(all_sections: dict) -> str:  # type: ignore[no-untyped-def]
    # Extract the end-to-end median so we can frame it against an LLM call.
    e2e_results = all_sections.get("End-to-end request path", [])
    if not e2e_results:
        return ""
    allow = next((r for r in e2e_results if "allow" in r.name), None)
    deny = next((r for r in e2e_results if "deny" in r.name), None)

    def _fraction_of(call_ms: float, overhead_us: float) -> str:
        pct = (overhead_us / (call_ms * 1000)) * 100
        return f"{pct:.4f}%"

    lines = [
        "## Framing against an LLM round-trip",
        "",
        "CaMeL (Debenedetti et al, 2025) reports a 6.6x latency cost for "
        "its custom interpreter approach. Tessera's schema-enforced "
        "dual-LLM pattern does no dataflow tracking: validation is a "
        "Pydantic call on a structured dict, and policy evaluation is a "
        "min over the context segments.",
        "",
        "The end-to-end row above is the full Tessera per-request "
        "overhead: sign three segments, verify three segments, evaluate "
        "one tool call. As a fraction of a typical LLM round-trip:",
        "",
    ]
    if allow is not None:
        lines.append(
            f"- Allow path ({allow.median_us:.2f} us per request) vs "
            f"200 ms LLM call: {_fraction_of(200, allow.median_us)} overhead."
        )
        lines.append(
            f"- Allow path ({allow.median_us:.2f} us per request) vs "
            f"1000 ms LLM call: {_fraction_of(1000, allow.median_us)} overhead."
        )
    if deny is not None:
        lines.append(
            f"- Deny path ({deny.median_us:.2f} us per request, emits "
            f"SecurityEvent) vs 200 ms LLM call: "
            f"{_fraction_of(200, deny.median_us)} overhead."
        )
    lines.append("")
    lines.append(
        "We do not claim this is a head-to-head comparison with CaMeL: "
        "we did not run CaMeL, and the two systems are doing different "
        "work. The point of this report is to pin Tessera's absolute "
        "overhead so readers can compute the ratio against whatever LLM "
        "latency they care about."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks")
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
    all_sections: dict[str, list] = {}

    for title, module in SECTIONS:
        results = run_all(module.BENCHMARKS, rounds=args.rounds)
        all_sections[title] = results
        out.append(render_markdown(title, results))

    out.append(summary_table(all_sections))
    out.append(_framing(all_sections))

    report = "\n".join(out)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
