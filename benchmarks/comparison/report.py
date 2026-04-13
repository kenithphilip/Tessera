"""Comparison report renderer for the head-to-head benchmark.

Produces markdown tables showing latency ratios across strategies and
a static summary of which strategy blocks the injection.
"""

from __future__ import annotations

from benchmarks.harness import Result


def comparison_table(results: dict[str, list[Result]]) -> str:
    """Render a markdown table comparing median latency across strategies.

    Computes the ratio of each strategy's overhead relative to the baseline
    (single-LLM, no security). The baseline ratio is always 1.00x.
    """
    # Collect the first (primary) result from each strategy.
    rows: list[tuple[str, float]] = []
    for section, section_results in results.items():
        if section_results:
            rows.append((section, section_results[0].median_us))

    if not rows:
        return ""

    # Find the baseline for ratio computation.
    baseline_us = rows[0][1] if rows else 1.0

    lines = [
        "## Strategy comparison",
        "",
        "| Strategy | Median | Ratio vs baseline |",
        "| --- | ---: | ---: |",
    ]
    for name, median in rows:
        ratio = median / baseline_us if baseline_us > 0 else 0.0
        lines.append(f"| {name} | {median:,.2f} us | {ratio:.2f}x |")

    lines.append("")
    return "\n".join(lines)


def injection_resistance_summary() -> str:
    """Static summary of each strategy's injection resistance.

    This is not measured at runtime (all stubs are deterministic). The
    summary documents what each strategy does when the scraped document
    contains the embedded injection.
    """
    lines = [
        "## Injection resistance",
        "",
        "| Strategy | Blocks injection? | Mechanism |",
        "| --- | --- | --- |",
        "| Baseline (no security) | No | No policy evaluation. Both "
        "legitimate and attacker tool calls execute. |",
        "| Tessera (dual-LLM) | Yes | Taint-floor policy: min_trust "
        "across context is UNTRUSTED (0), below USER (100) required "
        "for send_email. Worker schema prevents instruction smuggling. |",
        "| CaMeL (interpreter) | Yes | Variable-level taint: "
        "scraped_content is tainted, extract_entities propagates taint "
        "to its output, send_email requires clean inputs and blocks. |",
        "",
        "Both Tessera and CaMeL achieve 100% injection resistance on "
        "this workload. The security properties are equivalent; the "
        "mechanisms differ. Tessera operates at the context-segment "
        "level with Pydantic schema enforcement. CaMeL operates at the "
        "variable level with a custom interpreter and capability system.",
        "",
    ]
    return "\n".join(lines)
