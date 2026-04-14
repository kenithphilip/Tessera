"""Render APRReport as markdown or JSON.

The markdown output includes a comparison table against published baselines
from the PromptGuard 2 and CaMeL papers so the reader can assess Tessera's
position without needing to retrieve those papers.
"""

from __future__ import annotations

import json

from benchmarks.agentdojo.tasks import APRReport

_COMPARISON_HEADER = """\
## Comparison with published baselines

| System | APR | Utility |
| --- | ---: | ---: |
"""

_COMPARISON_ROWS = [
    ("PromptGuard 2 (reported)", "81.2%", "~97%"),
    ("CaMeL (reported)", "~100%", "~97%"),
    ("Baseline (no defense)", "0%", "100%"),
]


def render_markdown(report: APRReport) -> str:
    """Return the full APR report as a markdown string."""
    lines: list[str] = ["# Tessera AgentDojo APR Evaluation\n"]

    lines.append(f"**Overall APR:** {report.overall_apr:.1%}")
    lines.append(f"**Overall Utility:** {report.overall_utility:.1%}")
    threshold_status = "PASS" if report.passes_threshold() else "FAIL"
    lines.append(
        f"**Threshold (APR>=80%, utility reduction<=3%):** {threshold_status}\n"
    )

    lines.append("## Per-suite results\n")
    lines.append("| Suite | APR | Utility | Injection tasks | Benign tasks | Prevented |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for suite_apr in report.suite_results.values():
        lines.append(
            f"| {suite_apr.suite} "
            f"| {suite_apr.apr:.1%} "
            f"| {suite_apr.utility:.1%} "
            f"| {suite_apr.total_injection} "
            f"| {suite_apr.total_benign} "
            f"| {suite_apr.prevented} |"
        )
    lines.append(
        f"| **Total** "
        f"| **{report.overall_apr:.1%}** "
        f"| **{report.overall_utility:.1%}** "
        f"| **{report.total_injection}** "
        f"| **{report.total_benign}** "
        f"| **{report.injection_prevented}** |"
    )
    lines.append("")

    lines.append(_COMPARISON_HEADER.rstrip())
    lines.append(
        f"| Tessera (this run) "
        f"| {report.overall_apr:.1%} "
        f"| {report.overall_utility:.1%} |"
    )
    for name, apr, utility in _COMPARISON_ROWS:
        lines.append(f"| {name} | {apr} | {utility} |")
    lines.append("")

    lines.append("## Task totals\n")
    lines.append(f"- Total tasks: {report.total_tasks}")
    lines.append(f"- Injection tasks: {report.total_injection}")
    lines.append(f"- Injections prevented: {report.injection_prevented}")
    lines.append(f"- Benign tasks: {report.total_benign}")
    lines.append(f"- Utility preserved: {report.utility_preserved}")
    lines.append("")

    return "\n".join(lines)


def render_json(report: APRReport) -> str:
    """Return the APR report as a JSON string."""
    data: dict = {
        "overall_apr": report.overall_apr,
        "overall_utility": report.overall_utility,
        "passes_threshold": report.passes_threshold(),
        "total_tasks": report.total_tasks,
        "total_benign": report.total_benign,
        "total_injection": report.total_injection,
        "injection_prevented": report.injection_prevented,
        "utility_preserved": report.utility_preserved,
        "suites": {
            name: {
                "suite": s.suite,
                "apr": s.apr,
                "utility": s.utility,
                "total_injection": s.total_injection,
                "total_benign": s.total_benign,
                "prevented": s.prevented,
            }
            for name, s in report.suite_results.items()
        },
        "comparison_baselines": [
            {"system": name, "apr": apr, "utility": utility}
            for name, apr, utility in _COMPARISON_ROWS
        ],
    }
    return json.dumps(data, indent=2)
