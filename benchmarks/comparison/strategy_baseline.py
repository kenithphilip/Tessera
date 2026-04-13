"""Baseline strategy: single LLM, no security controls.

Concatenates all content into a flat prompt, calls the stub LLM, and
returns every tool call without policy evaluation. This is the "no
defense" baseline that every production system should be embarrassed to
ship but many still do.
"""

from __future__ import annotations

from benchmarks.comparison.stubs import stub_single_llm
from benchmarks.comparison.workload import (
    SCRAPED_DOCUMENT,
    SYSTEM_PROMPT,
    USER_INSTRUCTION,
)


def _baseline_request() -> None:
    """Full baseline request path: concatenate and call."""
    # Build a flat prompt (no signing, no labeling, no policy).
    _prompt = f"{SYSTEM_PROMPT}\n\n{USER_INSTRUCTION}\n\n{SCRAPED_DOCUMENT}"

    # "Call the LLM" (deterministic stub).
    tool_calls = stub_single_llm()

    # Execute every tool call without checking anything.
    for call in tool_calls:
        _tool = call["tool"]
        _args = call["args"]
        # In a real system this dispatches to the tool. Here we just
        # touch the data to keep the benchmark honest about dict access.


BENCHMARKS = [
    ("Baseline: single LLM, no policy", _baseline_request),
]
