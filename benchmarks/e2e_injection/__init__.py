"""End-to-end injection resistance benchmark.

Simulates a poisoned environment with injected tool descriptions, web content
with injections, compromised RAG documents, MCP baseline drift, and Unicode
steganography, then measures whether Tessera detects and blocks each attack.
"""

from __future__ import annotations

from benchmarks.e2e_injection.runner import (
    E2EReport,
    E2ERunner,
    ScenarioResult,
    VectorBreakdown,
)
from benchmarks.e2e_injection.scenarios import InjectionScenario, SCENARIOS

__all__ = [
    "E2EReport",
    "E2ERunner",
    "InjectionScenario",
    "SCENARIOS",
    "ScenarioResult",
    "VectorBreakdown",
]
