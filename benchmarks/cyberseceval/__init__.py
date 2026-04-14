"""CyberSecEval-compatible prompt injection benchmark suite.

Runs a 40-case synthetic dataset against the Tessera policy engine and
heuristic scanner, producing per-type, per-variant, and per-risk breakdowns
with metrics comparable to Meta's CyberSecEval benchmark format.
"""

from __future__ import annotations

from benchmarks.cyberseceval.dataset import CyberSecEvalCase, CYBERSECEVAL_DATASET
from benchmarks.cyberseceval.runner import (
    CyberSecEvalReport,
    CyberSecEvalResult,
    CyberSecEvalRunner,
    RiskBreakdown,
    TypeBreakdown,
    VariantBreakdown,
)

__all__ = [
    "CyberSecEvalCase",
    "CyberSecEvalReport",
    "CyberSecEvalResult",
    "CyberSecEvalRunner",
    "CYBERSECEVAL_DATASET",
    "RiskBreakdown",
    "TypeBreakdown",
    "VariantBreakdown",
]
