"""Injection variant taxonomy for CyberSecEval-compatible benchmarking.

Provides a 48-case labeled corpus covering all combinations of InjectionType,
InjectionVariant, and RiskCategory, plus a TaxonomyRunner that evaluates the
corpus against Tessera policy and the heuristic scanner.
"""

from __future__ import annotations

from benchmarks.injection_taxonomy.runner import TaxonomyReport, TaxonomyRunner
from benchmarks.injection_taxonomy.taxonomy import (
    InjectionCase,
    InjectionType,
    InjectionVariant,
    RiskCategory,
)

__all__ = [
    "InjectionCase",
    "InjectionType",
    "InjectionVariant",
    "RiskCategory",
    "TaxonomyReport",
    "TaxonomyRunner",
]
