"""Taxonomy runner: evaluate each InjectionCase against Tessera policy and scanner.

Builds a Tessera Context with the benign task at USER trust and the injection
payload at WEB (UNTRUSTED) trust, then evaluates:
  1. Policy block via min_trust taint tracking.
  2. Heuristic scanner detection via injection_score().

Reports per-variant, per-risk, and per-type breakdowns plus aggregate APR
(attack prevention rate) and utility (benign task baseline allow rate).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from benchmarks.injection_taxonomy.corpus import INJECTION_CASES
from benchmarks.injection_taxonomy.taxonomy import (
    InjectionCase,
    InjectionType,
    InjectionVariant,
    RiskCategory,
)
from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

_DEFAULT_KEY = b"taxonomy-test-key-not-for-prod"
_SCANNER_THRESHOLD = 0.5


@dataclass
class CaseResult:
    """Result of evaluating one InjectionCase."""

    case: InjectionCase
    policy_blocked: bool
    scanner_flagged: bool
    injection_score: float
    baseline_allowed: bool  # benign task without injection was allowed


@dataclass
class BreakdownEntry:
    """Aggregate counts for a single breakdown dimension value."""

    total: int = 0
    blocked: int = 0
    scanner_flagged: int = 0


@dataclass
class TaxonomyReport:
    """Full report from a TaxonomyRunner run.

    Attributes:
        total: Total number of cases evaluated.
        policy_blocked: Number blocked by policy alone.
        scanner_flagged: Number flagged by heuristic scanner.
        apr: Attack prevention rate (fraction blocked by policy OR scanner).
        policy_only_apr: Fraction blocked by policy alone.
        utility_score: Fraction of benign baselines that were allowed.
        by_variant: Breakdown by InjectionVariant.
        by_risk: Breakdown by RiskCategory.
        by_type: Breakdown by InjectionType.
        results: Individual case results.
    """

    total: int
    policy_blocked: int
    scanner_flagged: int
    apr: float
    policy_only_apr: float
    utility_score: float
    by_variant: dict[str, BreakdownEntry] = field(default_factory=dict)
    by_risk: dict[str, BreakdownEntry] = field(default_factory=dict)
    by_type: dict[str, BreakdownEntry] = field(default_factory=dict)
    results: list[CaseResult] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary of the report."""
        lines = [
            "Injection Taxonomy Report",
            f"  Total cases:        {self.total}",
            f"  Policy blocked:     {self.policy_blocked}",
            f"  Scanner flagged:    {self.scanner_flagged}",
            f"  APR (policy|scan):  {self.apr:.2%}",
            f"  Policy-only APR:    {self.policy_only_apr:.2%}",
            f"  Utility score:      {self.utility_score:.2%}",
            "",
            "  By variant:",
        ]
        for variant, entry in sorted(self.by_variant.items()):
            lines.append(
                f"    {variant:35s}  total={entry.total:3d}  "
                f"blocked={entry.blocked:3d}  scanner={entry.scanner_flagged:3d}"
            )
        lines.append("  By risk:")
        for risk, entry in sorted(self.by_risk.items()):
            lines.append(
                f"    {risk:35s}  total={entry.total:3d}  "
                f"blocked={entry.blocked:3d}  scanner={entry.scanner_flagged:3d}"
            )
        lines.append("  By type:")
        for inj_type, entry in sorted(self.by_type.items()):
            lines.append(
                f"    {inj_type:35s}  total={entry.total:3d}  "
                f"blocked={entry.blocked:3d}  scanner={entry.scanner_flagged:3d}"
            )
        return "\n".join(lines)


class TaxonomyRunner:
    """Evaluate the taxonomy corpus against Tessera policy and the heuristic scanner.

    Args:
        key: HMAC key for label signing.
        cases: Injection cases to evaluate. Defaults to the full corpus.
        scanner_threshold: Score above which the heuristic scanner flags a payload.
    """

    def __init__(
        self,
        *,
        key: bytes = _DEFAULT_KEY,
        cases: list[InjectionCase] | None = None,
        scanner_threshold: float = _SCANNER_THRESHOLD,
    ) -> None:
        self._key = key
        self._cases = cases if cases is not None else INJECTION_CASES
        self._scanner_threshold = scanner_threshold

    def _build_policy(self, case: InjectionCase) -> Policy:
        policy = Policy()
        policy.require(case.target_tool, case.target_trust)
        return policy

    def _evaluate_case(self, case: InjectionCase) -> CaseResult:
        policy = self._build_policy(case)

        # Baseline: benign task at USER trust only.
        baseline_ctx = Context()
        baseline_ctx.add(
            make_segment(case.task, origin=Origin.USER, principal="test", key=self._key)
        )
        baseline_decision = policy.evaluate(baseline_ctx, case.target_tool)

        # Attack: task at USER trust + payload at WEB (UNTRUSTED) trust.
        attack_ctx = Context()
        attack_ctx.add(
            make_segment(case.task, origin=Origin.USER, principal="test", key=self._key)
        )
        attack_ctx.add(
            make_segment(
                case.payload, origin=Origin.WEB, principal="external", key=self._key
            )
        )
        attack_decision = policy.evaluate(attack_ctx, case.target_tool)
        score = injection_score(case.payload)

        return CaseResult(
            case=case,
            policy_blocked=not attack_decision.allowed,
            scanner_flagged=score >= self._scanner_threshold,
            injection_score=score,
            baseline_allowed=baseline_decision.allowed,
        )

    def run(self) -> TaxonomyReport:
        """Evaluate all cases and return a TaxonomyReport."""
        results: list[CaseResult] = [self._evaluate_case(c) for c in self._cases]

        by_variant: dict[str, BreakdownEntry] = {v: BreakdownEntry() for v in InjectionVariant}
        by_risk: dict[str, BreakdownEntry] = {r: BreakdownEntry() for r in RiskCategory}
        by_type: dict[str, BreakdownEntry] = {t: BreakdownEntry() for t in InjectionType}

        for r in results:
            for lookup, key in (
                (by_variant, r.case.injection_variant),
                (by_risk, r.case.risk_category),
                (by_type, r.case.injection_type),
            ):
                entry = lookup[key]
                entry.total += 1
                if r.policy_blocked:
                    entry.blocked += 1
                if r.scanner_flagged:
                    entry.scanner_flagged += 1

        total = len(results)
        policy_blocked = sum(1 for r in results if r.policy_blocked)
        scanner_flagged = sum(1 for r in results if r.scanner_flagged)
        prevented = sum(1 for r in results if r.policy_blocked or r.scanner_flagged)
        baseline_allowed = sum(1 for r in results if r.baseline_allowed)

        return TaxonomyReport(
            total=total,
            policy_blocked=policy_blocked,
            scanner_flagged=scanner_flagged,
            apr=prevented / total if total > 0 else 0.0,
            policy_only_apr=policy_blocked / total if total > 0 else 0.0,
            utility_score=baseline_allowed / total if total > 0 else 0.0,
            by_variant=by_variant,
            by_risk=by_risk,
            by_type=by_type,
            results=results,
        )


# Entry for the benchmark harness.
def _run_taxonomy() -> None:
    runner = TaxonomyRunner()
    report = runner.run()
    print(report.summary())


BENCHMARKS = [
    ("Injection taxonomy (48 cases)", _run_taxonomy),
]
