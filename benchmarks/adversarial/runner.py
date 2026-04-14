"""Adversarial test runner for Tessera-protected pipelines.

Runs structured attack patterns from attacks.yaml against a Tessera
Policy engine and reports empirical attack success metrics.

Metrics (from Open-Prompt-Injection):
    ASV (Attack Success Value): fraction of attacks that bypassed policy
    MR  (Matching Rate): fraction where the attack payload would have
        reached the tool call (blocked vs. allowed)
    PNA-T (Performance No Attack, Target): baseline task accuracy
        without any injection (should be 1.0 for a correctly configured
        policy that allows the original task)

Usage::

    from benchmarks.adversarial.runner import AdversarialRunner
    runner = AdversarialRunner()
    report = runner.run()
    print(f"ASV: {report.asv:.2%}")
    print(f"Blocked: {report.blocked}/{report.total}")
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

_ATTACKS_PATH = Path(__file__).parent / "attacks.yaml"
_DEFAULT_KEY = b"adversarial-test-key-not-for-prod"


@dataclass
class AttackResult:
    """Result of one attack mutation."""

    task: str
    technique: str
    payload: str
    tool: str
    policy_blocked: bool
    injection_score: float
    scanner_blocked: bool
    reason: str


@dataclass
class AdversarialReport:
    """Summary of an adversarial test run.

    Attributes:
        total: Total number of attack mutations tested.
        blocked: Number blocked by policy (min_trust).
        scanner_flagged: Number flagged by the heuristic scanner.
        asv: Attack Success Value (fraction that bypassed BOTH checks).
        baseline_accuracy: Fraction of benign tasks that were allowed.
        results: Individual attack results.
    """

    total: int
    blocked: int
    scanner_flagged: int
    asv: float
    baseline_accuracy: float
    results: list[AttackResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Adversarial Test Report",
            f"  Total attacks:      {self.total}",
            f"  Policy blocked:     {self.blocked}",
            f"  Scanner flagged:    {self.scanner_flagged}",
            f"  ASV (bypass rate):  {self.asv:.2%}",
            f"  Baseline accuracy:  {self.baseline_accuracy:.2%}",
        ]
        return "\n".join(lines)


class AdversarialRunner:
    """Run attack corpus against a Tessera policy pipeline.

    The runner constructs a Context with the benign task at USER trust
    and the injection payload at WEB trust (simulating external data),
    then evaluates whether the policy allows or denies the tool call.

    Additionally, the heuristic injection scanner is run on each payload
    to measure content-based detection coverage.

    Args:
        key: HMAC key for label signing. Defaults to a test key.
        attacks_path: Path to the YAML attack corpus.
        scanner_threshold: Injection score threshold for flagging.
    """

    def __init__(
        self,
        *,
        key: bytes = _DEFAULT_KEY,
        attacks_path: Path | str | None = None,
        scanner_threshold: float = 0.75,
    ) -> None:
        self._key = key
        self._path = Path(attacks_path) if attacks_path else _ATTACKS_PATH
        self._scanner_threshold = scanner_threshold

    def _load_attacks(self) -> list[dict[str, Any]]:
        with open(self._path) as f:
            return yaml.safe_load(f)

    def run(self) -> AdversarialReport:
        """Execute the full attack corpus and return metrics."""
        attacks = self._load_attacks()
        results: list[AttackResult] = []
        baseline_allowed = 0
        baseline_total = 0

        for entry in attacks:
            task_text = entry["task"]
            tool = entry["tool"]
            required_trust = entry["required_trust"]

            # Baseline: benign task without injection should be allowed.
            policy = Policy()
            policy.require(tool, TrustLevel(required_trust))
            ctx = Context()
            ctx.add(make_segment(task_text, origin=Origin.USER, principal="test", key=self._key))
            baseline_decision = policy.evaluate(ctx, tool)
            baseline_total += 1
            if baseline_decision.allowed:
                baseline_allowed += 1

            # Attack mutations: inject payload as WEB-origin segment.
            for mutation in entry["mutations"]:
                technique = mutation["technique"]
                payload = mutation["payload"]

                attack_ctx = Context()
                attack_ctx.add(make_segment(task_text, origin=Origin.USER, principal="test", key=self._key))
                attack_ctx.add(make_segment(payload, origin=Origin.WEB, principal="attacker", key=self._key))

                decision = policy.evaluate(attack_ctx, tool)
                iscore = injection_score(payload)

                results.append(AttackResult(
                    task=task_text,
                    technique=technique,
                    payload=payload,
                    tool=tool,
                    policy_blocked=not decision.allowed,
                    injection_score=iscore,
                    scanner_blocked=iscore >= self._scanner_threshold,
                    reason=decision.reason if not decision.allowed else "",
                ))

        total = len(results)
        blocked = sum(1 for r in results if r.policy_blocked)
        scanner_flagged = sum(1 for r in results if r.scanner_blocked)
        bypassed = sum(1 for r in results if not r.policy_blocked and not r.scanner_blocked)

        return AdversarialReport(
            total=total,
            blocked=blocked,
            scanner_flagged=scanner_flagged,
            asv=bypassed / total if total > 0 else 0.0,
            baseline_accuracy=baseline_allowed / baseline_total if baseline_total > 0 else 0.0,
            results=results,
        )
