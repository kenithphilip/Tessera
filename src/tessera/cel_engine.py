"""CEL-based policy evaluation for attribute-driven deny rules.

CEL expressions are evaluated after the taint-floor check passes.
They act as deny-only refinements: a CEL rule can block an otherwise-
allowed tool call but cannot allow a taint-denied one. This follows
the same pattern as the OPA backend in policy_backends.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


class CELNotAvailable(RuntimeError):
    """Raised when cel-python is not installed."""


@dataclass(frozen=True)
class CELRule:
    """A single CEL deny rule.

    Args:
        name: Human-readable rule identifier.
        expression: CEL expression that evaluates to a boolean.
        action: Either "deny" or "require_approval".
        message: Explanation surfaced when the rule fires.
    """

    name: str
    expression: str
    action: str  # "deny" or "require_approval"
    message: str


@dataclass(frozen=True)
class CELContext:
    """Variables available inside CEL expressions.

    Each field maps to a CEL variable of the same name.
    """

    tool: str
    args: dict[str, Any]
    min_trust: int
    principal: str
    segment_count: int
    delegation_subject: str | None
    delegation_actions: tuple[str, ...]


@dataclass(frozen=True)
class CELDecision:
    """Result when a CEL rule fires."""

    rule_name: str
    action: str
    message: str


class CELPolicyEngine:
    """Evaluates a sequence of CEL deny rules against a CELContext.

    Requires the cel-python package. If cel-python is not installed,
    the constructor raises CELNotAvailable.
    """

    def __init__(self, rules: Sequence[CELRule]) -> None:
        try:
            import celpy
            import celpy.celtypes
        except ImportError as exc:
            raise CELNotAvailable(
                "cel-python is required for CEL policy rules. "
                "Install it with: pip install tessera[cel]"
            ) from exc

        self._celpy = celpy
        self._celtypes = celpy.celtypes
        self._rules = list(rules)
        self._compiled: list[tuple[CELRule, Any]] = []

        env = celpy.Environment()
        for rule in self._rules:
            ast = env.compile(rule.expression)
            prog = env.program(ast)
            self._compiled.append((rule, prog))

    def evaluate(self, context: CELContext) -> CELDecision | None:
        """Evaluate each rule in order. Return the first that fires, or None."""
        activation = self._build_activation(context)
        for rule, prog in self._compiled:
            result = prog.evaluate(activation)
            if result:
                return CELDecision(
                    rule_name=rule.name,
                    action=rule.action,
                    message=rule.message,
                )
        return None

    def _build_activation(self, context: CELContext) -> dict[str, Any]:
        """Convert a CELContext into a cel-python activation dict."""
        ct = self._celtypes
        return {
            "tool": ct.StringType(context.tool),
            "args": ct.MapType(
                {ct.StringType(k): ct.StringType(str(v)) for k, v in context.args.items()}
            ),
            "min_trust": ct.IntType(context.min_trust),
            "principal": ct.StringType(context.principal),
            "segment_count": ct.IntType(context.segment_count),
            "delegation_subject": ct.StringType(
                context.delegation_subject or ""
            ),
            "delegation_actions": ct.ListType(
                [ct.StringType(a) for a in context.delegation_actions]
            ),
        }
