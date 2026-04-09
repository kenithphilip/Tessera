"""Taint-tracking policy engine for tool calls.

The policy engine answers one question: given a context and a proposed tool
call, is the minimum trust level in the context high enough to clear the
tool's required trust level?

This is deliberately simple. Real deployments will want OPA or Cedar for
richer attribute-based policy, but the taint-tracking primitive is the load-
bearing security property, and it lives here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from tessera.context import Context
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import TrustLevel
from tessera.telemetry import emit_decision


class PolicyViolation(Exception):
    """Raised when a tool call fails policy evaluation."""


class DecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    tool: str
    required_trust: TrustLevel
    observed_trust: TrustLevel

    @property
    def allowed(self) -> bool:
        return self.kind is DecisionKind.ALLOW


@dataclass(frozen=True)
class ToolRequirement:
    """Minimum trust level a tool requires to fire.

    Sensitive tools that mutate external state or exfiltrate data should
    require TrustLevel.USER. Read-only tools can run at TrustLevel.TOOL.
    Nothing should require SYSTEM unless the proxy itself is the caller.
    """

    name: str
    required_trust: TrustLevel


@dataclass
class Policy:
    """Per-tool trust requirements with deny-by-default semantics."""

    requirements: dict[str, ToolRequirement] = field(default_factory=dict)
    default_required_trust: TrustLevel = TrustLevel.USER

    def require(self, name: str, level: TrustLevel) -> None:
        self.requirements[name] = ToolRequirement(name=name, required_trust=level)

    def evaluate(
        self,
        context: Context,
        tool_name: str,
        # args is captured for future attribute-based policy; currently unused
        # but part of the stable decision surface so callers can start passing
        # it now.
        args: dict[str, Any] | None = None,
    ) -> Decision:
        """Return an allow or deny decision for a proposed tool call.

        The rule is: required_trust <= min_trust(context). Using min_trust
        (not max_trust) is what makes this taint tracking: any single
        untrusted segment drags the whole context down to its level.
        """
        del args  # reserved for richer policies
        required = (
            self.requirements[tool_name].required_trust
            if tool_name in self.requirements
            else self.default_required_trust
        )
        observed = context.min_trust

        if observed >= required:
            decision = Decision(
                kind=DecisionKind.ALLOW,
                reason=(
                    f"min_trust({int(observed)}) >= required({int(required)})"
                ),
                tool=tool_name,
                required_trust=required,
                observed_trust=observed,
            )
        else:
            decision = Decision(
                kind=DecisionKind.DENY,
                reason=(
                    f"context contains a segment at trust_level={int(observed)}, "
                    f"below required {int(required)} for tool {tool_name!r}"
                ),
                tool=tool_name,
                required_trust=required,
                observed_trust=observed,
            )
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=context.principal,
                    detail={
                        "tool": tool_name,
                        "required_trust": int(required),
                        "observed_trust": int(observed),
                        "reason": decision.reason,
                    },
                )
            )
        emit_decision(decision)
        return decision

    def enforce(
        self,
        context: Context,
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate and raise PolicyViolation on deny."""
        decision = self.evaluate(context, tool_name, args)
        if not decision.allowed:
            raise PolicyViolation(decision.reason)
        return decision
