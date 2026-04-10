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
from urllib.parse import urlparse

from tessera.context import Context
from tessera.delegation import DelegationToken
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import TrustLevel
from tessera.policy_backends import PolicyBackend, PolicyInput
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
    backend: PolicyBackend | None = None
    fail_closed_backend_errors: bool = True
    base_requirements: dict[str, ToolRequirement] | None = None
    request_requirements: dict[str, ToolRequirement] = field(default_factory=dict)

    def require(self, name: str, level: TrustLevel) -> None:
        self.requirements[name] = ToolRequirement(name=name, required_trust=level)

    def evaluate(
        self,
        context: Context,
        tool_name: str,
        args: dict[str, Any] | None = None,
        delegation: DelegationToken | None = None,
        expected_delegate: str | None = None,
    ) -> Decision:
        """Return an allow or deny decision for a proposed tool call.

        The rule is: required_trust <= min_trust(context). Using min_trust
        (not max_trust) is what makes this taint tracking: any single
        untrusted segment drags the whole context down to its level.

        Delegation adds extra deny conditions. It never widens access
        beyond what the trust floor allows.
        """
        required = (
            self.requirements[tool_name].required_trust
            if tool_name in self.requirements
            else self.default_required_trust
        )
        if self.base_requirements is None:
            base_required = required
        elif tool_name in self.base_requirements:
            base_required = self.base_requirements[tool_name].required_trust
        else:
            base_required = self.default_required_trust
        request_required = (
            self.request_requirements[tool_name].required_trust
            if tool_name in self.request_requirements
            else None
        )
        observed = context.min_trust
        delegation_reason = _delegation_deny_reason(
            tool_name,
            args,
            delegation,
            expected_delegate,
        )
        policy_input = PolicyInput.from_evaluation(
            context=context,
            tool=tool_name,
            args=args,
            required_trust=required,
            observed_trust=observed,
            default_required_trust=self.default_required_trust,
            base_required_trust=base_required,
            request_required_trust=request_required,
            delegation=delegation,
            expected_delegate=expected_delegate,
        )

        if observed >= required and delegation_reason is None:
            decision = Decision(
                kind=DecisionKind.ALLOW,
                reason=(
                    f"min_trust({int(observed)}) >= required({int(required)})"
                ),
                tool=tool_name,
                required_trust=required,
                observed_trust=observed,
            )
            backend_name: str | None = None
            metadata: dict[str, Any] = {}
            if self.backend is not None:
                backend_name = self.backend.name
                try:
                    backend_decision = self.backend.evaluate(policy_input)
                except Exception as exc:  # noqa: BLE001 - fail closed on backend faults
                    if self.fail_closed_backend_errors:
                        decision = Decision(
                            kind=DecisionKind.DENY,
                            reason=f"external policy backend {backend_name!r} failed: {exc}",
                            tool=tool_name,
                            required_trust=required,
                            observed_trust=observed,
                        )
                    else:
                        backend_name = f"{backend_name}:error"
                else:
                    metadata = backend_decision.metadata
                    if not backend_decision.allow:
                        decision = Decision(
                            kind=DecisionKind.DENY,
                            reason=backend_decision.reason or "denied by external policy backend",
                            tool=tool_name,
                            required_trust=required,
                            observed_trust=observed,
                        )
        else:
            reasons: list[str] = []
            if observed < required:
                reasons.append(
                    f"context contains a segment at trust_level={int(observed)}, "
                    f"below required {int(required)} for tool {tool_name!r}"
                )
            if delegation_reason is not None:
                reasons.append(delegation_reason)
            decision = Decision(
                kind=DecisionKind.DENY,
                reason="; ".join(reasons),
                tool=tool_name,
                required_trust=required,
                observed_trust=observed,
            )
            backend_name = None
            metadata = {}
        if not decision.allowed:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=context.principal,
                    detail={
                        "tool": tool_name,
                        "required_trust": int(required),
                        "observed_trust": int(observed),
                        "delegation_subject": delegation.subject if delegation else None,
                        "backend": backend_name,
                        "policy_input": policy_input.to_dict(),
                        "backend_metadata": metadata,
                        "reason": decision.reason,
                    },
                )
            )
        emit_decision(decision, backend=backend_name)
        return decision

    def enforce(
        self,
        context: Context,
        tool_name: str,
        args: dict[str, Any] | None = None,
        delegation: DelegationToken | None = None,
        expected_delegate: str | None = None,
    ) -> Decision:
        """Evaluate and raise PolicyViolation on deny."""
        decision = self.evaluate(
            context,
            tool_name,
            args,
            delegation,
            expected_delegate,
        )
        if not decision.allowed:
            raise PolicyViolation(decision.reason)
        return decision


def _delegation_deny_reason(
    tool_name: str,
    args: dict[str, Any] | None,
    delegation: DelegationToken | None,
    expected_delegate: str | None,
) -> str | None:
    if delegation is None:
        return None
    if expected_delegate is None:
        return "delegation token cannot be evaluated without local delegate identity"
    if delegation.delegate != expected_delegate:
        return (
            "delegation token delegate does not match local identity: "
            f"{delegation.delegate!r} != {expected_delegate!r}"
        )
    if tool_name not in delegation.authorized_actions:
        return f"delegation token does not authorize tool {tool_name!r}"

    constraints = delegation.constraints
    allowed_reason = _tool_list_constraint_reason(
        tool_name,
        constraints,
        field_name="allowed_tools",
        deny_if_missing=False,
    )
    if allowed_reason is not None:
        return allowed_reason

    denied_reason = _tool_list_constraint_reason(
        tool_name,
        constraints,
        field_name="denied_tools",
        deny_if_missing=True,
    )
    if denied_reason is not None:
        return denied_reason

    approval_reason = _tool_list_constraint_reason(
        tool_name,
        constraints,
        field_name="requires_human_for",
        deny_if_missing=True,
    )
    if approval_reason is not None:
        return (
            f"delegation constraint 'requires_human_for' requires human approval "
            f"for tool {tool_name!r}"
        )

    egress_reason = _domain_constraint_reason(args, constraints)
    if egress_reason is not None:
        return egress_reason

    return _max_cost_constraint_reason(tool_name, args, constraints)


def _tool_list_constraint_reason(
    tool_name: str,
    constraints: dict[str, Any],
    *,
    field_name: str,
    deny_if_missing: bool,
) -> str | None:
    if field_name not in constraints:
        return None
    value = constraints[field_name]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return f"delegation constraint {field_name!r} is invalid"
    tools = set(value)
    if deny_if_missing and tool_name in tools:
        return f"delegation constraint {field_name!r} blocks tool {tool_name!r}"
    if not deny_if_missing and tool_name not in tools:
        return f"delegation constraint {field_name!r} excludes tool {tool_name!r}"
    return None


def _max_cost_constraint_reason(
    tool_name: str,
    args: dict[str, Any] | None,
    constraints: dict[str, Any],
) -> str | None:
    del tool_name
    if "max_cost_usd" not in constraints:
        return None
    limit = constraints["max_cost_usd"]
    if not isinstance(limit, (int, float)):
        return "delegation constraint 'max_cost_usd' is invalid"
    if args is None:
        return "delegation constraint 'max_cost_usd' could not be evaluated"
    raw_cost = args.get("cost_usd", args.get("estimated_cost_usd"))
    if not isinstance(raw_cost, (int, float)):
        return "delegation constraint 'max_cost_usd' could not be evaluated"
    if float(raw_cost) > float(limit):
        return (
            f"delegation constraint 'max_cost_usd' exceeded: "
            f"{float(raw_cost)} > {float(limit)}"
        )
    return None


def _domain_constraint_reason(
    args: dict[str, Any] | None,
    constraints: dict[str, Any],
) -> str | None:
    if "allowed_domains" not in constraints and "denied_domains" not in constraints:
        return None
    if args is None:
        return "delegation domain constraints could not be evaluated"

    destinations = _extract_destinations(args)
    if not destinations:
        return "delegation domain constraints could not be evaluated"

    denied = _constraint_domain_set(constraints, "denied_domains")
    if isinstance(denied, str):
        return denied
    for destination in destinations:
        if any(_domain_matches(destination, blocked) for blocked in denied):
            return f"delegation constraint 'denied_domains' blocks destination {destination!r}"

    allowed = _constraint_domain_set(constraints, "allowed_domains")
    if isinstance(allowed, str):
        return allowed
    if allowed:
        for destination in destinations:
            if not any(_domain_matches(destination, permitted) for permitted in allowed):
                return (
                    "delegation constraint 'allowed_domains' excludes destination "
                    f"{destination!r}"
                )
    return None


def _constraint_domain_set(
    constraints: dict[str, Any],
    field_name: str,
) -> set[str] | str:
    if field_name not in constraints:
        return set()
    value = constraints[field_name]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return f"delegation constraint {field_name!r} is invalid"
    return {item.lower().strip().rstrip(".") for item in value}


def _extract_destinations(args: dict[str, Any]) -> set[str]:
    destinations: set[str] = set()
    for field_name in ("url", "endpoint", "host", "hostname", "domain"):
        _add_destination_value(destinations, args.get(field_name))
    for field_name in ("urls", "endpoints", "hosts", "domains"):
        value = args.get(field_name)
        if isinstance(value, list):
            for item in value:
                _add_destination_value(destinations, item)
    return destinations


def _add_destination_value(destinations: set[str], value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    candidate = value.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        host = parsed.hostname
        if host:
            destinations.add(host.rstrip("."))
        return
    destinations.add(candidate.rstrip("."))


def _domain_matches(destination: str, rule: str) -> bool:
    return destination == rule or destination.endswith(f".{rule}")
