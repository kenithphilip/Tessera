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
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from tessera.context import Context
from tessera.delegation import DelegationToken
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import TrustLevel
from tessera.policy_backends import PolicyBackend, PolicyInput
from tessera.telemetry import emit_decision

if TYPE_CHECKING:
    from tessera.cel_engine import CELPolicyEngine


class PolicyViolation(Exception):
    """Raised when a tool call fails policy evaluation."""


class DecisionKind(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    MODIFY = "modify"
    ADD_CONTEXT = "add_context"
    CONFIRM = "confirm"


class ResourceType(StrEnum):
    """MCP resource types subject to policy."""

    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"


class PolicyScope(StrEnum):
    """Hierarchy level for policy targeting.

    Scope priority: MESH > TEAM > AGENT. Higher scopes set trust
    floors that lower scopes can tighten but not loosen.
    """

    MESH = "mesh"
    TEAM = "team"
    AGENT = "agent"


_SCOPE_PRIORITY: dict[PolicyScope, int] = {
    PolicyScope.MESH: 0,
    PolicyScope.TEAM: 1,
    PolicyScope.AGENT: 2,
}


@dataclass(frozen=True)
class Decision:
    kind: DecisionKind
    reason: str
    tool: str
    required_trust: TrustLevel
    observed_trust: TrustLevel
    modified_args: dict[str, Any] | None = None
    injected_context: str | None = None
    confirmation_token: str | None = None

    @property
    def allowed(self) -> bool:
        return self.kind is DecisionKind.ALLOW

    @property
    def requires_approval(self) -> bool:
        return self.kind is DecisionKind.REQUIRE_APPROVAL


@dataclass(frozen=True)
class ResourceRequirement:
    """Minimum trust level a resource requires to be accessed.

    Sensitive tools that mutate external state or exfiltrate data should
    require TrustLevel.USER. Read-only tools can run at TrustLevel.TOOL.
    Nothing should require SYSTEM unless the proxy itself is the caller.

    side_effects: If False, this tool is read-only and exempt from the
    taint-floor denial. It can read tainted data but cannot act on it in
    ways that escape the trust boundary (no email, no writes, no exfil).
    Matches CaMeL's no_side_effect_tools set. Default True preserves
    existing deny-by-default behavior.
    """

    name: str
    resource_type: ResourceType = ResourceType.TOOL
    required_trust: TrustLevel = TrustLevel.USER
    side_effects: bool = True


# Backward-compatible alias.
ToolRequirement = ResourceRequirement


@dataclass
class Policy:
    """Per-tool trust requirements with deny-by-default semantics."""

    requirements: dict[tuple[str, ResourceType], ResourceRequirement] = field(
        default_factory=dict,
    )
    default_required_trust: TrustLevel = TrustLevel.USER
    backend: PolicyBackend | None = None
    fail_closed_backend_errors: bool = True
    base_requirements: dict[str, ToolRequirement] | None = None
    request_requirements: dict[str, ToolRequirement] = field(default_factory=dict)
    _human_approval_tools: set[str] = field(default_factory=set)
    scope: PolicyScope = PolicyScope.AGENT
    cel_engine: CELPolicyEngine | None = None

    def require(
        self,
        name: str,
        level: TrustLevel,
        resource_type: ResourceType = ResourceType.TOOL,
        side_effects: bool = True,
    ) -> None:
        """Register a trust requirement for a tool or resource.

        Args:
            name: Exact tool name or fnmatch glob pattern (e.g. "send_*").
                Exact names take precedence over patterns at evaluation time.
            level: Minimum trust level required to invoke this tool.
            resource_type: TOOL, PROMPT, or RESOURCE.
            side_effects: If False, this tool is read-only and exempt from
                the taint-floor denial. Tainted context can still be read
                but the tool cannot exfiltrate data or mutate external state.
        """
        self.requirements[(name, resource_type)] = ResourceRequirement(
            name=name,
            resource_type=resource_type,
            required_trust=level,
            side_effects=side_effects,
        )

    def requires_human_approval(self, tool: str) -> None:
        """Mark a tool as requiring human approval regardless of trust level."""
        self._human_approval_tools.add(tool)

    def evaluate(
        self,
        context: Context,
        tool_name: str,
        args: dict[str, Any] | None = None,
        delegation: DelegationToken | None = None,
        expected_delegate: str | None = None,
        resource_type: ResourceType = ResourceType.TOOL,
    ) -> Decision:
        """Return an allow or deny decision for a proposed tool call.

        The rule is: required_trust <= min_trust(context). Using min_trust
        (not max_trust) is what makes this taint tracking: any single
        untrusted segment drags the whole context down to its level.

        Delegation adds extra deny conditions. It never widens access
        beyond what the trust floor allows.
        """
        req = self._lookup_requirement(tool_name, resource_type)
        required = req.required_trust if req is not None else self.default_required_trust
        # Side-effect-free tools are exempt from the taint-floor denial.
        # They can consume tainted data but cannot act on it externally.
        # Setting required to UNTRUSTED ensures observed >= required always
        # holds; delegation and readers checks still apply.
        if req is not None and not req.side_effects:
            required = TrustLevel.UNTRUSTED
        if self.base_requirements is None:
            base_required = required
        elif tool_name in self.base_requirements:
            base_req = self.base_requirements[tool_name]
            base_required = TrustLevel.UNTRUSTED if not base_req.side_effects else base_req.required_trust
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
        # Readers lattice check: if any context segment has restricted readers,
        # verify that all recipient-like args are within the allowed set.
        # Only runs when the taint-floor check has already passed.
        if decision.allowed:
            readers_reason = _readers_deny_reason(args, context.effective_readers)
            if readers_reason is not None:
                decision = Decision(
                    kind=DecisionKind.DENY,
                    reason=readers_reason,
                    tool=tool_name,
                    required_trust=required,
                    observed_trust=observed,
                )
                backend_name = None
                metadata = {}

        # CEL deny rules: evaluated after taint floor passes. A CEL rule
        # can block or require approval but cannot allow a taint-denied call.
        if decision.allowed and self.cel_engine is not None:
            from tessera.cel_engine import CELContext as _CELCtx

            cel_ctx = _CELCtx(
                tool=tool_name,
                args=args or {},
                min_trust=int(observed),
                principal=context.principal or "",
                segment_count=len(context.segments),
                delegation_subject=(
                    delegation.subject if delegation else None
                ),
                delegation_actions=(
                    tuple(delegation.authorized_actions) if delegation else ()
                ),
            )
            cel_result = self.cel_engine.evaluate(cel_ctx)
            if cel_result is not None:
                if cel_result.action == "deny":
                    decision = Decision(
                        kind=DecisionKind.DENY,
                        reason=f"CEL rule {cel_result.rule_name!r}: {cel_result.message}",
                        tool=tool_name,
                        required_trust=required,
                        observed_trust=observed,
                    )
                elif cel_result.action == "require_approval":
                    decision = Decision(
                        kind=DecisionKind.REQUIRE_APPROVAL,
                        reason=f"CEL rule {cel_result.rule_name!r}: {cel_result.message}",
                        tool=tool_name,
                        required_trust=required,
                        observed_trust=observed,
                    )
        # Human approval gate: only triggers when taint floor allows the call.
        # DENY always takes precedence.
        if decision.allowed and tool_name in self._human_approval_tools:
            decision = Decision(
                kind=DecisionKind.REQUIRE_APPROVAL,
                reason="tool requires human approval",
                tool=tool_name,
                required_trust=required,
                observed_trust=observed,
            )
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.HUMAN_APPROVAL_REQUIRED,
                    principal=context.principal,
                    detail={
                        "tool": tool_name,
                        "required_trust": int(required),
                        "observed_trust": int(observed),
                    },
                )
            )
        if not decision.allowed and not decision.requires_approval:
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

    def _lookup_requirement(
        self,
        tool_name: str,
        resource_type: ResourceType,
    ) -> ResourceRequirement | None:
        """Resolve the requirement for a tool name with fnmatch fallback.

        Exact match takes precedence over glob patterns. Among patterns,
        the first registered match wins (registration order matters for
        overlapping patterns like "send_*" and "send_email_*").
        """
        key = (tool_name, resource_type)
        if key in self.requirements:
            return self.requirements[key]
        for (pattern, rtype), req in self.requirements.items():
            if rtype == resource_type and fnmatch(tool_name, pattern):
                return req
        return None

    @classmethod
    def merge(cls, *policies: Policy) -> Policy:
        """Merge policies from multiple scopes into one.

        Scope priority: MESH > TEAM > AGENT. Higher scopes set trust
        floors that lower scopes can tighten (raise) but not loosen
        (lower). This prevents an agent from relaxing org-wide policy.

        Human-approval-required tools from any scope are unioned.
        CEL engines from all scopes contribute rules evaluated in
        scope-priority order.
        """
        if not policies:
            return cls()

        sorted_policies = sorted(
            policies,
            key=lambda p: _SCOPE_PRIORITY.get(p.scope, 2),
        )

        # Use default_required_trust from the highest-priority scope.
        merged_default = sorted_policies[0].default_required_trust

        # For each requirement key, take the highest required_trust
        # across all scopes (lower scopes can tighten, not loosen).
        merged_reqs: dict[tuple[str, ResourceType], ResourceRequirement] = {}
        for policy in sorted_policies:
            for key, req in policy.requirements.items():
                if key not in merged_reqs:
                    merged_reqs[key] = req
                elif req.required_trust > merged_reqs[key].required_trust:
                    merged_reqs[key] = req

        # Union all human-approval tools.
        merged_approval: set[str] = set()
        for policy in sorted_policies:
            merged_approval |= policy._human_approval_tools

        # Concatenate CEL rules from all scopes in priority order.
        merged_cel: CELPolicyEngine | None = None
        all_cel_rules: list[Any] = []
        for policy in sorted_policies:
            if policy.cel_engine is not None:
                all_cel_rules.extend(policy.cel_engine._rules)
        if all_cel_rules:
            from tessera.cel_engine import CELPolicyEngine

            merged_cel = CELPolicyEngine(all_cel_rules)

        result = cls(
            requirements=merged_reqs,
            default_required_trust=merged_default,
            _human_approval_tools=merged_approval,
            scope=sorted_policies[0].scope,
            cel_engine=merged_cel,
        )
        return result


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


def _readers_deny_reason(
    args: dict[str, Any] | None,
    effective_readers: frozenset[str] | None,
) -> str | None:
    """Return a denial reason if the call's recipients are outside effective_readers.

    Only fires when at least one context segment carries restricted readers
    (effective_readers is not None). Recipients are extracted from common
    destination-like argument names.
    """
    if effective_readers is None or args is None:
        return None
    recipients: set[str] = set()
    for fname in ("to", "recipient", "recipients", "email", "destination", "destinations"):
        val = args.get(fname)
        if isinstance(val, str) and val.strip():
            recipients.add(val.strip())
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    recipients.add(item.strip())
    if not recipients:
        return None
    blocked = recipients - effective_readers
    if blocked:
        return (
            f"readers lattice violation: recipients {sorted(blocked)} "
            f"are outside the allowed readers set {sorted(effective_readers)}"
        )
    return None
