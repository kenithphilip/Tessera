"""Intermediate representation for policy configuration.

The IR decouples config parsing from policy execution. All input
formats (YAML dicts, CEL strings, Cedar, OPA/Rego) produce the same
IR types. The IR compiles to live Policy instances via compile_policy().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tessera.labels import TrustLevel

_TRUST_NAMES: dict[str, TrustLevel] = {
    "untrusted": TrustLevel.UNTRUSTED,
    "tool": TrustLevel.TOOL,
    "user": TrustLevel.USER,
    "system": TrustLevel.SYSTEM,
}


def _parse_trust(value: str | int) -> int:
    """Resolve a trust level string or int to its integer value."""
    if isinstance(value, int):
        return TrustLevel(value).value
    key = value.strip().lower()
    if key not in _TRUST_NAMES:
        raise ValueError(
            f"unknown trust level {value!r}, expected one of {list(_TRUST_NAMES)}"
        )
    return _TRUST_NAMES[key].value


@dataclass(frozen=True)
class ResourceRequirementIR:
    """One resource requirement in the IR.

    YAML example::

        requirements:
          - name: send_email
            required_trust: user
            side_effects: true
            critical_args: [to, recipient, cc, bcc]
          - name: "get_*"
            required_trust: tool
            side_effects: false
    """

    name: str
    resource_type: str = "tool"  # "tool", "prompt", "resource"
    required_trust: int = 100  # TrustLevel int value
    side_effects: bool = True   # False = read-only, exempt from taint floor
    critical_args: tuple[str, ...] | None = None  # args requiring user provenance


@dataclass(frozen=True)
class CELRuleIR:
    """One CEL deny rule in the IR."""

    name: str
    expression: str
    action: str = "deny"  # "deny" or "require_approval"
    message: str = ""


@dataclass(frozen=True)
class PolicyIR:
    """Complete policy configuration in intermediate form."""

    requirements: tuple[ResourceRequirementIR, ...] = ()
    scope: str = "agent"  # "mesh", "team", "agent"
    default_trust: int = 100  # TrustLevel.USER
    cel_rules: tuple[CELRuleIR, ...] = ()
    human_approval_tools: frozenset[str] = field(default_factory=frozenset)


def compile_policy(ir: PolicyIR) -> Any:
    """Compile a PolicyIR into a live tessera.policy.Policy instance.

    Imports Policy at call time to avoid circular imports. Resilient
    to missing optional features (PolicyScope, ResourceType,
    CELPolicyEngine): the IR still compiles to a basic Policy when
    those types are not yet available.
    """
    from tessera.policy import Policy

    policy = Policy(default_required_trust=TrustLevel(ir.default_trust))

    # Try to set scope if PolicyScope exists.
    try:
        from tessera.policy import PolicyScope  # type: ignore[attr-defined]
        policy.scope = PolicyScope(ir.scope)
    except (ImportError, AttributeError, ValueError):
        pass

    # Add requirements.
    for req in ir.requirements:
        try:
            from tessera.policy import ResourceType  # type: ignore[attr-defined]
            policy.require(
                req.name,
                TrustLevel(req.required_trust),
                resource_type=ResourceType(req.resource_type),
                side_effects=req.side_effects,
            )
        except (ImportError, AttributeError, TypeError):
            policy.require(
                req.name,
                TrustLevel(req.required_trust),
                side_effects=req.side_effects,
            )

    # Add human approval tools.
    for tool in ir.human_approval_tools:
        policy.requires_human_approval(tool)

    # Add CEL engine if rules are present.
    if ir.cel_rules:
        try:
            from tessera.cel_engine import CELPolicyEngine, CELRule  # type: ignore[import-not-found]
            rules = [
                CELRule(
                    name=r.name,
                    expression=r.expression,
                    action=r.action,
                    message=r.message,
                )
                for r in ir.cel_rules
            ]
            policy.cel_engine = CELPolicyEngine(rules)  # type: ignore[attr-defined]
        except ImportError:
            pass

    return policy


def from_dict(data: dict[str, Any]) -> PolicyIR:
    """Parse a dict (from YAML, JSON, or inline) into PolicyIR.

    Expected keys:
      requirements or tool_policies: list of {name, resource_type?, required_trust}
      scope: "mesh" | "team" | "agent"
      default_trust or default_required_trust: trust level name or int
      cel_rules: list of {name, expression, action?, message?}
      human_approval_tools: list of tool names
    """
    raw_reqs = data.get("requirements") or data.get("tool_policies") or []
    requirements = tuple(
        ResourceRequirementIR(
            name=r["name"],
            resource_type=r.get("resource_type", "tool"),
            required_trust=_parse_trust(r.get("required_trust", 100)),
            side_effects=r.get("side_effects", True),
            critical_args=(
                tuple(r["critical_args"]) if r.get("critical_args") else None
            ),
        )
        for r in raw_reqs
    )

    raw_trust = data.get("default_trust") or data.get("default_required_trust")
    default_trust = _parse_trust(raw_trust) if raw_trust is not None else 100

    scope = data.get("scope", "agent")
    if scope not in ("mesh", "team", "agent"):
        raise ValueError(
            f"invalid scope {scope!r}, expected 'mesh', 'team', or 'agent'"
        )

    raw_cel = data.get("cel_rules") or []
    cel_rules = tuple(
        CELRuleIR(
            name=c["name"],
            expression=c["expression"],
            action=c.get("action", "deny"),
            message=c.get("message", ""),
        )
        for c in raw_cel
    )

    raw_approval = data.get("human_approval_tools") or []
    human_approval_tools = frozenset(raw_approval)

    return PolicyIR(
        requirements=requirements,
        scope=scope,
        default_trust=default_trust,
        cel_rules=cel_rules,
        human_approval_tools=human_approval_tools,
    )


def from_yaml_string(text: str) -> PolicyIR:
    """Parse a YAML string into PolicyIR. Requires PyYAML."""
    import yaml  # type: ignore[import-untyped]

    return from_dict(yaml.safe_load(text))


def from_yaml_path(path: str) -> PolicyIR:
    """Load a YAML file into PolicyIR. Requires PyYAML."""
    from pathlib import Path

    import yaml  # type: ignore[import-untyped]

    return from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
