"""Tests for tessera.ir -- intermediate representation for policy config."""

from __future__ import annotations

import pytest

from tessera.ir import (
    CELRuleIR,
    PolicyIR,
    ResourceRequirementIR,
    compile_policy,
    from_dict,
)
from tessera.labels import TrustLevel
from tessera.policy import DecisionKind, Policy, ResourceType


def test_from_dict_minimal() -> None:
    """Empty dict produces default PolicyIR."""
    ir = from_dict({})
    assert ir == PolicyIR()
    assert ir.requirements == ()
    assert ir.scope == "agent"
    assert ir.default_trust == 100
    assert ir.cel_rules == ()
    assert ir.human_approval_tools == frozenset()


def test_from_dict_with_requirements() -> None:
    """Parses tool requirements from the 'requirements' key."""
    ir = from_dict({
        "requirements": [
            {"name": "send_email", "required_trust": 100},
            {"name": "read_file", "resource_type": "resource", "required_trust": 50},
        ],
    })
    assert len(ir.requirements) == 2
    assert ir.requirements[0] == ResourceRequirementIR(
        name="send_email", resource_type="tool", required_trust=100,
    )
    assert ir.requirements[1] == ResourceRequirementIR(
        name="read_file", resource_type="resource", required_trust=50,
    )


def test_from_dict_trust_level_by_name() -> None:
    """Trust levels resolve from case-insensitive string names."""
    ir = from_dict({
        "default_trust": "tool",
        "requirements": [
            {"name": "fetch", "required_trust": "user"},
            {"name": "browse", "required_trust": "UNTRUSTED"},
        ],
    })
    assert ir.default_trust == 50
    assert ir.requirements[0].required_trust == 100
    assert ir.requirements[1].required_trust == 0


def test_from_dict_trust_level_by_int() -> None:
    """Trust levels pass through from integer values."""
    ir = from_dict({
        "default_trust": 200,
        "requirements": [
            {"name": "admin_tool", "required_trust": 200},
        ],
    })
    assert ir.default_trust == 200
    assert ir.requirements[0].required_trust == 200


def test_from_dict_with_cel_rules() -> None:
    """Parses CEL rule dicts."""
    ir = from_dict({
        "cel_rules": [
            {
                "name": "block_exfil",
                "expression": "tool.name == 'send_email'",
                "action": "deny",
                "message": "blocked",
            },
        ],
    })
    assert len(ir.cel_rules) == 1
    rule = ir.cel_rules[0]
    assert rule == CELRuleIR(
        name="block_exfil",
        expression="tool.name == 'send_email'",
        action="deny",
        message="blocked",
    )


def test_from_dict_with_human_approval() -> None:
    """Parses human approval tool list."""
    ir = from_dict({
        "human_approval_tools": ["delete_account", "transfer_funds"],
    })
    assert ir.human_approval_tools == frozenset({"delete_account", "transfer_funds"})


def test_from_dict_with_scope() -> None:
    """Parses scope string."""
    ir = from_dict({"scope": "mesh"})
    assert ir.scope == "mesh"


def test_from_dict_tool_policies_alias() -> None:
    """The 'tool_policies' key works as an alias for 'requirements'."""
    ir = from_dict({
        "tool_policies": [
            {"name": "query_db", "required_trust": "tool"},
        ],
    })
    assert len(ir.requirements) == 1
    assert ir.requirements[0].name == "query_db"


def test_from_dict_default_required_trust_alias() -> None:
    """The 'default_required_trust' key works as an alias."""
    ir = from_dict({"default_required_trust": "system"})
    assert ir.default_trust == 200


def test_from_dict_invalid_trust_name() -> None:
    """Unknown trust level name raises ValueError."""
    with pytest.raises(ValueError, match="unknown trust level"):
        from_dict({"default_trust": "superadmin"})


def test_compile_policy_creates_policy() -> None:
    """IR compiles to a tessera.policy.Policy instance."""
    ir = PolicyIR()
    policy = compile_policy(ir)
    assert isinstance(policy, Policy)
    assert policy.default_required_trust == TrustLevel.USER


def test_compile_policy_with_requirements() -> None:
    """Requirements are added to the compiled Policy."""
    ir = PolicyIR(
        requirements=(
            ResourceRequirementIR(name="send_email", required_trust=100),
            ResourceRequirementIR(name="read_file", required_trust=50),
        ),
    )
    policy = compile_policy(ir)
    assert ("send_email", ResourceType.TOOL) in policy.requirements
    assert policy.requirements[("send_email", ResourceType.TOOL)].required_trust == TrustLevel.USER
    assert ("read_file", ResourceType.TOOL) in policy.requirements
    assert policy.requirements[("read_file", ResourceType.TOOL)].required_trust == TrustLevel.TOOL


def test_compile_policy_with_human_approval() -> None:
    """Human approval tools are registered on the compiled Policy."""
    ir = PolicyIR(
        human_approval_tools=frozenset({"delete_account"}),
    )
    policy = compile_policy(ir)
    assert "delete_account" in policy._human_approval_tools


def test_compile_policy_default_trust() -> None:
    """The default trust level propagates to the compiled Policy."""
    ir = PolicyIR(default_trust=50)
    policy = compile_policy(ir)
    assert policy.default_required_trust == TrustLevel.TOOL


def test_from_yaml_string_parses_yaml() -> None:
    """YAML string parses to PolicyIR."""
    yaml = pytest.importorskip("yaml")  # noqa: F841
    from tessera.ir import from_yaml_string

    text = """\
scope: team
default_trust: tool
requirements:
  - name: send_email
    required_trust: user
human_approval_tools:
  - delete_account
"""
    ir = from_yaml_string(text)
    assert ir.scope == "team"
    assert ir.default_trust == 50
    assert len(ir.requirements) == 1
    assert ir.requirements[0].name == "send_email"
    assert ir.human_approval_tools == frozenset({"delete_account"})


def test_round_trip_dict_to_policy() -> None:
    """dict -> IR -> Policy -> evaluate produces correct decisions."""
    from tessera.context import Context, make_segment
    from tessera.labels import Origin, sign_label

    key = b"test-key-for-ir-round-trip"

    ir = from_dict({
        "default_trust": "user",
        "requirements": [
            {"name": "send_email", "required_trust": "user"},
            {"name": "read_file", "required_trust": "tool"},
        ],
    })
    policy = compile_policy(ir)

    # Build a context at TOOL level.
    seg = make_segment("tool output", Origin.TOOL, "agent", key)
    ctx = Context(segments=[seg])
    assert ctx.min_trust == TrustLevel.TOOL

    # TOOL-level context can call read_file (requires TOOL).
    decision = policy.evaluate(ctx, "read_file")
    assert decision.kind == DecisionKind.ALLOW

    # TOOL-level context cannot call send_email (requires USER).
    decision = policy.evaluate(ctx, "send_email")
    assert decision.kind == DecisionKind.DENY
