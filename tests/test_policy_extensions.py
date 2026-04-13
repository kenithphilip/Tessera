"""Tests for CEL engine, resource-type RBAC, and hierarchical policy merge."""

from __future__ import annotations

import sys

import pytest

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import (
    DecisionKind,
    Policy,
    PolicyScope,
    ResourceRequirement,
    ResourceType,
    ToolRequirement,
)

KEY = b"test-hmac-key-do-not-use-in-prod"

try:
    import celpy  # noqa: F401

    _has_celpy = True
except ImportError:
    _has_celpy = False

requires_celpy = pytest.mark.skipif(not _has_celpy, reason="cel-python not installed")


def _ctx_with(*segments: object) -> Context:
    ctx = Context()
    for s in segments:
        ctx.add(s)  # type: ignore[arg-type]
    return ctx


# ── CEL engine tests ──────────────────────────────────────────────────


@requires_celpy
def test_cel_rule_denies_when_expression_matches() -> None:
    from tessera.cel_engine import CELContext, CELPolicyEngine, CELRule

    rule = CELRule(
        name="block-delete",
        expression='tool == "delete_account"',
        action="deny",
        message="account deletion blocked by CEL",
    )
    engine = CELPolicyEngine([rule])
    cel_ctx = CELContext(
        tool="delete_account",
        args={},
        min_trust=100,
        principal="alice",
        segment_count=1,
        delegation_subject=None,
        delegation_actions=(),
    )
    result = engine.evaluate(cel_ctx)
    assert result is not None
    assert result.rule_name == "block-delete"
    assert result.action == "deny"


@requires_celpy
def test_cel_rule_passes_when_expression_does_not_match() -> None:
    from tessera.cel_engine import CELContext, CELPolicyEngine, CELRule

    rule = CELRule(
        name="block-delete",
        expression='tool == "delete_account"',
        action="deny",
        message="account deletion blocked",
    )
    engine = CELPolicyEngine([rule])
    cel_ctx = CELContext(
        tool="read_file",
        args={},
        min_trust=100,
        principal="alice",
        segment_count=1,
        delegation_subject=None,
        delegation_actions=(),
    )
    result = engine.evaluate(cel_ctx)
    assert result is None


@requires_celpy
def test_cel_require_approval_action() -> None:
    from tessera.cel_engine import CELContext, CELPolicyEngine, CELRule

    rule = CELRule(
        name="high-cost-approval",
        expression="min_trust < 200",
        action="require_approval",
        message="requires human sign-off",
    )
    engine = CELPolicyEngine([rule])
    cel_ctx = CELContext(
        tool="transfer_funds",
        args={},
        min_trust=100,
        principal="alice",
        segment_count=2,
        delegation_subject=None,
        delegation_actions=(),
    )
    result = engine.evaluate(cel_ctx)
    assert result is not None
    assert result.action == "require_approval"


@requires_celpy
def test_cel_context_includes_delegation_fields() -> None:
    from tessera.cel_engine import CELContext, CELPolicyEngine, CELRule

    rule = CELRule(
        name="delegation-check",
        expression='delegation_subject == "user:bob"',
        action="deny",
        message="bob cannot invoke this",
    )
    engine = CELPolicyEngine([rule])
    cel_ctx = CELContext(
        tool="send_email",
        args={},
        min_trust=100,
        principal="alice",
        segment_count=1,
        delegation_subject="user:bob",
        delegation_actions=("send_email",),
    )
    result = engine.evaluate(cel_ctx)
    assert result is not None
    assert result.rule_name == "delegation-check"


@requires_celpy
def test_cel_evaluated_after_taint_floor() -> None:
    """Taint deny takes precedence over CEL evaluation."""
    from tessera.cel_engine import CELPolicyEngine, CELRule

    rule = CELRule(
        name="always-deny",
        expression="true",
        action="deny",
        message="should not matter",
    )
    engine = CELPolicyEngine([rule])
    policy = Policy(cel_engine=engine)
    policy.require("send_email", TrustLevel.USER)

    ctx = _ctx_with(
        make_segment("untrusted data", Origin.WEB, "alice", KEY),
    )
    decision = policy.evaluate(ctx, "send_email")
    assert decision.kind is DecisionKind.DENY
    assert "CEL" not in decision.reason


@requires_celpy
def test_cel_engine_raises_without_celpy(monkeypatch: pytest.MonkeyPatch) -> None:
    """CELPolicyEngine raises CELNotAvailable when celpy is missing."""
    real_celpy = sys.modules.get("celpy")
    real_celtypes = sys.modules.get("celpy.celtypes")
    monkeypatch.setitem(sys.modules, "celpy", None)
    monkeypatch.setitem(sys.modules, "celpy.celtypes", None)
    import importlib
    from tessera import cel_engine

    importlib.reload(cel_engine)
    try:
        with pytest.raises(cel_engine.CELNotAvailable):
            cel_engine.CELPolicyEngine([])
    finally:
        if real_celpy is not None:
            monkeypatch.setitem(sys.modules, "celpy", real_celpy)
        else:
            monkeypatch.delitem(sys.modules, "celpy", raising=False)
        if real_celtypes is not None:
            monkeypatch.setitem(sys.modules, "celpy.celtypes", real_celtypes)
        else:
            monkeypatch.delitem(sys.modules, "celpy.celtypes", raising=False)
        importlib.reload(cel_engine)


# ── Resource type tests ───────────────────────────────────────────────


def test_resource_requirement_defaults_to_tool() -> None:
    req = ResourceRequirement(name="send_email")
    assert req.resource_type is ResourceType.TOOL
    assert req.required_trust is TrustLevel.USER


def test_policy_require_with_resource_type() -> None:
    policy = Policy()
    policy.require("my_prompt", TrustLevel.TOOL, resource_type=ResourceType.PROMPT)
    key = ("my_prompt", ResourceType.PROMPT)
    assert key in policy.requirements
    assert policy.requirements[key].resource_type is ResourceType.PROMPT


def test_evaluate_with_prompt_resource_type() -> None:
    policy = Policy()
    policy.require("summarize", TrustLevel.TOOL, resource_type=ResourceType.PROMPT)
    ctx = _ctx_with(
        make_segment("tool output", Origin.TOOL, "alice", KEY),
    )
    decision = policy.evaluate(
        ctx, "summarize", resource_type=ResourceType.PROMPT,
    )
    assert decision.allowed


def test_evaluate_with_resource_resource_type() -> None:
    policy = Policy()
    policy.require("config_file", TrustLevel.USER, resource_type=ResourceType.RESOURCE)
    ctx = _ctx_with(
        make_segment("user request", Origin.USER, "alice", KEY),
    )
    decision = policy.evaluate(
        ctx, "config_file", resource_type=ResourceType.RESOURCE,
    )
    assert decision.allowed


def test_backward_compat_tool_requirement_alias() -> None:
    """ToolRequirement is an alias for ResourceRequirement."""
    assert ToolRequirement is ResourceRequirement
    req = ToolRequirement(name="send_email", required_trust=TrustLevel.USER)
    assert req.resource_type is ResourceType.TOOL


# ── Hierarchical policy tests ────────────────────────────────────────


def test_merge_higher_scope_sets_floor() -> None:
    mesh = Policy(scope=PolicyScope.MESH)
    mesh.require("deploy", TrustLevel.USER)

    agent = Policy(scope=PolicyScope.AGENT)

    merged = Policy.merge(mesh, agent)
    ctx = _ctx_with(
        make_segment("deploy now", Origin.USER, "alice", KEY),
    )
    decision = merged.evaluate(ctx, "deploy")
    assert decision.allowed
    assert decision.required_trust == TrustLevel.USER


def test_merge_agent_cannot_loosen_mesh_policy() -> None:
    mesh = Policy(scope=PolicyScope.MESH)
    mesh.require("deploy", TrustLevel.USER)

    agent = Policy(scope=PolicyScope.AGENT)
    agent.require("deploy", TrustLevel.UNTRUSTED)

    merged = Policy.merge(mesh, agent)
    key = ("deploy", ResourceType.TOOL)
    assert merged.requirements[key].required_trust == TrustLevel.USER


def test_merge_agent_can_tighten_mesh_policy() -> None:
    mesh = Policy(scope=PolicyScope.MESH)
    mesh.require("deploy", TrustLevel.TOOL)

    agent = Policy(scope=PolicyScope.AGENT)
    agent.require("deploy", TrustLevel.SYSTEM)

    merged = Policy.merge(mesh, agent)
    key = ("deploy", ResourceType.TOOL)
    assert merged.requirements[key].required_trust == TrustLevel.SYSTEM


def test_merge_unions_human_approval_tools() -> None:
    mesh = Policy(scope=PolicyScope.MESH)
    mesh.requires_human_approval("deploy")

    agent = Policy(scope=PolicyScope.AGENT)
    agent.requires_human_approval("delete_user")

    merged = Policy.merge(mesh, agent)
    assert "deploy" in merged._human_approval_tools
    assert "delete_user" in merged._human_approval_tools


def test_merge_uses_highest_scope_default_trust() -> None:
    mesh = Policy(
        scope=PolicyScope.MESH,
        default_required_trust=TrustLevel.SYSTEM,
    )
    agent = Policy(
        scope=PolicyScope.AGENT,
        default_required_trust=TrustLevel.UNTRUSTED,
    )
    merged = Policy.merge(mesh, agent)
    assert merged.default_required_trust == TrustLevel.SYSTEM


def test_merge_single_policy_returns_equivalent() -> None:
    original = Policy(scope=PolicyScope.TEAM)
    original.require("send_email", TrustLevel.USER)
    original.requires_human_approval("deploy")

    merged = Policy.merge(original)
    key = ("send_email", ResourceType.TOOL)
    assert key in merged.requirements
    assert merged.requirements[key].required_trust == TrustLevel.USER
    assert "deploy" in merged._human_approval_tools


def test_scope_enum_values() -> None:
    assert PolicyScope.MESH == "mesh"
    assert PolicyScope.TEAM == "team"
    assert PolicyScope.AGENT == "agent"
