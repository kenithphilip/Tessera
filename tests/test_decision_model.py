"""Tests for Phase 4: Expanded Decision Model.

Covers:
- DecisionKind MODIFY, ADD_CONTEXT, CONFIRM verbs
- Decision extended fields (modified_args, injected_context, confirmation_token)
- HookEvent/DecisionKind compatibility matrix
- narrow_delegation() monotonic narrowing enforcement
- LivenessChecker three-property gate
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tessera.delegation import (
    DelegationNarrowingViolation,
    DelegationToken,
    narrow_delegation,
    sign_delegation,
)
from tessera.hooks.compatibility import (
    HookEvent,
    IncompatibleDecisionError,
    valid_decisions,
    validate_decision,
)
from tessera.labels import TrustLevel
from tessera.liveness import LivenessChecker, LivenessState
from tessera.policy import Decision, DecisionKind

# ---------------------------------------------------------------------------
# DecisionKind values
# ---------------------------------------------------------------------------

def test_decision_kind_core_values():
    assert DecisionKind.ALLOW == "allow"
    assert DecisionKind.DENY == "deny"
    assert DecisionKind.REQUIRE_APPROVAL == "require_approval"


def test_decision_kind_extended_values():
    assert DecisionKind.MODIFY == "modify"
    assert DecisionKind.ADD_CONTEXT == "add_context"
    assert DecisionKind.CONFIRM == "confirm"


def test_decision_kind_is_str_enum():
    assert str(DecisionKind.MODIFY) == "modify"
    assert DecisionKind("add_context") is DecisionKind.ADD_CONTEXT


# ---------------------------------------------------------------------------
# Decision extended fields
# ---------------------------------------------------------------------------

def _base_decision(kind: DecisionKind = DecisionKind.ALLOW, **kwargs) -> Decision:
    return Decision(
        kind=kind,
        reason="test",
        tool="send_email",
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.USER,
        **kwargs,
    )


def test_decision_defaults_none():
    d = _base_decision()
    assert d.modified_args is None
    assert d.injected_context is None
    assert d.confirmation_token is None


def test_decision_modify_kind_carries_args():
    d = _base_decision(
        kind=DecisionKind.MODIFY,
        modified_args={"recipient": "safe@example.com", "body": "[redacted]"},
    )
    assert d.kind is DecisionKind.MODIFY
    assert d.modified_args == {"recipient": "safe@example.com", "body": "[redacted]"}
    assert d.injected_context is None


def test_decision_add_context_kind_carries_context():
    d = _base_decision(
        kind=DecisionKind.ADD_CONTEXT,
        injected_context="WARNING: this tool writes to production.",
    )
    assert d.kind is DecisionKind.ADD_CONTEXT
    assert d.injected_context == "WARNING: this tool writes to production."
    assert d.modified_args is None


def test_decision_confirm_kind_carries_token():
    d = _base_decision(
        kind=DecisionKind.CONFIRM,
        confirmation_token="tok-abc123",
    )
    assert d.kind is DecisionKind.CONFIRM
    assert d.confirmation_token == "tok-abc123"


def test_decision_is_frozen():
    d = _base_decision()
    with pytest.raises(Exception):
        d.kind = DecisionKind.DENY  # type: ignore[misc]


def test_decision_allowed_property():
    assert _base_decision(kind=DecisionKind.ALLOW).allowed
    assert not _base_decision(kind=DecisionKind.DENY).allowed


# ---------------------------------------------------------------------------
# HookEvent / DecisionKind compatibility matrix
# ---------------------------------------------------------------------------

def test_post_policy_evaluate_allows_all_kinds():
    all_kinds = set(DecisionKind)
    valid = valid_decisions(HookEvent.POST_POLICY_EVALUATE)
    assert all_kinds == valid, f"Missing: {all_kinds - valid}"


def test_post_tool_call_gate_allows_allow_deny_modify():
    valid = valid_decisions(HookEvent.POST_TOOL_CALL_GATE)
    assert DecisionKind.ALLOW in valid
    assert DecisionKind.DENY in valid
    assert DecisionKind.MODIFY in valid
    # ADD_CONTEXT and CONFIRM do not apply at tool execution time
    assert DecisionKind.ADD_CONTEXT not in valid
    assert DecisionKind.CONFIRM not in valid
    assert DecisionKind.REQUIRE_APPROVAL not in valid


def test_post_delegation_verify_allows_only_allow_deny():
    valid = valid_decisions(HookEvent.POST_DELEGATION_VERIFY)
    assert valid == frozenset({DecisionKind.ALLOW, DecisionKind.DENY})


def test_validate_decision_passes_for_compatible():
    # Should not raise
    validate_decision(HookEvent.POST_DELEGATION_VERIFY, DecisionKind.DENY)
    validate_decision(HookEvent.POST_TOOL_CALL_GATE, DecisionKind.MODIFY)
    validate_decision(HookEvent.POST_POLICY_EVALUATE, DecisionKind.CONFIRM)


def test_validate_decision_raises_for_incompatible():
    with pytest.raises(IncompatibleDecisionError) as exc_info:
        validate_decision(HookEvent.POST_DELEGATION_VERIFY, DecisionKind.MODIFY)
    err = exc_info.value
    assert err.event is HookEvent.POST_DELEGATION_VERIFY
    assert err.decision is DecisionKind.MODIFY
    assert "MODIFY" in str(err)


def test_validate_decision_add_context_invalid_for_tool_gate():
    with pytest.raises(IncompatibleDecisionError):
        validate_decision(HookEvent.POST_TOOL_CALL_GATE, DecisionKind.ADD_CONTEXT)


def test_incompatible_error_lists_valid_decisions():
    with pytest.raises(IncompatibleDecisionError) as exc_info:
        validate_decision(HookEvent.POST_DELEGATION_VERIFY, DecisionKind.CONFIRM)
    msg = str(exc_info.value)
    assert "allow" in msg
    assert "deny" in msg


# ---------------------------------------------------------------------------
# narrow_delegation()
# ---------------------------------------------------------------------------

_KEY = b"test-key-for-narrowing"
_NOW = datetime(2026, 4, 13, 12, 0, 0, tzinfo=timezone.utc)
_LATER = _NOW + timedelta(hours=1)
_EXPIRY = _NOW + timedelta(hours=2)


def _parent(
    actions: tuple[str, ...] = ("read", "write"),
    constraints: dict | None = None,
    expires_at: datetime | None = None,
) -> DelegationToken:
    token = DelegationToken(
        subject="alice",
        delegate="agent-a",
        audience="svc",
        authorized_actions=actions,
        constraints=constraints or {},
        session_id="sess-1",
        expires_at=expires_at or _EXPIRY,
    )
    return sign_delegation(token, _KEY)


def test_narrow_delegation_subset_actions():
    parent = _parent(actions=("read", "write", "delete"))
    child = narrow_delegation(parent, delegate="agent-b", authorized_actions=("read",))
    assert set(child.authorized_actions) == {"read"}
    assert child.delegate == "agent-b"
    assert child.subject == "alice"
    assert child.audience == "svc"


def test_narrow_delegation_inherits_parent_actions():
    parent = _parent(actions=("read", "write"))
    child = narrow_delegation(parent, delegate="agent-b")
    assert set(child.authorized_actions) == {"read", "write"}


def test_narrow_delegation_rejects_extra_actions():
    parent = _parent(actions=("read",))
    with pytest.raises(DelegationNarrowingViolation, match="not in parent"):
        narrow_delegation(parent, delegate="agent-b", authorized_actions=("read", "write"))


def test_narrow_delegation_empty_parent_actions_allows_any():
    """Empty parent authorized_actions means 'no restriction' so child can specify anything."""
    parent = _parent(actions=())
    child = narrow_delegation(parent, delegate="agent-b", authorized_actions=("read", "write"))
    assert set(child.authorized_actions) == {"read", "write"}


def test_narrow_delegation_rejects_later_expiry():
    parent = _parent(expires_at=_LATER)
    with pytest.raises(DelegationNarrowingViolation, match="expires_at"):
        narrow_delegation(parent, delegate="agent-b", expires_at=_EXPIRY)


def test_narrow_delegation_accepts_earlier_expiry():
    parent = _parent(expires_at=_EXPIRY)
    child = narrow_delegation(parent, delegate="agent-b", expires_at=_LATER)
    assert child.expires_at == _LATER


def test_narrow_delegation_accepts_equal_expiry():
    parent = _parent(expires_at=_EXPIRY)
    child = narrow_delegation(parent, delegate="agent-b", expires_at=_EXPIRY)
    assert child.expires_at == _EXPIRY


def test_narrow_delegation_rejects_higher_max_cost():
    parent = _parent(constraints={"max_cost_usd": 10.0})
    with pytest.raises(DelegationNarrowingViolation, match="max_cost_usd"):
        narrow_delegation(
            parent,
            delegate="agent-b",
            constraints={"max_cost_usd": 20.0},
        )


def test_narrow_delegation_accepts_lower_max_cost():
    parent = _parent(constraints={"max_cost_usd": 10.0})
    child = narrow_delegation(
        parent,
        delegate="agent-b",
        constraints={"max_cost_usd": 5.0},
    )
    assert child.constraints["max_cost_usd"] == 5.0


def test_narrow_delegation_read_only_is_sticky():
    parent = _parent(constraints={"read_only": True})
    child = narrow_delegation(
        parent,
        delegate="agent-b",
        constraints={},  # trying to drop read_only
    )
    assert child.constraints.get("read_only") is True


def test_narrow_delegation_read_only_not_added_by_default():
    """read_only should not appear in child unless parent has it."""
    parent = _parent(constraints={})
    child = narrow_delegation(parent, delegate="agent-b", constraints={})
    assert "read_only" not in child.constraints


def test_narrow_delegation_child_is_unsigned():
    parent = _parent()
    child = narrow_delegation(parent, delegate="agent-b")
    assert child.signature == ""


def test_narrow_delegation_preserves_session_id():
    parent = _parent()
    child = narrow_delegation(parent, delegate="agent-b", session_id="sess-child")
    assert child.session_id == "sess-child"


# ---------------------------------------------------------------------------
# LivenessChecker
# ---------------------------------------------------------------------------

def test_liveness_unknown_agent_is_dead():
    checker = LivenessChecker()
    assert not checker.is_alive("agent-x")


def test_liveness_heartbeat_makes_alive():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    assert checker.is_alive("agent-1")


def test_liveness_ttl_expiry():
    checker = LivenessChecker(ttl=timedelta(seconds=30))
    t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    checker.heartbeat("agent-1", at=t0)
    t_within = t0 + timedelta(seconds=29)
    t_after = t0 + timedelta(seconds=31)
    assert checker.is_alive("agent-1", at=t_within)
    assert not checker.is_alive("agent-1", at=t_after)


def test_liveness_suspend_overrides_heartbeat():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.suspend("agent-1")
    assert not checker.is_alive("agent-1")


def test_liveness_heartbeat_clears_suspension():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.suspend("agent-1")
    checker.heartbeat("agent-1")
    assert checker.is_alive("agent-1")


def test_liveness_revoke_removes_all_state():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.revoke("agent-1")
    assert not checker.is_alive("agent-1")


def test_liveness_revoke_clears_suspension():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.suspend("agent-1")
    checker.revoke("agent-1")
    # After revoke, suspension is gone; a new heartbeat makes it alive
    checker.heartbeat("agent-1")
    assert checker.is_alive("agent-1")


def test_liveness_revoke_nonexistent_agent_is_noop():
    checker = LivenessChecker()
    checker.revoke("ghost")  # should not raise


def test_liveness_state_alive():
    checker = LivenessChecker(ttl=timedelta(seconds=60))
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    checker.heartbeat("agent-1", at=t0)
    state = checker.state("agent-1", at=t0 + timedelta(seconds=10))
    assert isinstance(state, LivenessState)
    assert state.agent_id == "agent-1"
    assert state.alive is True
    assert state.suspended is False
    assert state.last_heartbeat == t0
    assert state.ttl_seconds == 60.0


def test_liveness_state_suspended():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.suspend("agent-1")
    state = checker.state("agent-1")
    assert state.alive is False
    assert state.suspended is True


def test_liveness_state_expired():
    checker = LivenessChecker(ttl=timedelta(seconds=10))
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    checker.heartbeat("agent-1", at=t0)
    state = checker.state("agent-1", at=t0 + timedelta(seconds=20))
    assert state.alive is False
    assert state.suspended is False
    assert state.last_heartbeat == t0


def test_liveness_state_unknown_agent():
    checker = LivenessChecker()
    state = checker.state("ghost")
    assert state.alive is False
    assert state.suspended is False
    assert state.last_heartbeat is None


def test_liveness_multiple_agents_isolated():
    checker = LivenessChecker()
    checker.heartbeat("agent-1")
    checker.suspend("agent-2")
    assert checker.is_alive("agent-1")
    assert not checker.is_alive("agent-2")
    assert not checker.is_alive("agent-3")
