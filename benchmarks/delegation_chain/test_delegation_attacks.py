"""Delegation chain attack scenarios.

Each test sets up a delegation chain where agent B is given a scoped
token and then attempts to exceed its authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tessera.context import Context, make_segment
from tessera.delegation import DelegationToken, sign_delegation, verify_delegation
from tessera.labels import Origin, TrustLevel
from tessera.policy import DecisionKind, Policy

KEY = b"delegation-bench-key-0123456789a"


def _token(subject: str, delegate: str, actions: tuple[str, ...]) -> DelegationToken:
    """Create and sign a delegation token."""
    token = DelegationToken(
        subject=subject,
        delegate=delegate,
        audience="bench",
        authorized_actions=actions,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    return sign_delegation(token, KEY)


def _build_policy() -> Policy:
    policy = Policy()
    policy.require("send_email", TrustLevel.USER)
    policy.require("send_money", TrustLevel.USER)
    policy.require("read_file", TrustLevel.USER, side_effects=False)
    policy.require("delete_file", TrustLevel.USER)
    return policy


class TestDelegationScopeEnforcement:
    """Agent B receives a scoped delegation token and tries to exceed it."""

    def test_delegated_tool_within_scope_allowed(self) -> None:
        """Agent B calls a tool within the delegated scope."""
        token = _token("alice", "agent_b", ("read_file",))
        ctx = Context()
        ctx.add(make_segment("read file report.txt", Origin.USER, "alice", KEY))

        policy = _build_policy()
        decision = policy.evaluate(
            ctx, "read_file",
            delegation=token,
            expected_delegate="agent_b",
        )
        assert decision.kind == DecisionKind.ALLOW

    def test_delegated_tool_outside_scope_denied(self) -> None:
        """Agent B calls send_money with a read_file-only delegation token."""
        token = _token("alice", "agent_b", ("read_file",))
        ctx = Context()
        ctx.add(make_segment("read the report", Origin.USER, "alice", KEY))

        policy = _build_policy()
        decision = policy.evaluate(
            ctx, "send_money",
            delegation=token,
            expected_delegate="agent_b",
        )
        assert decision.kind == DecisionKind.DENY
        assert "delegation" in decision.reason.lower() or "action" in decision.reason.lower()

    def test_wrong_delegate_identity_denied(self) -> None:
        """Agent C uses a token issued to agent B."""
        token = _token("alice", "agent_b", ("read_file",))
        ctx = Context()
        ctx.add(make_segment("read report", Origin.USER, "alice", KEY))

        policy = _build_policy()
        decision = policy.evaluate(
            ctx, "read_file",
            delegation=token,
            expected_delegate="agent_c",  # wrong identity
        )
        assert decision.kind == DecisionKind.DENY

    def test_chain_delegation_scopes_narrow(self) -> None:
        """Delegation A->B->C: C's scope is the narrower B->C token."""
        # A delegates read_file + send_email to B
        _token_ab = _token("alice", "agent_b", ("read_file", "send_email"))
        # B delegates to C with narrower scope
        token_bc = _token("agent_b", "agent_c", ("read_file",))

        ctx = Context()
        ctx.add(make_segment("read the report", Origin.USER, "alice", KEY))

        policy = _build_policy()
        # C can read_file via B's scoped token
        decision = policy.evaluate(
            ctx, "read_file",
            delegation=token_bc,
            expected_delegate="agent_c",
        )
        assert decision.kind == DecisionKind.ALLOW

        # C cannot send_email (B didn't delegate that to C)
        decision = policy.evaluate(
            ctx, "send_email",
            delegation=token_bc,
            expected_delegate="agent_c",
        )
        assert decision.kind == DecisionKind.DENY
