"""Encrypted session persistence tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)
from tessera.labels import TrustLevel
from tessera.policy import Decision, DecisionKind
from tessera.sessions import PendingApproval, SessionStore, make_session_id


@pytest.fixture(autouse=True)
def _reset_sinks():
    clear_sinks()
    yield
    clear_sinks()


def _make_decision(tool: str = "deploy") -> Decision:
    return Decision(
        kind=DecisionKind.REQUIRE_APPROVAL,
        reason="tool requires human approval",
        tool=tool,
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.USER,
    )


def _make_approval(
    tool: str = "deploy",
    ttl: timedelta = timedelta(minutes=5),
    session_id: str | None = None,
) -> PendingApproval:
    now = datetime.now(timezone.utc)
    return PendingApproval(
        session_id=session_id or make_session_id(),
        tool=tool,
        principal="alice",
        decision=_make_decision(tool),
        context_summary="test context",
        created_at=now,
        expires_at=now + ttl,
    )


def _make_expired_approval(tool: str = "deploy") -> PendingApproval:
    now = datetime.now(timezone.utc)
    return PendingApproval(
        session_id=make_session_id(),
        tool=tool,
        principal="alice",
        decision=_make_decision(tool),
        context_summary="test context",
        created_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )


def test_store_and_retrieve():
    store = SessionStore()
    approval = _make_approval()
    sid = store.store(approval)
    retrieved = store.retrieve(sid)
    assert retrieved is not None
    assert retrieved.session_id == sid
    assert retrieved.tool == "deploy"
    assert retrieved.principal == "alice"
    assert retrieved.context_summary == "test context"


def test_retrieve_returns_none_for_unknown_id():
    store = SessionStore()
    assert store.retrieve("nonexistent-id") is None


def test_retrieve_returns_none_for_expired():
    store = SessionStore()
    expired = _make_expired_approval()
    store.store(expired)
    assert store.retrieve(expired.session_id) is None


def test_resolve_approved_returns_allow():
    store = SessionStore()
    approval = _make_approval()
    store.store(approval)
    decision = store.resolve(
        approval.session_id, approved=True, approver="bob", reason="lgtm",
    )
    assert decision.kind is DecisionKind.ALLOW
    assert "bob" in decision.reason
    assert "lgtm" in decision.reason


def test_resolve_denied_returns_deny():
    store = SessionStore()
    approval = _make_approval()
    store.store(approval)
    decision = store.resolve(
        approval.session_id, approved=False, approver="carol", reason="nope",
    )
    assert decision.kind is DecisionKind.DENY
    assert "carol" in decision.reason


def test_resolve_expired_fails_closed():
    store = SessionStore()
    expired = _make_expired_approval()
    store.store(expired)
    decision = store.resolve(
        expired.session_id, approved=True, approver="bob", reason="late",
    )
    assert decision.kind is DecisionKind.DENY
    assert "expired" in decision.reason


def test_resolve_removes_session():
    store = SessionStore()
    approval = _make_approval()
    store.store(approval)
    store.resolve(
        approval.session_id, approved=True, approver="bob",
    )
    assert store.retrieve(approval.session_id) is None


def test_expire_stale_removes_old_sessions():
    store = SessionStore()
    expired = _make_expired_approval()
    live = _make_approval()
    store.store(expired)
    store.store(live)
    assert len(store) == 2
    removed = store.expire_stale()
    assert removed == 1
    assert len(store) == 1
    assert store.retrieve(live.session_id) is not None


def test_encrypted_store_and_retrieve():
    key = b"test-encryption-key-32-bytes-ok!"
    store = SessionStore(encryption_key=key)
    approval = _make_approval()
    store.store(approval)
    retrieved = store.retrieve(approval.session_id)
    assert retrieved is not None
    assert retrieved.session_id == approval.session_id
    assert retrieved.tool == "deploy"
    assert retrieved.principal == "alice"


def test_len_reflects_active_count():
    store = SessionStore()
    assert len(store) == 0
    a1 = _make_approval(tool="t1")
    a2 = _make_approval(tool="t2")
    store.store(a1)
    assert len(store) == 1
    store.store(a2)
    assert len(store) == 2
    store.resolve(a1.session_id, approved=True, approver="x")
    assert len(store) == 1


def test_store_generates_unique_session_ids():
    a1 = _make_approval()
    a2 = _make_approval()
    assert a1.session_id != a2.session_id


def test_session_expired_event_fires():
    events: list[SecurityEvent] = []
    register_sink(events.append)

    store = SessionStore()
    expired = _make_expired_approval()
    store.store(expired)
    store.expire_stale()

    session_events = [e for e in events if e.kind == EventKind.SESSION_EXPIRED]
    assert len(session_events) == 1
    assert session_events[0].detail["session_id"] == expired.session_id


def test_resolve_unknown_session_fails_closed():
    store = SessionStore()
    decision = store.resolve(
        "does-not-exist", approved=True, approver="bob",
    )
    assert decision.kind is DecisionKind.DENY
    assert "not found" in decision.reason
