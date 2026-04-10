"""Delegation token signing and verification."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from tessera.delegation import DelegationToken, sign_delegation, verify_delegation

KEY = b"test-hmac-key-do-not-use-in-prod"


def _token(*, expires_at: datetime | None = None) -> DelegationToken:
    return DelegationToken(
        subject="user:jane@example.com",
        delegate="spiffe://acme.ai/ns/assistants/agent/researcher/i/1234",
        audience="proxy://tessera",
        authorized_actions=("search", "summarize"),
        constraints={"max_cost_usd": 10, "requires_human_for": ["send_email"]},
        session_id="ses_123",
        expires_at=expires_at or datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def test_signed_delegation_round_trips():
    token = sign_delegation(_token(), KEY)
    assert verify_delegation(token, KEY, audience="proxy://tessera") is True


def test_wrong_key_fails_verification():
    token = sign_delegation(_token(), KEY)
    assert verify_delegation(token, b"other-key", audience="proxy://tessera") is False


def test_tampered_field_fails_verification():
    token = sign_delegation(_token(), KEY)
    tampered = replace(token, subject="user:bob@example.com")
    assert verify_delegation(tampered, KEY, audience="proxy://tessera") is False


def test_unsigned_token_fails_verification():
    assert verify_delegation(_token(), KEY, audience="proxy://tessera") is False


def test_audience_mismatch_fails_verification():
    token = sign_delegation(_token(), KEY)
    assert verify_delegation(token, KEY, audience="proxy://other") is False


def test_expired_token_fails_verification():
    expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    token = sign_delegation(_token(expires_at=expires_at), KEY)
    assert verify_delegation(token, KEY, audience="proxy://tessera") is False


def test_verification_uses_supplied_now_for_expiry_checks():
    issued = datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc)
    token = sign_delegation(_token(expires_at=issued + timedelta(minutes=1)), KEY)
    assert (
        verify_delegation(
            token,
            KEY,
            audience="proxy://tessera",
            now=issued + timedelta(seconds=30),
        )
        is True
    )
    assert (
        verify_delegation(
            token,
            KEY,
            audience="proxy://tessera",
            now=issued + timedelta(minutes=2),
        )
        is False
    )


def test_canonical_serialization_is_stable_for_constraint_key_order():
    left = DelegationToken(
        subject="user:jane@example.com",
        delegate="spiffe://acme.ai/ns/assistants/agent/researcher/i/1234",
        audience="proxy://tessera",
        authorized_actions=("summarize", "search"),
        constraints={"b": 2, "a": 1},
        session_id="ses_123",
        expires_at=datetime(2026, 4, 10, 12, 5, tzinfo=timezone.utc),
    )
    right = DelegationToken(
        subject="user:jane@example.com",
        delegate="spiffe://acme.ai/ns/assistants/agent/researcher/i/1234",
        audience="proxy://tessera",
        authorized_actions=("search", "summarize"),
        constraints={"a": 1, "b": 2},
        session_id="ses_123",
        expires_at=datetime(2026, 4, 10, 12, 5, tzinfo=timezone.utc),
    )

    assert left.canonical() == right.canonical()
