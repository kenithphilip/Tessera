"""Tests for Wave 2I: WIMSE / draft-klrc-aiagent-auth alignment.

Covers:
- WIMSEIdentityClaim.from_workload_identity round-trip
- WorkloadIdentityToken sign + verify with an HMAC key
- OAuthTransactionToken wraps DelegationToken without changing canonical form
- WIMSEAdapter.fetch_workload_identity_token with a stub SPIRE client
- Extended DelegationToken fields default to empty and round-trip
- Old DelegationTokens (new fields at defaults) verify under new code
- New fields produce a different signature when non-empty
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from tessera.delegation import DelegationToken, sign_delegation, verify_delegation
from tessera.identity import (
    OAuthTransactionToken,
    WIMSEIdentityClaim,
    WorkloadIdentity,
    WorkloadIdentityToken,
)
from tessera.spire import SpireJWKSFetcher, SpireJWTSource, WIMSEAdapter
from tessera.taint.label import SecrecyLevel

KEY = b"wimse-test-key-not-for-production"

_NOW = datetime(2026, 4, 25, 12, 0, tzinfo=timezone.utc)
_EXPIRES = _NOW + timedelta(hours=1)

_WORKLOAD = WorkloadIdentity(
    spiffe_id="spiffe://example.org/ns/agents/svc/planner",
    trust_domain="example.org",
    issuer="https://spire.example.org",
    audience=("tessera",),
    tenant="acme",
    issued_at=_NOW,
    expires_at=_EXPIRES,
)

_DELEGATION_KEY = b"delegation-test-key-not-for-prod"


def _base_token(*, expires_at: datetime | None = None) -> DelegationToken:
    return DelegationToken(
        subject="user:alice@example.com",
        delegate="spiffe://example.org/ns/agents/svc/planner",
        audience="proxy://tessera",
        authorized_actions=("search", "summarize"),
        constraints={"max_cost_usd": 5},
        session_id="ses_abc",
        expires_at=expires_at or _NOW + timedelta(minutes=30),
    )


# ---------------------------------------------------------------------------
# WIMSEIdentityClaim
# ---------------------------------------------------------------------------


def test_wimse_claim_from_workload_identity_maps_fields():
    claim = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)

    assert claim.iss == "https://spire.example.org"
    assert claim.sub == "spiffe://example.org/ns/agents/svc/planner"
    assert claim.wimse_id == "spiffe://example.org/ns/agents/svc/planner"
    assert claim.aud == ("tessera",)
    assert claim.tenant == "acme"
    assert claim.created_at == _NOW
    assert claim.expires_at == _EXPIRES


def test_wimse_claim_round_trips_through_dict():
    original = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)
    restored = WIMSEIdentityClaim.from_dict(original.to_dict())

    assert restored.iss == original.iss
    assert restored.sub == original.sub
    assert restored.aud == original.aud
    assert restored.wimse_id == original.wimse_id
    assert restored.tenant == original.tenant
    assert restored.created_at == original.created_at
    assert restored.expires_at == original.expires_at


def test_wimse_claim_no_tenant():
    workload = replace(_WORKLOAD, tenant=None)
    claim = WIMSEIdentityClaim.from_workload_identity(workload)
    assert claim.tenant is None
    restored = WIMSEIdentityClaim.from_dict(claim.to_dict())
    assert restored.tenant is None


def test_wimse_claim_from_dict_raises_on_missing_field():
    bad = {"iss": "x", "sub": "y"}  # missing aud, wimse_id, iat, exp
    with pytest.raises(ValueError):
        WIMSEIdentityClaim.from_dict(bad)


# ---------------------------------------------------------------------------
# WorkloadIdentityToken
# ---------------------------------------------------------------------------


def test_wit_sign_and_verify_returns_claims():
    claims = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)
    token = WorkloadIdentityToken(claims=claims)
    signed = token.sign(KEY)

    assert signed.signature != ""
    recovered = signed.verify(KEY)
    assert recovered == claims


def test_wit_verify_wrong_key_raises():
    claims = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)
    signed = WorkloadIdentityToken(claims=claims).sign(KEY)

    with pytest.raises(ValueError, match="mismatch"):
        signed.verify(b"wrong-key")


def test_wit_verify_unsigned_raises():
    claims = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)
    unsigned = WorkloadIdentityToken(claims=claims)

    with pytest.raises(ValueError, match="no signature"):
        unsigned.verify(KEY)


def test_wit_is_frozen():
    claims = WIMSEIdentityClaim.from_workload_identity(_WORKLOAD)
    token = WorkloadIdentityToken(claims=claims).sign(KEY)
    with pytest.raises(Exception):
        token.signature = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# OAuthTransactionToken
# ---------------------------------------------------------------------------


def test_oauth_txn_token_wraps_delegation():
    base = _base_token()
    signed = sign_delegation(base, _DELEGATION_KEY)
    txn = OAuthTransactionToken(delegation=signed)
    claims = txn.to_txn_token_claims()

    assert claims["sub"] == signed.delegate
    assert claims["azp"] == signed.subject
    assert claims["aud"] == [signed.audience]
    assert "search" in claims["txn_token"]["authorized_actions"]


def test_oauth_txn_token_does_not_change_canonical_form():
    """Wrapping in OAuthTransactionToken must not touch DelegationToken.canonical()."""
    base = _base_token()
    canonical_before = base.canonical()
    _txn = OAuthTransactionToken(delegation=base)
    canonical_after = base.canonical()
    assert canonical_before == canonical_after


def test_oauth_txn_token_back_compat_signature():
    """The DelegationToken signature must survive the OAuthTransactionToken round-trip."""
    base = _base_token()
    signed = sign_delegation(base, _DELEGATION_KEY)
    _txn = OAuthTransactionToken(delegation=signed)
    # The original token must still verify.
    assert verify_delegation(signed, _DELEGATION_KEY, audience="proxy://tessera")


# ---------------------------------------------------------------------------
# WIMSEAdapter
# ---------------------------------------------------------------------------


def _make_adapter(audience: str = "tessera") -> WIMSEAdapter:
    jwt_source = MagicMock(spec=SpireJWTSource)
    jwks_fetcher = MagicMock(spec=SpireJWKSFetcher)
    return WIMSEAdapter(
        spiffe_id="spiffe://example.org/ns/agents/svc/planner",
        issuer="https://spire.example.org",
        jwt_source=jwt_source,
        jwks_fetcher=jwks_fetcher,
        hmac_key=KEY,
        tenant="acme",
    )


def test_wimse_adapter_fetch_returns_signed_token():
    adapter = _make_adapter()
    token = adapter.fetch_workload_identity_token(audience="resource-server")

    assert isinstance(token, WorkloadIdentityToken)
    assert token.signature != ""
    assert token.claims.sub == "spiffe://example.org/ns/agents/svc/planner"
    assert token.claims.aud == ("resource-server",)


def test_wimse_adapter_verify_returns_claims():
    adapter = _make_adapter()
    token = adapter.fetch_workload_identity_token(audience="resource-server")
    claims = adapter.verify_workload_identity_token(token)

    assert claims.wimse_id == "spiffe://example.org/ns/agents/svc/planner"
    assert claims.tenant == "acme"


def test_wimse_adapter_verify_tampered_token_raises():
    adapter = _make_adapter()
    token = adapter.fetch_workload_identity_token()
    bad_claims = replace(token.claims, sub="spiffe://attacker/evil")
    tampered = WorkloadIdentityToken(claims=bad_claims, signature=token.signature)

    with pytest.raises(ValueError):
        adapter.verify_workload_identity_token(tampered)


# ---------------------------------------------------------------------------
# DelegationToken: new WIMSE fields
# ---------------------------------------------------------------------------


def test_delegation_new_fields_default_to_empty():
    token = _base_token()
    assert token.mcp_audiences == frozenset()
    assert token.allowed_tools == frozenset()
    assert token.sensitivity_ceiling is None


def test_delegation_with_wimse_fields_signs_and_verifies():
    base = _base_token()
    extended = replace(
        base,
        mcp_audiences=frozenset({"mcp://files", "mcp://calendar"}),
        allowed_tools=frozenset({"read_file", "list_events"}),
        sensitivity_ceiling=SecrecyLevel.PRIVATE,
    )
    signed = sign_delegation(extended, _DELEGATION_KEY)
    assert verify_delegation(signed, _DELEGATION_KEY, audience="proxy://tessera")


def test_delegation_empty_wimse_fields_produce_same_canonical_as_old_token():
    """A token without the new fields must produce the same canonical bytes."""
    old_token = DelegationToken(
        subject="user:alice@example.com",
        delegate="spiffe://example.org/ns/agents/svc/planner",
        audience="proxy://tessera",
        authorized_actions=("search", "summarize"),
        constraints={"max_cost_usd": 5},
        session_id="ses_abc",
        expires_at=_NOW + timedelta(minutes=30),
    )
    new_token = replace(
        old_token,
        mcp_audiences=frozenset(),
        allowed_tools=frozenset(),
        sensitivity_ceiling=None,
    )
    assert old_token.canonical() == new_token.canonical()


def test_delegation_old_signature_verifies_under_new_code():
    """A token signed before Wave 2I verifies under the updated verify_delegation."""
    # Simulate a v0.12 token by constructing without the new fields.
    old_style = DelegationToken(
        subject="user:alice@example.com",
        delegate="spiffe://example.org/ns/agents/svc/planner",
        audience="proxy://tessera",
        authorized_actions=("search",),
        constraints={},
        session_id="ses_old",
        expires_at=_NOW + timedelta(minutes=10),
    )
    signed = sign_delegation(old_style, _DELEGATION_KEY)
    assert verify_delegation(signed, _DELEGATION_KEY, audience="proxy://tessera")


def test_delegation_non_empty_wimse_fields_differ_from_empty():
    """Tokens with non-default WIMSE fields must produce a different signature."""
    base = _base_token()
    signed_base = sign_delegation(base, _DELEGATION_KEY)

    extended = replace(base, mcp_audiences=frozenset({"mcp://files"}))
    signed_extended = sign_delegation(extended, _DELEGATION_KEY)

    assert signed_base.signature != signed_extended.signature


def test_delegation_sensitivity_ceiling_included_in_canonical():
    base = _base_token()
    with_ceiling = replace(base, sensitivity_ceiling=SecrecyLevel.INTERNAL)
    without_ceiling = replace(base, sensitivity_ceiling=None)

    assert with_ceiling.canonical() != without_ceiling.canonical()


def test_delegation_allowed_tools_sorted_canonically():
    """The canonical form must be identical regardless of frozenset iteration order."""
    a = replace(_base_token(), allowed_tools=frozenset({"z_tool", "a_tool"}))
    b = replace(_base_token(), allowed_tools=frozenset({"a_tool", "z_tool"}))
    assert a.canonical() == b.canonical()
