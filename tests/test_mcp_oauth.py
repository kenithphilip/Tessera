"""Tests for Wave 2C: RFC 8707 audience binding + per-MCP delegation."""

from __future__ import annotations

import pytest

from datetime import datetime, timedelta, timezone

from tessera.delegation import DelegationToken, sign_delegation, verify_delegation
from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)
from tessera.mcp.oauth import (
    mint_upstream_token_request,
    reject_token_passthrough,
    resource_metadata_document,
    token_audience_check,
    www_authenticate_challenge,
)
from tessera.taint.label import SecrecyLevel


_KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _capture_events() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


# --- token_audience_check ---------------------------------------------------


def test_audience_match_returns_valid() -> None:
    result = token_audience_check(
        "https://mesh.invalid/api",
        expected_resource="https://mesh.invalid/api",
    )
    assert bool(result) is True


def test_audience_match_with_list() -> None:
    result = token_audience_check(
        ["https://mesh.invalid/api", "https://other.invalid"],
        expected_resource="https://mesh.invalid/api",
    )
    assert bool(result) is True


def test_audience_mismatch_emits_event(_capture_events) -> None:
    result = token_audience_check(
        "https://other.invalid",
        expected_resource="https://mesh.invalid/api",
        principal="alice",
    )
    assert bool(result) is False
    events = [
        e
        for e in _capture_events
        if e.kind == EventKind.MCP_TOKEN_AUDIENCE_MISMATCH
    ]
    assert len(events) == 1
    assert events[0].detail["expected_resource"] == "https://mesh.invalid/api"


def test_audience_none_fails(_capture_events) -> None:
    result = token_audience_check(
        None, expected_resource="https://mesh.invalid/api"
    )
    assert bool(result) is False


# --- mint_upstream_token_request --------------------------------------------


def test_mint_upstream_token_request_includes_resource() -> None:
    body = mint_upstream_token_request(
        "https://upstream-mcp.invalid/api",
        scope="mcp.tools.invoke",
    )
    assert body["resource"] == "https://upstream-mcp.invalid/api"
    assert body["scope"] == "mcp.tools.invoke"
    assert body["grant_type"] == "client_credentials"


def test_mint_upstream_token_request_extra_params() -> None:
    body = mint_upstream_token_request(
        "https://upstream.invalid",
        audience="https://upstream.invalid/aud",
        extra={"correlation_id": "req-42"},
    )
    assert body["audience"] == "https://upstream.invalid/aud"
    assert body["correlation_id"] == "req-42"


# --- reject_token_passthrough -----------------------------------------------


def test_reject_passthrough_when_tokens_match(_capture_events) -> None:
    result = reject_token_passthrough(
        inbound_token="tok-abc",
        upstream_token="tok-abc",
        principal="alice",
    )
    assert bool(result) is False
    events = [
        e
        for e in _capture_events
        if e.kind == EventKind.MCP_TOKEN_AUDIENCE_MISMATCH
    ]
    assert any(e.detail.get("violation") == "token_passthrough" for e in events)


def test_passthrough_check_passes_when_tokens_differ() -> None:
    result = reject_token_passthrough(
        inbound_token="inbound", upstream_token="outbound"
    )
    assert bool(result) is True


def test_passthrough_check_passes_when_inbound_missing() -> None:
    result = reject_token_passthrough(
        inbound_token=None, upstream_token="outbound"
    )
    assert bool(result) is True


# --- Resource metadata + WWW-Authenticate -----------------------------------


def test_resource_metadata_document_shape() -> None:
    doc = resource_metadata_document(
        resource_indicator="https://mesh.invalid/api",
        authorization_servers=["https://auth.invalid"],
        scopes_supported=("mcp.tools.invoke", "mcp.tools.list"),
    )
    assert doc["resource"] == "https://mesh.invalid/api"
    assert doc["authorization_servers"] == ["https://auth.invalid"]
    assert "mcp.tools.invoke" in doc["scopes_supported"]


def test_www_authenticate_challenge_includes_metadata_url() -> None:
    header = www_authenticate_challenge(
        "https://mesh.invalid/.well-known/oauth-protected-resource"
    )
    assert header.startswith("Bearer ")
    assert "resource_metadata=" in header


# --- DelegationToken extension (Wave 2I) carries audiences ------------------


def test_delegation_with_mcp_audiences_round_trips() -> None:
    """Wave 2I extended DelegationToken with mcp_audiences /
    allowed_tools / sensitivity_ceiling. The 2C audience check
    pulls the active token's mcp_audiences to decide which
    upstream MCP servers it may target."""
    token = DelegationToken(
        subject="alice",
        delegate="agent-1",
        audience="https://mesh.invalid/api",
        authorized_actions=("send_email",),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        mcp_audiences=frozenset({"https://upstream-a.invalid"}),
        allowed_tools=frozenset({"send_email"}),
        sensitivity_ceiling=SecrecyLevel.PRIVATE,
    )
    signed = sign_delegation(token, _KEY)
    assert verify_delegation(signed, _KEY) is True
    assert "https://upstream-a.invalid" in signed.mcp_audiences
    assert signed.allowed_tools == frozenset({"send_email"})
    assert signed.sensitivity_ceiling == SecrecyLevel.PRIVATE


def test_delegation_without_new_fields_remains_back_compat() -> None:
    """Legacy DelegationToken (no new fields) MUST still
    round-trip identically. This is the v0.12 -> v0.13
    upgrade contract."""
    token = DelegationToken(
        subject="alice",
        delegate="agent-1",
        audience="https://mesh.invalid/api",
        authorized_actions=("send_email",),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    signed = sign_delegation(token, _KEY)
    assert verify_delegation(signed, _KEY) is True
    assert signed.subject == "alice"
    assert not signed.mcp_audiences
    assert not signed.allowed_tools
    assert signed.sensitivity_ceiling is None
