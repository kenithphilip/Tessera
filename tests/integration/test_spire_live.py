"""Live SPIRE Workload API integration tests.

These tests run against a real SPIRE server and agent. They require:
- SPIFFE_ENDPOINT_SOCKET pointing to a live agent socket
- Workload entries registered for the test runner UID
- The spiffe Python package installed

Skipped automatically when SPIFFE_ENDPOINT_SOCKET is not set.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("jwt")

from tessera.spire import SpireJWTSource, create_spire_identity_verifier

SOCKET = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
TRUST_DOMAIN = os.environ.get("TESSERA_SPIRE_TRUST_DOMAIN", "example.org")
AUDIENCE = f"spiffe://{TRUST_DOMAIN}/ci/proxy"


@pytest.fixture
def jwt_source() -> SpireJWTSource:
    return SpireJWTSource(socket_path=SOCKET)


def test_fetch_jwt_svid_returns_valid_token(jwt_source: SpireJWTSource) -> None:
    """Fetch a real JWT-SVID from the Workload API."""
    token = jwt_source.fetch_token(AUDIENCE)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3


def test_identity_headers_include_asm_header(jwt_source: SpireJWTSource) -> None:
    """ASM-Agent-Identity header is populated from live SVID."""
    headers = jwt_source.identity_headers(audience=AUDIENCE)
    assert "ASM-Agent-Identity" in headers


def test_svid_verifies_against_live_trust_bundles(jwt_source: SpireJWTSource) -> None:
    """Full round-trip: fetch SVID, build verifier from bundles, verify."""
    token = jwt_source.fetch_token(AUDIENCE)
    verifier = create_spire_identity_verifier(
        socket_path=SOCKET,
        expected_trust_domain=TRUST_DOMAIN,
    )
    identity = verifier.verify(token, audience=AUDIENCE)
    assert identity is not None
    assert TRUST_DOMAIN in identity.agent_id


def test_verified_identity_has_expected_trust_domain(jwt_source: SpireJWTSource) -> None:
    """The SPIFFE ID carries the configured trust domain."""
    token = jwt_source.fetch_token(AUDIENCE)
    verifier = create_spire_identity_verifier(
        socket_path=SOCKET,
        expected_trust_domain=TRUST_DOMAIN,
    )
    identity = verifier.verify(token, audience=AUDIENCE)
    assert identity.trust_domain == TRUST_DOMAIN
    assert identity.agent_id.startswith(f"spiffe://{TRUST_DOMAIN}/")
