"""SPIRE Workload API adapters for live identity and trust bundles."""

from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from tessera.identity import JWTAgentIdentitySigner
from tessera.spire import (
    SpireJWKSFetcher,
    SpireJWTSource,
    create_spire_identity_verifier,
)


def _install_modern_spiffe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = "spire.jwt.svid",
    jwks: Any | None = None,
    socket_observer: list[str | None] | None = None,
) -> None:
    module = types.ModuleType("spiffe")

    class WorkloadApiClient:
        def __enter__(self) -> "WorkloadApiClient":
            if socket_observer is not None:
                socket_observer.append(sys.modules["os"].environ.get("SPIFFE_ENDPOINT_SOCKET"))
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def fetch_jwt_svid(
            self,
            audience: set[str] | tuple[str, ...],
            spiffe_id: str | None = None,
        ) -> Any:
            del audience, spiffe_id
            return types.SimpleNamespace(token=token)

        def fetch_jwt_bundles(self) -> Any:
            return jwks

    module.WorkloadApiClient = WorkloadApiClient
    monkeypatch.setitem(sys.modules, "spiffe", module)
    monkeypatch.delitem(sys.modules, "pyspiffe", raising=False)
    monkeypatch.delitem(sys.modules, "pyspiffe.workloadapi", raising=False)


def _install_legacy_pyspiffe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = "legacy.jwt.svid",
    jwks: Any | None = None,
) -> None:
    package = types.ModuleType("pyspiffe")
    workloadapi = types.ModuleType("pyspiffe.workloadapi")

    class LegacySource:
        def __enter__(self) -> "LegacySource":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def get_jwt_svid(
            self,
            audiences: list[str],
            spiffe_id: str | None = None,
        ) -> Any:
            del audiences, spiffe_id
            return types.SimpleNamespace(token=token)

        def get_jwt_bundle_set(self) -> Any:
            return jwks

    workloadapi.default_jwt_source = lambda: LegacySource()
    monkeypatch.setitem(sys.modules, "pyspiffe", package)
    monkeypatch.setitem(sys.modules, "pyspiffe.workloadapi", workloadapi)
    monkeypatch.delitem(sys.modules, "spiffe", raising=False)


def test_spire_jwt_source_fetches_live_token_from_modern_workload_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_socket: list[str | None] = []
    _install_modern_spiffe(monkeypatch, socket_observer=observed_socket)

    token = SpireJWTSource(
        socket_path="unix:///tmp/spire-agent-api/api.sock",
        spiffe_id="spiffe://example.org/ns/agents/sa/caller",
    ).fetch_token("proxy://tessera")

    assert token == "spire.jwt.svid"
    assert observed_socket == ["unix:///tmp/spire-agent-api/api.sock"]
    assert "SPIFFE_ENDPOINT_SOCKET" not in sys.modules["os"].environ


def test_spire_jwt_source_falls_back_to_legacy_pyspiffe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_legacy_pyspiffe(monkeypatch)

    token = SpireJWTSource().fetch_token("proxy://tessera")

    assert token == "legacy.jwt.svid"


def test_spire_jwks_fetcher_extracts_nested_bundle_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_bundles = types.SimpleNamespace(
        bundles={
            "example.org": types.SimpleNamespace(
                jwt_authorities=[
                    types.SimpleNamespace(
                        jwk={
                            "kty": "RSA",
                            "kid": "spire-key-1",
                            "n": "abc",
                            "e": "AQAB",
                        }
                    )
                ]
            )
        }
    )
    _install_modern_spiffe(monkeypatch, jwks=nested_bundles)

    jwks = SpireJWKSFetcher().fetch_jwks()

    assert jwks == {
        "keys": [
            {
                "kty": "RSA",
                "kid": "spire-key-1",
                "n": "abc",
                "e": "AQAB",
            }
        ]
    }


def test_create_spire_identity_verifier_uses_live_bundles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "spire-key-1"
    public_jwk["use"] = "sig"
    _install_modern_spiffe(monkeypatch, jwks={"keys": [public_jwk]})

    verifier = create_spire_identity_verifier(
        expected_issuer="spiffe://example.org",
        expected_trust_domain="example.org",
    )
    token = JWTAgentIdentitySigner(
        private_key=private_key,
        key_id="spire-key-1",
        issuer="spiffe://example.org",
    ).sign(
        agent_id="spiffe://example.org/ns/agents/sa/caller",
        audience="proxy://tessera",
        valid_until=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    identity = verifier.verify(token, audience="proxy://tessera")

    assert identity is not None
    assert identity.agent_id == "spiffe://example.org/ns/agents/sa/caller"


def test_spire_jwt_source_builds_identity_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_modern_spiffe(monkeypatch, token="header.jwt.svid")

    headers = SpireJWTSource().identity_headers(audience="proxy://tessera")

    assert headers == {"ASM-Agent-Identity": "header.jwt.svid"}
