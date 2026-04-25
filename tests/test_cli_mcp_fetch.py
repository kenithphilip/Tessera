"""Tests for the `tessera mcp fetch` CLI (Wave 2B-ii audit gap 7)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tessera.cli import main as cli_main
from tessera.mcp.manifest import SigningMethod, sign
from tessera.mcp.manifest_schema import PREDICATE_TYPE, STATEMENT_TYPE


_KEY = b"k" * 32


def _good_statement() -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "ghcr.io/example/mcp",
                "digest": {"sha256": "a" * 64},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "serverUri": "mcp+ws://example.invalid",
            "issuer": "https://github.com/example/mcp",
            "issuedAt": "2026-04-25T00:00:00Z",
            "resourceIndicator": "https://example.invalid/mcp",
            "tesseraTrustTier": "verified",
            "tools": [
                {
                    "name": "ping",
                    "descriptionDigest": "sha256:" + "b" * 64,
                    "inputSchemaDigest": "sha256:" + "c" * 64,
                    "outputSchemaDigest": "sha256:" + "d" * 64,
                    "annotations": {
                        "actionImpact": "benign",
                        "openWorldHint": False,
                    },
                }
            ],
        },
    }


@pytest.fixture
def signed_envelope_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Patch httpx.get to return a stub envelope; use a synthetic URL."""
    manifest = sign(_good_statement(), method=SigningMethod.HMAC, hmac_key=_KEY)
    envelope = manifest.to_envelope()

    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return envelope

    def _fake_get(url: str, timeout: float = 0.0):
        return _Resp()

    import httpx

    monkeypatch.setattr(httpx, "get", _fake_get)
    return "https://registry.invalid/manifest.json"


def test_mcp_fetch_returns_zero_at_default_tier(
    signed_envelope_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli_main([
        "mcp",
        "fetch",
        signed_envelope_url,
        "--hmac-key",
        _KEY.hex(),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    body = json.loads(out)
    assert body["verification"]["allowed"] is True
    assert body["verification"]["tier"] == "COMMUNITY"


def test_mcp_fetch_denies_when_min_tier_above_assigned(
    signed_envelope_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """HMAC envelopes are COMMUNITY-tier in production; --min-tier=verified
    must fail."""
    rc = cli_main([
        "mcp",
        "fetch",
        signed_envelope_url,
        "--hmac-key",
        _KEY.hex(),
        "--min-tier",
        "verified",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    body = json.loads(err)
    assert body["allowed"] is False
    assert body["min_tier"] == "VERIFIED"


def test_mcp_fetch_allow_unverified_returns_zero_anyway(
    signed_envelope_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli_main([
        "mcp",
        "fetch",
        signed_envelope_url,
        "--hmac-key",
        _KEY.hex(),
        "--min-tier",
        "verified",
        "--allow-unverified",
    ])
    assert rc == 0


def test_mcp_fetch_transport_failure_exits_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import httpx

    def _boom(url: str, timeout: float = 0.0):
        raise httpx.ConnectError("synthetic")

    monkeypatch.setattr(httpx, "get", _boom)
    rc = cli_main(["mcp", "fetch", "https://nope.invalid"])
    assert rc == 3
