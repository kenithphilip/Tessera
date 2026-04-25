"""Tests for tessera.mcp.registry_mirror (Wave 4D).

All signing uses HMAC so no Sigstore network call is made. The test
upstream is served by a monkeypatched httpx.get.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tessera.mcp.manifest import SigningMethod, sign
from tessera.mcp.manifest_schema import PREDICATE_TYPE, STATEMENT_TYPE
from tessera.mcp.registry_mirror import (
    MirrorEntry,
    MirrorManifest,
    RegistryMirror,
    _SCHEMA_VERSION,
    _derive_mirror_tag,
)


_KEY = b"m" * 32


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _minimal_statement(server_uri: str = "mcp+ws://example.invalid") -> dict[str, Any]:
    digest = "a" * 64
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": server_uri, "digest": {"sha256": digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "serverUri": server_uri,
            "issuer": "https://tessera.dev/mirror",
            "issuedAt": "2026-04-25T02:00:00Z",
            "resourceIndicator": "https://example.invalid/mcp",
            "tesseraTrustTier": "community",
            "tools": [],
        },
    }


def _upstream_dsse_envelope(server_uri: str = "mcp+ws://example.invalid") -> dict[str, Any]:
    """Return a pre-signed DSSE envelope as upstream would serve it."""
    stmt = _minimal_statement(server_uri)
    signed = sign(stmt, method=SigningMethod.HMAC, hmac_key=_KEY)
    return signed.to_envelope()


def _upstream_bare(server_uri: str = "mcp+ws://other.invalid") -> dict[str, Any]:
    """Return a bare upstream record (no DSSE wrapper)."""
    return {
        "serverUri": server_uri,
        "issuer": "https://other.invalid",
        "issuedAt": "2026-04-25T02:00:00Z",
        "resourceIndicator": "https://other.invalid/mcp",
        "tesseraTrustTier": "community",
        "tools": [],
    }


@pytest.fixture
def mirror(tmp_path: Path) -> RegistryMirror:
    return RegistryMirror(
        upstream_url="https://registry.example.invalid",
        hmac_key=_KEY,
        output_dir=tmp_path / "out",
    )


# ---------------------------------------------------------------------------
# MirrorEntry / MirrorManifest round-trip
# ---------------------------------------------------------------------------


def test_mirror_entry_fields() -> None:
    entry = MirrorEntry(
        source_url="https://registry.example.invalid",
        server_uri="mcp+ws://example.invalid",
        manifest_digest_sha256="a" * 64,
        sigstore_envelope_path="envelopes/sometag.json",
        mirror_tag="sometag",
        mirrored_at="2026-04-25T02:00:00Z",
    )
    assert entry.source_url == "https://registry.example.invalid"
    assert entry.mirror_tag == "sometag"


def test_mirror_manifest_round_trip() -> None:
    entry = MirrorEntry(
        source_url="https://registry.example.invalid",
        server_uri="mcp+ws://example.invalid",
        manifest_digest_sha256="b" * 64,
        sigstore_envelope_path="envelopes/tag123.json",
        mirror_tag="tag123",
        mirrored_at="2026-04-25T02:00:00Z",
    )
    original = MirrorManifest(
        schema_version=_SCHEMA_VERSION,
        generated_at="2026-04-25T02:00:00Z",
        entries=(entry,),
        upstream_registry_url="https://registry.example.invalid",
        mirror_signing_identity="tessera-mirror-hmac-v1",
    )
    data = original.to_dict()
    restored = MirrorManifest.from_dict(data)

    assert restored.schema_version == _SCHEMA_VERSION
    assert restored.upstream_registry_url == original.upstream_registry_url
    assert restored.mirror_signing_identity == original.mirror_signing_identity
    assert len(restored.entries) == 1
    assert restored.entries[0].mirror_tag == "tag123"


def test_mirror_manifest_from_dict_wrong_schema_version() -> None:
    data = {
        "schema_version": "bad.version",
        "generated_at": "2026-04-25T02:00:00Z",
        "entries": [],
        "upstream_registry_url": "https://x.invalid",
        "mirror_signing_identity": "test",
    }
    with pytest.raises(ValueError, match="unsupported schema_version"):
        MirrorManifest.from_dict(data)


def test_mirror_manifest_json_file_round_trip(tmp_path: Path) -> None:
    manifest = MirrorManifest(
        schema_version=_SCHEMA_VERSION,
        generated_at="2026-04-25T02:00:00Z",
        entries=(),
        upstream_registry_url="https://registry.example.invalid",
        mirror_signing_identity="tessera-mirror-hmac-v1",
    )
    path = tmp_path / "mirror-manifest.json"
    path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    restored = MirrorManifest.from_dict(json.loads(path.read_text()))
    assert restored == manifest


# ---------------------------------------------------------------------------
# re_sign
# ---------------------------------------------------------------------------


def test_re_sign_dsse_envelope(mirror: RegistryMirror) -> None:
    """re_sign on a pre-signed DSSE envelope produces a valid SignedManifest."""
    upstream = _upstream_dsse_envelope()
    result = mirror.re_sign(upstream)
    assert result.method == SigningMethod.HMAC
    server = result.statement["predicate"]["serverUri"]
    assert server == "mcp+ws://example.invalid"


def test_re_sign_bare_record(mirror: RegistryMirror) -> None:
    """re_sign on a bare upstream record synthesises a valid Statement."""
    upstream = _upstream_bare()
    result = mirror.re_sign(upstream)
    assert result.method == SigningMethod.HMAC
    assert result.statement["predicate"]["serverUri"] == "mcp+ws://other.invalid"


def test_re_sign_invalid_upstream(mirror: RegistryMirror) -> None:
    with pytest.raises(ValueError):
        mirror.re_sign({})


# ---------------------------------------------------------------------------
# mirror_all
# ---------------------------------------------------------------------------


def _make_stub_response(payloads: list[dict[str, Any]]) -> MagicMock:
    stub = MagicMock()
    stub.status_code = 200
    stub.json.return_value = payloads
    stub.raise_for_status.return_value = None
    return stub


def test_mirror_all_entry_count(mirror: RegistryMirror) -> None:
    """mirror_all returns a MirrorManifest with one entry per valid upstream."""
    upstreams = [
        _upstream_dsse_envelope("mcp+ws://server-a.invalid"),
        _upstream_dsse_envelope("mcp+ws://server-b.invalid"),
    ]
    with patch("tessera.mcp.registry_mirror.httpx.get", return_value=_make_stub_response(upstreams)):
        result = mirror.mirror_all()

    assert result.schema_version == _SCHEMA_VERSION
    assert len(result.entries) == 2
    server_uris = {e.server_uri for e in result.entries}
    assert "mcp+ws://server-a.invalid" in server_uris
    assert "mcp+ws://server-b.invalid" in server_uris


def test_mirror_all_skips_invalid_entries(mirror: RegistryMirror) -> None:
    """Invalid upstream entries are skipped; valid ones still produce entries."""
    upstreams = [
        {"bad": "entry"},  # no serverUri; will be skipped
        _upstream_dsse_envelope("mcp+ws://good.invalid"),
    ]
    with patch("tessera.mcp.registry_mirror.httpx.get", return_value=_make_stub_response(upstreams)):
        result = mirror.mirror_all()

    assert len(result.entries) == 1
    assert result.entries[0].server_uri == "mcp+ws://good.invalid"


def test_mirror_all_writes_manifest_file(mirror: RegistryMirror) -> None:
    upstreams = [_upstream_bare("mcp+ws://bare.invalid")]
    with patch("tessera.mcp.registry_mirror.httpx.get", return_value=_make_stub_response(upstreams)):
        mirror.mirror_all()

    manifest_path = mirror.manifest_path()
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text())
    assert data["schema_version"] == _SCHEMA_VERSION
    assert len(data["entries"]) == 1


def test_mirror_all_writes_envelope_files(mirror: RegistryMirror) -> None:
    upstreams = [_upstream_dsse_envelope("mcp+ws://env.invalid")]
    with patch("tessera.mcp.registry_mirror.httpx.get", return_value=_make_stub_response(upstreams)):
        result = mirror.mirror_all()

    entry = result.entries[0]
    envelope_path = mirror._output_dir / entry.sigstore_envelope_path
    assert envelope_path.exists()
    envelope = json.loads(envelope_path.read_text())
    assert envelope["payloadType"] == "application/vnd.in-toto+json"


def test_mirror_all_writes_oci_layout(mirror: RegistryMirror) -> None:
    upstreams = [_upstream_dsse_envelope("mcp+ws://oci.invalid")]
    with patch("tessera.mcp.registry_mirror.httpx.get", return_value=_make_stub_response(upstreams)):
        result = mirror.mirror_all()

    entry = result.entries[0]
    oci_dir = mirror._output_dir / "oci" / entry.mirror_tag
    assert (oci_dir / "index.json").exists()
    assert (oci_dir / "oci-layout").exists()


# ---------------------------------------------------------------------------
# CLI: mirror status reads back the manifest
# ---------------------------------------------------------------------------


def test_cli_mirror_status(tmp_path: Path) -> None:
    """CLI status command reads back and prints a MirrorManifest correctly."""
    from tessera.cli import main as cli_main

    entry = MirrorEntry(
        source_url="https://registry.example.invalid",
        server_uri="mcp+ws://example.invalid",
        manifest_digest_sha256="c" * 64,
        sigstore_envelope_path="envelopes/thetag.json",
        mirror_tag="thetag",
        mirrored_at="2026-04-25T02:00:00Z",
    )
    manifest = MirrorManifest(
        schema_version=_SCHEMA_VERSION,
        generated_at="2026-04-25T02:00:00Z",
        entries=(entry,),
        upstream_registry_url="https://registry.example.invalid",
        mirror_signing_identity="tessera-mirror-hmac-v1",
    )
    (tmp_path / "mirror-manifest.json").write_text(
        json.dumps(manifest.to_dict()), encoding="utf-8"
    )

    rc = cli_main(["mcp", "mirror", "status", "--out", str(tmp_path)])
    assert rc == 0


def test_cli_mirror_status_missing_file(tmp_path: Path) -> None:
    from tessera.cli import main as cli_main

    rc = cli_main(["mcp", "mirror", "status", "--out", str(tmp_path)])
    assert rc == 2


def test_cli_mirror_help() -> None:
    from tessera.cli import main as cli_main

    with pytest.raises(SystemExit) as exc_info:
        cli_main(["mcp", "mirror", "--help"])
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Tag derivation
# ---------------------------------------------------------------------------


def test_derive_mirror_tag_stable() -> None:
    tag = _derive_mirror_tag("mcp+ws://example.invalid")
    assert tag == _derive_mirror_tag("mcp+ws://example.invalid")


def test_derive_mirror_tag_oci_legal() -> None:
    import re

    tag = _derive_mirror_tag("mcp+ws://example.invalid:8080/path")
    assert re.match(r"^[a-zA-Z0-9_.\-]+$", tag), f"tag {tag!r} is not OCI-legal"
    assert len(tag) <= 128
