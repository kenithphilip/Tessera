"""Phase 1A audit gap 6: pin the frozen MCP manifest schema shape.

The schema in :mod:`tessera.mcp.manifest_schema` is the wire
format Phase 2 wave 2B-i signing work targets. A schema change
breaks every signed manifest in flight or at rest. These tests
pin the load-bearing constants so any drift surfaces in CI.

The full schema's structure is exercised by
:mod:`tests.test_mcp_manifest_signing`; this file pins only the
top-level invariants the signing surface depends on.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tessera.mcp.manifest_schema import (
    MCP_MANIFEST_STATEMENT_SCHEMA,
    PREDICATE_TYPE,
    STATEMENT_TYPE,
)


# --- Schema constant freeze -------------------------------------------------


def test_predicate_type_is_v1() -> None:
    """The predicate URI MUST stay tessera.dev/mcp-manifest/v1.
    Bumping it requires a new schema document, not an in-place
    edit; downstream consumers key on this string."""
    assert PREDICATE_TYPE == "https://tessera.dev/mcp-manifest/v1"


def test_statement_type_is_in_toto_v1() -> None:
    """STATEMENT_TYPE MUST be the in-toto Statement v1 URI; this
    is the in-toto contract every Sigstore consumer expects."""
    assert STATEMENT_TYPE == "https://in-toto.io/Statement/v1"


def test_schema_top_level_required_fields() -> None:
    schema = MCP_MANIFEST_STATEMENT_SCHEMA
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    required = set(schema.get("required", ()))
    # The four in-toto Statement v1 required fields.
    assert {"_type", "subject", "predicateType", "predicate"} <= required


def test_schema_predicate_block_required_fields() -> None:
    """The predicate block MUST require the load-bearing fields
    that Tessera signing depends on."""
    predicate = MCP_MANIFEST_STATEMENT_SCHEMA["properties"]["predicate"]
    required = set(predicate.get("required", ()))
    expected = {
        "serverUri",
        "issuer",
        "issuedAt",
        "tools",
        "resourceIndicator",
        "tesseraTrustTier",
    }
    assert expected <= required, f"missing required fields: {expected - required}"


def test_schema_subject_uses_sha256_digest() -> None:
    """Subject digests MUST use sha256 with the canonical hex shape."""
    subj = MCP_MANIFEST_STATEMENT_SCHEMA["properties"]["subject"]["items"]
    digest_props = subj["properties"]["digest"]["properties"]
    assert "sha256" in digest_props
    assert "pattern" in digest_props["sha256"]
    # 64 hex chars.
    assert "[0-9a-f]{64}" in digest_props["sha256"]["pattern"]


def test_schema_tools_use_three_digest_fields() -> None:
    """Per-tool entries MUST carry descriptionDigest +
    inputSchemaDigest + outputSchemaDigest. The Tessera sigstore
    flow checks all three before assigning a trust tier."""
    tools = MCP_MANIFEST_STATEMENT_SCHEMA["properties"]["predicate"][
        "properties"
    ]["tools"]
    item = tools["items"]
    required = set(item.get("required", ()))
    assert {
        "descriptionDigest",
        "inputSchemaDigest",
        "outputSchemaDigest",
    } <= required


def test_schema_sep1913_annotations_block_present() -> None:
    """Per-tool annotations MUST follow the SEP-1913 shape that
    Wave 2B-iii's MCP Security Score consumes (actionImpact,
    sensitiveHint, privateHint, openWorldHint, dataClass)."""
    annotations_def = (
        MCP_MANIFEST_STATEMENT_SCHEMA["definitions"]["sep1913Annotations"]
    )
    keys = set(annotations_def["properties"].keys())
    expected = {
        "actionImpact",
        "sensitiveHint",
        "privateHint",
        "openWorldHint",
        "dataClass",
    }
    assert expected <= keys


def test_schema_validates_a_real_statement() -> None:
    """Round-trip: build a minimal conforming Statement and
    verify it passes the schema's own validator."""
    pytest.importorskip("jsonschema")
    from jsonschema import validate

    sample: dict[str, Any] = {
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
    validate(instance=sample, schema=MCP_MANIFEST_STATEMENT_SCHEMA)


def test_schema_serializes_deterministically() -> None:
    """The schema must serialize to canonical JSON (stable key
    order). Cross-language consumers (Rust workspace in Phase 4)
    re-derive the schema id from a hash of the canonical form."""
    a = json.dumps(
        MCP_MANIFEST_STATEMENT_SCHEMA, sort_keys=True, separators=(",", ":")
    )
    b = json.dumps(
        MCP_MANIFEST_STATEMENT_SCHEMA, sort_keys=True, separators=(",", ":")
    )
    assert a == b
