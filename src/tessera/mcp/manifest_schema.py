"""Frozen JSON-Schema for in-toto signed MCP tool manifests.

The schema this module defines is the **wire format** that
Phase 2 wave 2B-i (Sigstore + in-toto signing) will produce and
verify. Freezing the schema here in Phase 1 wave 1A means:

- Phase 2 signing work has a fixed target.
- Phase 0 wave 0D's SEP-1913 working-group engagement can cite a
  concrete reference implementation when discussing
  ``manifestDigest`` requirements.
- Cross-language interop with the Rust workspace
  (``tessera-policy::mcp::manifest`` in Phase 4 wave 4B) has a
  schema both sides validate against.

The schema is an in-toto Statement v1 wrapping a Tessera-specific
predicate (``predicateType: https://tessera.dev/mcp-manifest/v1``).
The signing envelope is DSSE; signatures use Sigstore Fulcio
(short-lived OIDC-bound certs) with Rekor inclusion proofs. The
schema below validates only the Statement; signing-envelope
validation lives in Phase 2 wave 2B-i.

References
----------

- in-toto Statement v1: https://in-toto.io/Statement/v1
- DSSE: https://github.com/secure-systems-lab/dsse
- Sigstore: https://docs.sigstore.dev/
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.3
"""

from __future__ import annotations

#: Predicate type URI. Anyone consuming a Tessera-signed MCP
#: manifest validates this string before trusting the predicate
#: payload, per the in-toto Statement contract.
PREDICATE_TYPE = "https://tessera.dev/mcp-manifest/v1"

#: Statement type URI from in-toto.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: JSON-Schema (draft-07) for the in-toto Statement Tessera signs.
#: Stored as a Python dict literal so ``import tessera.mcp.manifest_schema``
#: gives callers immediate access without a file read.
MCP_MANIFEST_STATEMENT_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://tessera.dev/schemas/mcp-manifest-statement/v1.json",
    "title": "Tessera Signed MCP Manifest Statement",
    "description": (
        "in-toto Statement v1 wrapping a Tessera MCP manifest "
        "predicate. The Statement is the payload of a DSSE envelope "
        "signed via Sigstore Fulcio with a Rekor inclusion proof. "
        "Frozen 2026-04-24 under Tessera v0.12 plan Phase 1 wave 1A."
    ),
    "type": "object",
    "required": ["_type", "subject", "predicateType", "predicate"],
    "additionalProperties": False,
    "properties": {
        "_type": {
            "type": "string",
            "const": STATEMENT_TYPE,
            "description": "in-toto Statement v1 type URI.",
        },
        "subject": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "digest"],
                "additionalProperties": False,
                "properties": {
                    "name": {
                        "type": "string",
                        "description": (
                            "Subject identifier. For an MCP manifest, "
                            "the canonical URI of the manifest "
                            "(e.g., 'mcp://gmail.example.com/manifest')."
                        ),
                    },
                    "digest": {
                        "type": "object",
                        "minProperties": 1,
                        "additionalProperties": {"type": "string"},
                        "description": (
                            "Map of digest algorithm to lowercase hex "
                            "value. SHA-256 is required; other "
                            "algorithms (SHA-512, etc.) MAY appear."
                        ),
                        "required": ["sha256"],
                        "properties": {
                            "sha256": {
                                "type": "string",
                                "pattern": "^[0-9a-f]{64}$",
                            }
                        },
                    },
                },
            },
        },
        "predicateType": {
            "type": "string",
            "const": PREDICATE_TYPE,
            "description": "Tessera MCP manifest predicate type URI.",
        },
        "predicate": {
            "type": "object",
            "required": [
                "serverUri",
                "issuer",
                "issuedAt",
                "tools",
                "resourceIndicator",
                "tesseraTrustTier",
            ],
            "additionalProperties": False,
            "properties": {
                "serverUri": {
                    "type": "string",
                    "format": "uri",
                    "description": "MCP server canonical URI.",
                },
                "issuer": {
                    "type": "string",
                    "format": "uri",
                    "description": (
                        "Identity that signed this manifest. The "
                        "Sigstore Fulcio cert's OIDC subject MUST "
                        "match this URI."
                    ),
                },
                "issuedAt": {
                    "type": "string",
                    "format": "date-time",
                    "description": (
                        "RFC 3339 timestamp. Used for staleness "
                        "checks; a manifest more than 90 days old "
                        "warns at verification time."
                    ),
                },
                "tools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "name",
                            "descriptionDigest",
                            "inputSchemaDigest",
                            "outputSchemaDigest",
                            "annotations",
                        ],
                        "additionalProperties": False,
                        "properties": {
                            "name": {"type": "string"},
                            "descriptionDigest": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                            },
                            "inputSchemaDigest": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                            },
                            "outputSchemaDigest": {
                                "type": "string",
                                "pattern": "^sha256:[0-9a-f]{64}$",
                            },
                            "annotations": {
                                "$ref": "#/definitions/sep1913Annotations"
                            },
                        },
                    },
                },
                "resourceIndicator": {
                    "type": "string",
                    "format": "uri",
                    "description": (
                        "RFC 8707 resource indicator. Tokens minted "
                        "for this MCP server MUST carry this URI in "
                        "their `aud` claim."
                    ),
                },
                "tesseraTrustTier": {
                    "type": "string",
                    "enum": ["community", "verified", "attested"],
                    "description": (
                        "Self-asserted trust tier. Verified at runtime "
                        "by Tessera per Phase 2 wave 2B-ii: Community "
                        "is the default; Verified requires a valid "
                        "Sigstore signature; Attested requires "
                        "Verified plus SLSA Provenance v1.0 L>=2 "
                        "attestation on the server binary."
                    ),
                },
            },
        },
    },
    "definitions": {
        "sep1913Annotations": {
            "type": "object",
            "description": (
                "MCP SEP-1913 trust annotations carried per tool. "
                "Wire-compatible with PR #1913 (open as of 2026-04-24); "
                "Tessera consumes additional fields the SEP draft does "
                "not yet require so the Tessera shape is a SUPERSET of "
                "SEP-1913. See "
                "docs/standards-engagement/sep-1913-comments.md."
            ),
            "additionalProperties": True,
            "properties": {
                "actionImpact": {
                    "type": "string",
                    "enum": ["benign", "side-effect", "destructive"],
                    "description": (
                        "How impactful invoking this tool is. Maps to "
                        "the action critic risk_class for circuit "
                        "breaker fail-mode in Phase 2 wave 2A."
                    ),
                },
                "sensitiveHint": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "FIDES secrecy seed.",
                },
                "privateHint": {
                    "type": "boolean",
                    "description": (
                        "Tool returns private content. Equivalent to "
                        "sensitiveHint >= 'high' but carried as a "
                        "separate boolean for SEP-1913 monotonicity."
                    ),
                },
                "openWorldHint": {
                    "type": "boolean",
                    "description": (
                        "Tool may inject untrusted bytes (web, email, "
                        "user-controlled MCP content). Sets initial "
                        "ProvenanceLabel.integrity = UNTRUSTED."
                    ),
                },
                "dataClass": {
                    "type": "string",
                    "enum": [
                        "public",
                        "internal",
                        "confidential",
                        "regulated:gdpr",
                        "regulated:hipaa",
                        "regulated:pci-dss",
                        "regulated:sox",
                        "regulated:cui",
                    ],
                    "description": (
                        "Optional. Carries a fixed-vocabulary data "
                        "class for SIEM filtering. Tessera proposes "
                        "this enum to SEP-1913 in wave 0D review "
                        "comment 3."
                    ),
                },
            },
        }
    },
}


def is_valid_predicate_type(predicate_type: str) -> bool:
    """Return True iff ``predicate_type`` matches the Tessera
    MCP manifest predicate URI exactly. Use as a fast pre-filter
    before invoking a JSON-Schema validator."""
    return predicate_type == PREDICATE_TYPE


def is_valid_statement_type(statement_type: str) -> bool:
    """Return True iff ``statement_type`` matches the in-toto
    Statement v1 URI exactly."""
    return statement_type == STATEMENT_TYPE


__all__ = [
    "MCP_MANIFEST_STATEMENT_SCHEMA",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "is_valid_predicate_type",
    "is_valid_statement_type",
]
