"""Tests for Wave 2B: Sigstore signing + trust tiers + MCP score."""

from __future__ import annotations

from typing import Any

import pytest

from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)
from tessera.mcp.manifest import (
    DSSESignature,
    SignedManifest,
    SigningMethod,
    sign,
    validate_statement,
    verify,
)
from tessera.mcp.manifest_schema import PREDICATE_TYPE, STATEMENT_TYPE
from tessera.mcp.score import (
    ScoreInputs,
    SecurityScore,
    compute,
    deny_threshold,
    warn_threshold,
)
from tessera.mcp.tier import (
    TierAssignment,
    TierPolicy,
    TrustTier,
    assign_tier,
    get_min_tier,
    tier_allows,
)


_KEY = b"x" * 32


@pytest.fixture(autouse=True)
def _capture_events() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


@pytest.fixture
def good_statement() -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "ghcr.io/anthropic-mcp/example",
                "digest": {"sha256": "a" * 64},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "serverUri": "mcp+ws://example.invalid",
            "issuer": "https://github.com/anthropic-mcp/example",
            "issuedAt": "2026-04-25T00:00:00Z",
            "resourceIndicator": "https://example.invalid/mcp",
            "tesseraTrustTier": "verified",
            "tools": [
                {
                    "name": "send_email",
                    "descriptionDigest": "sha256:" + "b" * 64,
                    "inputSchemaDigest": "sha256:" + "c" * 64,
                    "outputSchemaDigest": "sha256:" + "d" * 64,
                    "annotations": {
                        "actionImpact": "destructive",
                        "sensitiveHint": "high",
                        "privateHint": True,
                        "openWorldHint": False,
                        "dataClass": "confidential",
                    },
                }
            ],
        },
    }


# --- Statement validation ---------------------------------------------------


def test_validate_statement_accepts_good(good_statement: dict[str, Any]) -> None:
    validate_statement(good_statement)


def test_validate_statement_rejects_wrong_type(
    good_statement: dict[str, Any],
) -> None:
    bad = dict(good_statement)
    bad["_type"] = "https://other/Statement/v1"
    with pytest.raises(ValueError, match="_type"):
        validate_statement(bad)


def test_validate_statement_rejects_missing_subject(
    good_statement: dict[str, Any],
) -> None:
    bad = dict(good_statement)
    bad["subject"] = []
    with pytest.raises(ValueError, match="subject"):
        validate_statement(bad)


# --- HMAC sign + verify -----------------------------------------------------


def test_hmac_sign_and_verify(good_statement: dict[str, Any]) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    assert manifest.method == SigningMethod.HMAC
    assert len(manifest.signatures) == 1
    result = verify(manifest, hmac_key=_KEY)
    assert bool(result) is True


def test_hmac_verify_fails_with_wrong_key(
    good_statement: dict[str, Any],
) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    result = verify(manifest, hmac_key=b"y" * 32)
    assert bool(result) is False


def test_hmac_verify_emits_invalid_event(
    good_statement: dict[str, Any], _capture_events
) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    verify(manifest, hmac_key=b"y" * 32)
    invalid_events = [
        e for e in _capture_events if e.kind == EventKind.MCP_MANIFEST_SIG_INVALID
    ]
    assert len(invalid_events) == 1


def test_envelope_round_trip(good_statement: dict[str, Any]) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    envelope = manifest.to_envelope()
    revived = SignedManifest.from_envelope(envelope)
    assert revived.statement == manifest.statement
    assert revived.method == manifest.method


def test_subject_digest_mismatch_fails(good_statement: dict[str, Any]) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    expected = {"ghcr.io/anthropic-mcp/example": "b" * 64}
    result = verify(manifest, hmac_key=_KEY, expected_subject_digests=expected)
    assert bool(result) is False
    assert "subject" in result.reason.lower()


def test_hmac_requires_min_key_length(good_statement: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        sign(good_statement, method=SigningMethod.HMAC, hmac_key=b"short")


# --- Trust tiers ------------------------------------------------------------


def test_assign_tier_hmac_falls_to_community(
    good_statement: dict[str, Any],
) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    assignment = assign_tier(manifest, hmac_key=_KEY)
    assert assignment.tier == TrustTier.COMMUNITY
    assert "hmac" in assignment.reason.lower()


def test_tier_allows_default_min_community(
    good_statement: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TESSERA_MCP_MIN_TIER", raising=False)
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    assignment = assign_tier(manifest, hmac_key=_KEY)
    assert tier_allows(assignment) is True
    # Raise the bar; HMAC must now be denied.
    assert tier_allows(assignment, min_tier=TrustTier.VERIFIED) is False


def test_get_min_tier_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TESSERA_MCP_MIN_TIER", "verified")
    assert get_min_tier() == TrustTier.VERIFIED
    monkeypatch.setenv("TESSERA_MCP_MIN_TIER", "attested")
    assert get_min_tier() == TrustTier.ATTESTED
    monkeypatch.setenv("TESSERA_MCP_MIN_TIER", "bogus")
    assert get_min_tier() == TrustTier.COMMUNITY


def test_tier_assignment_records_failure_reason(
    good_statement: dict[str, Any],
) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    # Verify with the wrong key so verification fails.
    assignment = assign_tier(manifest, hmac_key=b"y" * 32)
    assert assignment.tier == TrustTier.COMMUNITY
    assert "verification failed" in assignment.reason


# --- MCP Security Score -----------------------------------------------------


def test_score_with_attested_no_drift_full_score(
    good_statement: dict[str, Any],
) -> None:
    manifest = sign(good_statement, method=SigningMethod.HMAC, hmac_key=_KEY)
    # Manually craft an ATTESTED assignment to test the score formula
    # decoupled from the real Sigstore path.
    assignment = TierAssignment(
        tier=TrustTier.ATTESTED, reason="test", verification=None
    )
    inputs = ScoreInputs(
        server_id="example",
        tier=assignment,
        drift_alert_kinds=(),
        rekor_age_days=1.0,
        critical_args_specs_present=True,
        recent_denials_24h=0,
        tools_count=5,
    )
    score = compute(inputs)
    assert isinstance(score, SecurityScore)
    # 40 (ATTESTED) + 20 (no drift) + 15 (fresh rekor) + 15 (specs) + 10 (no denials).
    assert score.score == 100.0


def test_score_drops_with_drift(good_statement: dict[str, Any]) -> None:
    assignment = TierAssignment(
        tier=TrustTier.VERIFIED, reason="test", verification=None
    )
    inputs = ScoreInputs(
        server_id="example",
        tier=assignment,
        drift_alert_kinds=(EventKind.MCP_DRIFT_SHAPE,),
        rekor_age_days=1.0,
        critical_args_specs_present=True,
        recent_denials_24h=0,
        tools_count=5,
    )
    score = compute(inputs)
    # 25 (VERIFIED) + 10 (drift_shape -10) + 15 + 15 + 10 = 75.
    assert score.score == 75.0


def test_score_otel_attributes_carry_components() -> None:
    assignment = TierAssignment(
        tier=TrustTier.ATTESTED, reason="ok", verification=None
    )
    inputs = ScoreInputs(
        server_id="example",
        tier=assignment,
        rekor_age_days=2.0,
        critical_args_specs_present=True,
    )
    score = compute(inputs)
    attrs = score.to_otel_attributes()
    assert "tessera.mcp.security_score" in attrs
    assert attrs["tessera.mcp.server_id"] == "example"
    assert attrs["tessera.mcp.security_score.tier"] == 40.0


def test_thresholds_have_sane_defaults() -> None:
    assert warn_threshold() == 60.0
    assert deny_threshold() == 40.0
    assert deny_threshold() < warn_threshold()


def test_score_handles_old_rekor_proof() -> None:
    assignment = TierAssignment(
        tier=TrustTier.VERIFIED, reason="ok", verification=None
    )
    inputs = ScoreInputs(
        server_id="x",
        tier=assignment,
        rekor_age_days=120.0,  # very stale
        critical_args_specs_present=False,
    )
    score = compute(inputs)
    assert score.breakdown.rekor_component == 0.0
