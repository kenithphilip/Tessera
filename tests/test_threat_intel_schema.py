"""Tests for tessera.threat_intel schema (Wave 2J)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from tessera.threat_intel import (
    IOCKind,
    InjectionPattern,
    MaliciousMcpServer,
    ModelFingerprint,
    ThreatIntelFeed,
    feed_schema_v1,
    validate_feed,
)

SAMPLE_FEED_PATH = (
    Path(__file__).parent.parent
    / "src" / "tessera" / "threat_intel" / "sample_feed.json"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Sample feed
# ---------------------------------------------------------------------------


def test_sample_feed_validates() -> None:
    raw = SAMPLE_FEED_PATH.read_text()
    feed = validate_feed(raw)
    assert feed.schema_version == "tessera.threat_intel.v1"
    # Wave 3F extended the sample feed beyond the original 4 IOCs.
    assert len(feed.iocs) >= 4


def test_sample_feed_contains_all_kinds() -> None:
    feed = validate_feed(SAMPLE_FEED_PATH.read_bytes())
    kinds = {ioc.kind for ioc in feed.iocs}
    assert IOCKind.MCP_SERVER_URI in kinds
    assert IOCKind.INJECTION_PATTERN in kinds
    assert IOCKind.MODEL_FINGERPRINT in kinds


# ---------------------------------------------------------------------------
# MaliciousMcpServer
# ---------------------------------------------------------------------------


def test_malicious_mcp_server_validates() -> None:
    ioc = MaliciousMcpServer(
        kind=IOCKind.MCP_SERVER_URI,
        value="https://evil.example.com/mcp",
        confidence=0.9,
        first_seen=_now(),
        last_seen=_now(),
        source="test",
        domain="evil.example.com",
        protocol="https",
    )
    assert ioc.kind == IOCKind.MCP_SERVER_URI
    assert ioc.domain == "evil.example.com"


def test_malicious_mcp_server_invalid_protocol() -> None:
    with pytest.raises(ValidationError):
        MaliciousMcpServer(
            kind=IOCKind.MCP_SERVER_URI,
            value="ftp://evil.example.com",
            confidence=0.5,
            first_seen=_now(),
            last_seen=_now(),
            source="test",
            domain="evil.example.com",
            protocol="ftp",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# InjectionPattern
# ---------------------------------------------------------------------------


def test_injection_pattern_validates() -> None:
    ioc = InjectionPattern(
        kind=IOCKind.INJECTION_PATTERN,
        value="ignore all previous instructions",
        confidence=0.85,
        first_seen=_now(),
        last_seen=_now(),
        source="test",
        pattern_type="substring",
        pattern_value="ignore all previous instructions",
        mitre_atlas_techniques=("AML.T0051.002",),
    )
    assert ioc.mitre_atlas_techniques == ("AML.T0051.002",)


def test_injection_pattern_coerces_list_techniques() -> None:
    raw = {
        "kind": "INJECTION_PATTERN",
        "value": "x",
        "confidence": 0.5,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source": "test",
        "pattern_type": "regex",
        "pattern_value": "x",
        "mitre_atlas_techniques": ["AML.T0051.001", "AML.T0051.002"],
    }
    ioc = InjectionPattern.model_validate(raw)
    assert ioc.mitre_atlas_techniques == ("AML.T0051.001", "AML.T0051.002")


# ---------------------------------------------------------------------------
# ModelFingerprint
# ---------------------------------------------------------------------------


def test_model_fingerprint_validates() -> None:
    ioc = ModelFingerprint(
        kind=IOCKind.MODEL_FINGERPRINT,
        value="bad-llm-7b",
        confidence=0.6,
        first_seen=_now(),
        last_seen=_now(),
        source="test",
        model_family="bad-llm",
        risk_class="high",
    )
    assert ioc.weight_hash is None
    assert ioc.risk_class == "high"


def test_model_fingerprint_invalid_risk_class() -> None:
    with pytest.raises(ValidationError):
        ModelFingerprint(
            kind=IOCKind.MODEL_FINGERPRINT,
            value="x",
            confidence=0.5,
            first_seen=_now(),
            last_seen=_now(),
            source="test",
            model_family="x",
            risk_class="extreme",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# ThreatIntelFeed validation
# ---------------------------------------------------------------------------


def test_missing_required_field_raises() -> None:
    payload = {
        "schema_version": "tessera.threat_intel.v1",
        # generated_at missing
        "maintainer": "test",
        "iocs": [],
    }
    with pytest.raises(ValidationError):
        ThreatIntelFeed.model_validate(payload)


def test_confidence_out_of_range_raises() -> None:
    with pytest.raises(ValidationError):
        MaliciousMcpServer(
            kind=IOCKind.MCP_SERVER_URI,
            value="x",
            confidence=1.5,  # invalid
            first_seen=_now(),
            last_seen=_now(),
            source="test",
            domain="x",
            protocol="https",
        )


def test_last_seen_before_first_seen_raises() -> None:
    t1 = datetime(2026, 4, 1, tzinfo=timezone.utc)
    t2 = datetime(2026, 3, 1, tzinfo=timezone.utc)
    with pytest.raises(ValidationError, match="last_seen"):
        MaliciousMcpServer(
            kind=IOCKind.MCP_SERVER_URI,
            value="x",
            confidence=0.5,
            first_seen=t1,
            last_seen=t2,
            source="test",
            domain="x",
            protocol="https",
        )


# ---------------------------------------------------------------------------
# Round-trip serialisation
# ---------------------------------------------------------------------------


def test_round_trip_json() -> None:
    feed = validate_feed(SAMPLE_FEED_PATH.read_bytes())
    serialized = feed.model_dump_json()
    feed2 = validate_feed(serialized)
    assert feed.feed_id == feed2.feed_id
    assert len(feed.iocs) == len(feed2.iocs)
    assert {ioc.ioc_id for ioc in feed.iocs} == {ioc.ioc_id for ioc in feed2.iocs}


# ---------------------------------------------------------------------------
# validate_feed input types
# ---------------------------------------------------------------------------


def test_validate_feed_accepts_dict() -> None:
    data = json.loads(SAMPLE_FEED_PATH.read_text())
    feed = validate_feed(data)
    assert feed.schema_version == "tessera.threat_intel.v1"


def test_validate_feed_accepts_str() -> None:
    feed = validate_feed(SAMPLE_FEED_PATH.read_text())
    assert feed.schema_version == "tessera.threat_intel.v1"


def test_validate_feed_accepts_bytes() -> None:
    feed = validate_feed(SAMPLE_FEED_PATH.read_bytes())
    assert feed.schema_version == "tessera.threat_intel.v1"


# ---------------------------------------------------------------------------
# Schema export
# ---------------------------------------------------------------------------


def test_feed_schema_v1_returns_dict() -> None:
    schema = feed_schema_v1()
    assert isinstance(schema, dict)
    assert schema.get("title") == "ThreatIntelFeed"
