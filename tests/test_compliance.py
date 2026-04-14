"""Tests for compliance enrichment and hash-chain audit log."""

from __future__ import annotations

from tessera.compliance import (
    CWE_CODES,
    NIST_CONTROLS,
    ChainedAuditLog,
    enrich_event,
)
from tessera.events import EventKind, SecurityEvent


# -- NIST/CWE enrichment -----------------------------------------------------


def test_enrich_policy_deny() -> None:
    event = SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "send_email"})
    enriched = enrich_event(event)
    assert "AC-4" in enriched["nist_controls"]
    assert "SI-10" in enriched["nist_controls"]
    assert "CWE-20" in enriched["cwe_codes"]


def test_enrich_label_verify_failure() -> None:
    event = SecurityEvent.now(EventKind.LABEL_VERIFY_FAILURE, "unknown", {})
    enriched = enrich_event(event)
    assert "IA-9" in enriched["nist_controls"]
    assert "CWE-345" in enriched["cwe_codes"]


def test_enrich_delegation_failure() -> None:
    event = SecurityEvent.now(EventKind.DELEGATION_VERIFY_FAILURE, "bob", {})
    enriched = enrich_event(event)
    assert "AC-6" in enriched["nist_controls"]
    assert "CWE-285" in enriched["cwe_codes"]


def test_enrich_unknown_kind_returns_empty_lists() -> None:
    event = SecurityEvent.now(EventKind.SESSION_EXPIRED, "sys", {})
    enriched = enrich_event(event)
    assert enriched["nist_controls"] == ["AC-12"]
    assert enriched["cwe_codes"] == []


def test_enrich_preserves_original_fields() -> None:
    event = SecurityEvent.now(EventKind.SECRET_REDACTED, "alice", {"name": "API_KEY"})
    enriched = enrich_event(event)
    assert enriched["kind"] == "secret_redacted"
    assert enriched["principal"] == "alice"
    assert enriched["detail"]["name"] == "API_KEY"


def test_all_event_kinds_have_nist_mapping() -> None:
    for kind in EventKind:
        assert kind in NIST_CONTROLS, f"{kind} missing from NIST_CONTROLS"


# -- Hash-chain audit log ----------------------------------------------------


def test_chain_single_event() -> None:
    chain = ChainedAuditLog()
    event = SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "x"})
    chain(event)
    assert len(chain.entries) == 1
    assert chain.entries[0]["previous_hash"] == "0" * 64
    assert len(chain.entries[0]["entry_hash"]) == 64
    assert chain.verify_chain() is True


def test_chain_multiple_events_link_correctly() -> None:
    chain = ChainedAuditLog()
    for i in range(5):
        chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"i": i}))

    assert len(chain.entries) == 5
    for i in range(1, 5):
        assert chain.entries[i]["previous_hash"] == chain.entries[i - 1]["entry_hash"]
    assert chain.verify_chain() is True


def test_chain_detects_tamper() -> None:
    chain = ChainedAuditLog()
    chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "a"}))
    chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "b"}))
    chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "c"}))

    # Tamper with the middle entry.
    chain._entries[1]["detail"] = {"tool": "TAMPERED"}
    assert chain.verify_chain() is False


def test_chain_forwards_to_inner_sink() -> None:
    received: list[SecurityEvent] = []
    chain = ChainedAuditLog(inner_sink=received.append)
    event = SecurityEvent.now(EventKind.SECRET_REDACTED, "bob", {})
    chain(event)
    assert len(received) == 1
    assert received[0].kind == EventKind.SECRET_REDACTED


def test_chain_empty_verifies_true() -> None:
    chain = ChainedAuditLog()
    assert chain.verify_chain() is True


def test_chain_enriches_with_compliance_metadata() -> None:
    chain = ChainedAuditLog()
    chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {}))
    entry = chain.entries[0]
    assert "nist_controls" in entry
    assert "cwe_codes" in entry
    assert "AC-4" in entry["nist_controls"]


# -- SecurityEvent correlation and trace IDs ----------------------------------


def test_event_with_correlation_id() -> None:
    event = SecurityEvent.now(
        EventKind.POLICY_DENY, "alice", {}, correlation_id="req-123"
    )
    d = event.to_dict()
    assert d["correlation_id"] == "req-123"


def test_event_with_trace_id() -> None:
    event = SecurityEvent.now(
        EventKind.POLICY_DENY, "alice", {}, trace_id="abc123"
    )
    d = event.to_dict()
    assert d["trace_id"] == "abc123"


def test_event_without_ids_omits_fields() -> None:
    event = SecurityEvent.now(EventKind.POLICY_DENY, "alice", {})
    d = event.to_dict()
    assert "correlation_id" not in d
    assert "trace_id" not in d


def test_content_injection_detected_event_kind_exists() -> None:
    event = SecurityEvent.now(
        EventKind.CONTENT_INJECTION_DETECTED, "alice", {"score": 0.95}
    )
    assert event.kind == EventKind.CONTENT_INJECTION_DETECTED
