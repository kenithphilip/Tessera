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


# -- v0.11.1 Phase 0 wave 0C: extended compliance taxonomies ----------------


def test_enrich_includes_mitre_atlas_for_injection_event() -> None:
    from tessera.compliance import MITRE_ATLAS

    event = SecurityEvent.now(
        EventKind.CONTENT_INJECTION_DETECTED, "alice", {"tool": "x"}
    )
    enriched = enrich_event(event)
    assert "AML.T0051.001" in enriched["mitre_atlas"]
    assert "AML.T0051.002" in enriched["mitre_atlas"]
    # Bare table also exposes the mapping.
    assert MITRE_ATLAS[EventKind.CONTENT_INJECTION_DETECTED]


def test_enrich_includes_eu_ai_act_articles_for_policy_deny() -> None:
    from tessera.compliance import EU_AI_ACT

    event = SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "x"})
    enriched = enrich_event(event)
    assert "Art.9" in enriched["eu_ai_act"]
    assert "Art.15" in enriched["eu_ai_act"]
    assert EU_AI_ACT[EventKind.POLICY_DENY]


def test_enrich_includes_iso_42001_for_label_verify_failure() -> None:
    from tessera.compliance import ISO_42001

    event = SecurityEvent.now(EventKind.LABEL_VERIFY_FAILURE, "unknown", {})
    enriched = enrich_event(event)
    # A.7.4 data quality + A.8.2 logging.
    assert "A.7.4" in enriched["iso_42001"]
    assert "A.8.2" in enriched["iso_42001"]
    assert ISO_42001[EventKind.LABEL_VERIFY_FAILURE]


def test_enrich_includes_csa_aicm_for_secret_redacted() -> None:
    from tessera.compliance import CSA_AICM

    event = SecurityEvent.now(EventKind.SECRET_REDACTED, "alice", {})
    enriched = enrich_event(event)
    # DSP-04 data classification + DSP-08 data masking.
    assert "DSP-04" in enriched["csa_aicm"]
    assert "DSP-08" in enriched["csa_aicm"]
    assert CSA_AICM[EventKind.SECRET_REDACTED]


def test_enrich_includes_nist_ai_600_1_for_human_approval() -> None:
    from tessera.compliance import NIST_AI_600_1

    event = SecurityEvent.now(EventKind.HUMAN_APPROVAL_REQUIRED, "alice", {})
    enriched = enrich_event(event)
    # Human-AI Configuration risk.
    assert "HumanAIConfig" in enriched["nist_ai_600_1"]
    assert NIST_AI_600_1[EventKind.HUMAN_APPROVAL_REQUIRED]


def test_enrich_unknown_kind_returns_empty_for_extended_taxonomies() -> None:
    # SESSION_EXPIRED is in some tables but not all; make sure missing
    # entries return empty lists and never raise KeyError.
    event = SecurityEvent.now(EventKind.SESSION_EXPIRED, "sys", {})
    enriched = enrich_event(event)
    assert isinstance(enriched["mitre_atlas"], list)
    assert isinstance(enriched["eu_ai_act"], list)
    assert isinstance(enriched["iso_42001"], list)
    assert isinstance(enriched["csa_aicm"], list)
    assert isinstance(enriched["nist_ai_600_1"], list)


def test_enrich_event_dict_includes_all_eight_taxonomies() -> None:
    event = SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"tool": "x"})
    enriched = enrich_event(event)
    expected_keys = {
        "nist_controls",
        "cwe_codes",
        "owasp_asi",
        "mitre_atlas",
        "eu_ai_act",
        "iso_42001",
        "csa_aicm",
        "nist_ai_600_1",
    }
    assert expected_keys <= set(enriched.keys())


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


# -- Timestamp and sequence validation ----------------------------------------


def test_monotonic_timestamps_pass() -> None:
    """Events arriving in order should have no timestamp violations."""
    chain = ChainedAuditLog(enforce_monotonic=True)
    for i in range(5):
        chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"i": i}))
    valid, violations = chain.verify_timestamps()
    assert valid
    assert violations == []


def test_non_monotonic_timestamp_detected() -> None:
    """An event with a timestamp before the previous should be flagged."""
    from datetime import datetime, timezone

    chain = ChainedAuditLog(enforce_monotonic=True)
    # First event at a later time
    e1 = SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="alice",
        detail={},
        timestamp="2026-04-15T12:00:00+00:00",
    )
    chain(e1)
    # Second event at an earlier time (clock went backwards)
    e2 = SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="alice",
        detail={},
        timestamp="2026-04-15T11:59:00+00:00",
    )
    chain(e2)
    valid, violations = chain.verify_timestamps()
    assert not valid
    assert len(violations) == 1


def test_sequence_numbers_contiguous() -> None:
    """Sequence numbers should be 1, 2, 3, ... N."""
    chain = ChainedAuditLog()
    for i in range(4):
        chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"i": i}))
    assert chain.verify_sequences()
    assert chain.entries[0]["sequence"] == 1
    assert chain.entries[3]["sequence"] == 4


def test_sequence_gap_detected() -> None:
    """A gap in sequence numbers (deleted entry) should fail verification."""
    chain = ChainedAuditLog()
    for i in range(3):
        chain(SecurityEvent.now(EventKind.POLICY_DENY, "alice", {"i": i}))
    # Simulate deletion of middle entry
    del chain._entries[1]
    # Sequences are now [1, 3], gap at 2
    assert not chain.verify_sequences()


def test_enforce_monotonic_disabled() -> None:
    """With enforce_monotonic=False, no timestamp violations are recorded."""
    chain = ChainedAuditLog(enforce_monotonic=False)
    e1 = SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="alice",
        detail={},
        timestamp="2026-04-15T12:00:00+00:00",
    )
    e2 = SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="alice",
        detail={},
        timestamp="2026-04-15T11:00:00+00:00",  # earlier
    )
    chain(e1)
    chain(e2)
    valid, violations = chain.verify_timestamps()
    assert valid  # no enforcement, no violations


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
