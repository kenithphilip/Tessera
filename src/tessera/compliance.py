"""NIST SP 800-53 and CWE enrichment for SecurityEvents.

Maps each SecurityEvent kind to the NIST controls and CWE weakness
IDs it enforces. This metadata makes SecurityEvents immediately
actionable in SIEM tooling and positions Tessera in enterprise
compliance frameworks without changing the event schema.

Source attribution: NIST control mappings derived from Compliant-LLM
(strategy_mapping.yaml). CWE assignments derived from Superagent
(prompts/guard.py).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tessera.events import EventKind, SecurityEvent

NIST_CONTROLS: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("AC-4", "SI-10", "SC-7"),
    EventKind.WORKER_SCHEMA_VIOLATION: ("SI-10", "SI-15"),
    EventKind.LABEL_VERIFY_FAILURE: ("IA-9", "SC-8"),
    EventKind.SECRET_REDACTED: ("SC-28", "SI-12"),
    EventKind.IDENTITY_VERIFY_FAILURE: ("IA-9", "IA-5"),
    EventKind.PROOF_VERIFY_FAILURE: ("IA-9", "IA-5"),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("AU-10", "SC-8"),
    EventKind.DELEGATION_VERIFY_FAILURE: ("AC-4", "AC-6"),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("AC-6", "AU-12"),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("AC-6", "AU-12"),
    EventKind.SESSION_EXPIRED: ("AC-12",),
    EventKind.CONTENT_INJECTION_DETECTED: ("SI-10", "SC-7"),
    EventKind.GUARDRAIL_DECISION: ("SI-10", "SC-7"),
}

CWE_CODES: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("CWE-20",),
    EventKind.WORKER_SCHEMA_VIOLATION: ("CWE-20",),
    EventKind.LABEL_VERIFY_FAILURE: ("CWE-345",),
    EventKind.IDENTITY_VERIFY_FAILURE: ("CWE-287",),
    EventKind.PROOF_VERIFY_FAILURE: ("CWE-287",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("CWE-345",),
    EventKind.DELEGATION_VERIFY_FAILURE: ("CWE-285",),
    EventKind.SECRET_REDACTED: ("CWE-200",),
    EventKind.CONTENT_INJECTION_DETECTED: ("CWE-77", "CWE-20"),
    EventKind.GUARDRAIL_DECISION: ("CWE-77",),
}

# OWASP Agentic AI Top 10 taxonomy (Agent Audit ASI-01..ASI-10).
# ASI-01: Prompt Injection
# ASI-02: Sensitive Information Disclosure
# ASI-03: Excessive Agency
# ASI-04: Agent Privilege Escalation
# ASI-05: Insufficient Identity Verification
# ASI-06: Insecure Tool Chaining
# ASI-07: Data Exfiltration via Tool Abuse
# ASI-08: Agent State Manipulation
# ASI-09: Unsafe Code Execution
# ASI-10: Multi-Agent Trust Exploitation
OWASP_ASI: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("ASI-01",),
    EventKind.WORKER_SCHEMA_VIOLATION: ("ASI-01",),
    EventKind.CONTENT_INJECTION_DETECTED: ("ASI-01", "ASI-07"),
    EventKind.GUARDRAIL_DECISION: ("ASI-01",),
    EventKind.LABEL_VERIFY_FAILURE: ("ASI-01", "ASI-08"),
    EventKind.IDENTITY_VERIFY_FAILURE: ("ASI-05",),
    EventKind.PROOF_VERIFY_FAILURE: ("ASI-05",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("ASI-08",),
    EventKind.DELEGATION_VERIFY_FAILURE: ("ASI-03", "ASI-10"),
    EventKind.SECRET_REDACTED: ("ASI-02",),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("ASI-03",),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("ASI-03",),
    EventKind.SESSION_EXPIRED: ("ASI-05",),
}

# MITRE ATLAS v5.4.0 (Feb 2026) technique mapping. Tessera defenses
# against AI / agent attack techniques. Cited in scorecard +
# SARIF runs so SOC teams can pivot from a Tessera event to an
# ATLAS Navigator layer. AML.T0051.* covers the LLM Prompt
# Injection family; AML.T0024 covers Exfiltration via Inference;
# AML.T0043 covers Craft Adversarial Data; AML.T0072 covers
# Reverse Shell, etc.
MITRE_ATLAS: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("AML.T0051.001",),  # Direct Prompt Injection
    EventKind.WORKER_SCHEMA_VIOLATION: ("AML.T0051.001",),
    EventKind.CONTENT_INJECTION_DETECTED: (
        "AML.T0051.001",  # Direct Prompt Injection
        "AML.T0051.002",  # Indirect Prompt Injection
    ),
    EventKind.GUARDRAIL_DECISION: ("AML.T0043",),  # Craft Adversarial Data
    EventKind.LABEL_VERIFY_FAILURE: ("AML.T0051.002",),
    EventKind.IDENTITY_VERIFY_FAILURE: ("AML.T0024",),  # Exfiltration via Inference
    EventKind.PROOF_VERIFY_FAILURE: ("AML.T0024",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("AML.T0051.002",),
    EventKind.DELEGATION_VERIFY_FAILURE: ("AML.T0024",),
    EventKind.SECRET_REDACTED: ("AML.T0024",),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("AML.T0043",),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("AML.T0043",),
}

# EU AI Act (Regulation 2024/1689) Articles applicable to high-risk
# AI systems. Article 9 risk management, Article 12 record keeping,
# Article 14 human oversight, Article 15 accuracy / robustness /
# cybersecurity. The mapping tells operators which Article each
# event provides evidence for under Annex III obligations
# (full obligation date 2026-08-02).
EU_AI_ACT: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("Art.9", "Art.15"),  # risk + cybersecurity
    EventKind.WORKER_SCHEMA_VIOLATION: ("Art.15",),  # robustness
    EventKind.CONTENT_INJECTION_DETECTED: ("Art.15",),
    EventKind.GUARDRAIL_DECISION: ("Art.15",),
    EventKind.LABEL_VERIFY_FAILURE: ("Art.12", "Art.15"),  # log + cyber
    EventKind.IDENTITY_VERIFY_FAILURE: ("Art.15",),
    EventKind.PROOF_VERIFY_FAILURE: ("Art.15",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("Art.12", "Art.15"),
    EventKind.DELEGATION_VERIFY_FAILURE: ("Art.14",),  # human oversight
    EventKind.SECRET_REDACTED: ("Art.15",),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("Art.14",),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("Art.14",),
    EventKind.SESSION_EXPIRED: ("Art.12",),
}

# ISO/IEC 42001:2023 Annex A AI Management System control IDs.
# Tessera evidences specific Annex A controls at runtime: A.6.2.6
# AI system impact assessments, A.6.2.7 documentation, A.7.4 data
# quality, A.8.2 logging, A.9.3 protective measures, A.9.4
# verification, A.10.2 incident response.
ISO_42001: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("A.6.2.6", "A.9.3"),
    EventKind.WORKER_SCHEMA_VIOLATION: ("A.9.3", "A.9.4"),
    EventKind.CONTENT_INJECTION_DETECTED: ("A.9.3", "A.9.4"),
    EventKind.GUARDRAIL_DECISION: ("A.9.3",),
    EventKind.LABEL_VERIFY_FAILURE: ("A.7.4", "A.8.2"),
    EventKind.IDENTITY_VERIFY_FAILURE: ("A.9.3",),
    EventKind.PROOF_VERIFY_FAILURE: ("A.9.3",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("A.7.4", "A.8.2"),
    EventKind.DELEGATION_VERIFY_FAILURE: ("A.9.3", "A.10.2"),
    EventKind.SECRET_REDACTED: ("A.7.4", "A.9.3"),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("A.6.2.7", "A.10.2"),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("A.10.2",),
    EventKind.SESSION_EXPIRED: ("A.8.2",),
}

# CSA AI Controls Matrix (AICM) v1.0 control identifiers. CSA
# released AICM in July 2025 with 243 control objectives across 18
# domains; STAR for AI certification (Oct 2025) consumes these.
# Tessera maps to the most directly evidenced controls:
# LM (Language Model), GA (Governance / Accountability), IAM
# (Identity / Access Management), DSP (Data Security & Privacy),
# AIS (AI Assurance & Safety), TVM (Threat & Vuln Mgmt), LOG.
CSA_AICM: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("LM-04", "AIS-03"),
    EventKind.WORKER_SCHEMA_VIOLATION: ("LM-04", "AIS-03"),
    EventKind.CONTENT_INJECTION_DETECTED: ("LM-04", "TVM-02"),
    EventKind.GUARDRAIL_DECISION: ("LM-04", "AIS-03"),
    EventKind.LABEL_VERIFY_FAILURE: ("DSP-08", "LOG-04"),
    EventKind.IDENTITY_VERIFY_FAILURE: ("IAM-02", "IAM-04"),
    EventKind.PROOF_VERIFY_FAILURE: ("IAM-02", "IAM-04"),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("DSP-08", "LOG-04"),
    EventKind.DELEGATION_VERIFY_FAILURE: ("IAM-02", "GA-02"),
    EventKind.SECRET_REDACTED: ("DSP-04", "DSP-08"),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("GA-02", "AIS-03"),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("GA-02", "LOG-04"),
    EventKind.SESSION_EXPIRED: ("IAM-04", "LOG-04"),
}

# NIST AI 600-1 (July 2024) twelve GenAI risks. The risk IDs are
# the strings NIST uses in the document section headings. Mapping
# lets Tessera SARIF runs cite which 600-1 risk each event
# evidences mitigation for.
NIST_AI_600_1: dict[str, tuple[str, ...]] = {
    EventKind.POLICY_DENY: ("DangerousOutputs", "Confabulation"),
    EventKind.WORKER_SCHEMA_VIOLATION: ("Confabulation",),
    EventKind.CONTENT_INJECTION_DETECTED: (
        "DangerousOutputs",
        "InfoIntegrity",
    ),
    EventKind.GUARDRAIL_DECISION: ("DangerousOutputs",),
    EventKind.LABEL_VERIFY_FAILURE: ("InfoIntegrity",),
    EventKind.IDENTITY_VERIFY_FAILURE: ("InfoIntegrity",),
    EventKind.PROOF_VERIFY_FAILURE: ("InfoIntegrity",),
    EventKind.PROVENANCE_VERIFY_FAILURE: ("InfoIntegrity",),
    EventKind.DELEGATION_VERIFY_FAILURE: ("HumanAIConfig",),
    EventKind.SECRET_REDACTED: ("DataPrivacy", "InfoSecurity"),
    EventKind.HUMAN_APPROVAL_REQUIRED: ("HumanAIConfig",),
    EventKind.HUMAN_APPROVAL_RESOLVED: ("HumanAIConfig",),
    EventKind.SESSION_EXPIRED: ("InfoSecurity",),
}


def enrich_event(event: SecurityEvent) -> dict[str, Any]:
    """Add compliance metadata to an event dict.

    Returns a new dict with the original event fields plus:
    - nist_controls: list of NIST SP 800-53 control IDs
    - cwe_codes: list of CWE weakness IDs
    - owasp_asi: list of OWASP Agentic AI Top 10 category IDs (ASI-01..10)
    - mitre_atlas: list of MITRE ATLAS v5.4.0 technique IDs (AML.T*)
    - eu_ai_act: list of EU AI Act Article numbers (Art.9 / Art.12 /
      Art.14 / Art.15) for which this event provides evidence under
      Annex III high-risk obligations
    - iso_42001: list of ISO/IEC 42001:2023 Annex A control IDs
    - csa_aicm: list of CSA AI Controls Matrix v1.0 IDs
    - nist_ai_600_1: list of NIST AI 600-1 GenAI risk IDs

    Args:
        event: The SecurityEvent to enrich.

    Returns:
        Dict with original fields plus compliance metadata.
    """
    enriched = event.to_dict()
    enriched["nist_controls"] = list(NIST_CONTROLS.get(event.kind, ()))
    enriched["cwe_codes"] = list(CWE_CODES.get(event.kind, ()))
    enriched["owasp_asi"] = list(OWASP_ASI.get(event.kind, ()))
    enriched["mitre_atlas"] = list(MITRE_ATLAS.get(event.kind, ()))
    enriched["eu_ai_act"] = list(EU_AI_ACT.get(event.kind, ()))
    enriched["iso_42001"] = list(ISO_42001.get(event.kind, ()))
    enriched["csa_aicm"] = list(CSA_AICM.get(event.kind, ()))
    enriched["nist_ai_600_1"] = list(NIST_AI_600_1.get(event.kind, ()))
    return enriched


class ChainedAuditLog:
    """Tamper-evident hash-chained audit log.

    Each entry includes the SHA-256 hash of the previous entry, creating
    a verifiable chain. Wraps any existing sink and enriches events with
    compliance metadata before forwarding.

    Source attribution: hash-chain pattern from Microsoft Agent
    Governance Toolkit (audit.py).

    Usage::

        from tessera.events import register_sink, stdout_sink
        chain = ChainedAuditLog(stdout_sink)
        register_sink(chain)
        # Events are now enriched with nist_controls, cwe_codes,
        # entry_hash, and previous_hash before reaching stdout_sink.
    """

    def __init__(self, inner_sink: Any = None, enforce_monotonic: bool = True) -> None:
        self._inner = inner_sink
        self._previous_hash: str = "0" * 64
        self._entries: list[dict[str, Any]] = []
        self._enforce_monotonic = enforce_monotonic
        self._last_timestamp: str | None = None
        self._sequence: int = 0

    def __call__(self, event: SecurityEvent) -> None:
        enriched = enrich_event(event)
        enriched["previous_hash"] = self._previous_hash

        # Monotonic timestamp enforcement: events must arrive in
        # non-decreasing timestamp order. An attacker who controls
        # the clock could replay or reorder events to hide an attack
        # in the audit log. This check detects that.
        event_ts = enriched.get("timestamp", event.timestamp)
        if self._enforce_monotonic and self._last_timestamp is not None:
            if str(event_ts) < self._last_timestamp:
                enriched["timestamp_violation"] = {
                    "event_timestamp": str(event_ts),
                    "last_timestamp": self._last_timestamp,
                    "violation": "non-monotonic: event arrived before previous",
                }
        self._last_timestamp = str(event_ts)

        # Sequence number: provides ordering even when timestamps
        # have identical precision. Monotonically increasing, never
        # reset, not affected by clock manipulation.
        self._sequence += 1
        enriched["sequence"] = self._sequence

        canonical = json.dumps(enriched, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
        enriched["entry_hash"] = entry_hash

        self._previous_hash = entry_hash
        self._entries.append(enriched)

        if self._inner is not None:
            self._inner(event)

    @property
    def entries(self) -> list[dict[str, Any]]:
        """Return a copy of all logged entries."""
        return list(self._entries)

    def verify_chain(self) -> bool:
        """Verify the hash chain integrity.

        Returns:
            True if every entry's previous_hash matches the prior
            entry's entry_hash. False if any link is broken.
        """
        expected_prev = "0" * 64
        for entry in self._entries:
            if entry["previous_hash"] != expected_prev:
                return False
            check = dict(entry)
            stored_hash = check.pop("entry_hash")
            canonical = json.dumps(check, sort_keys=True, separators=(",", ":"))
            computed = hashlib.sha256(canonical.encode()).hexdigest()
            if computed != stored_hash:
                return False
            expected_prev = stored_hash
        return True

    def verify_timestamps(self) -> tuple[bool, list[int]]:
        """Verify that all entries have monotonically non-decreasing timestamps.

        Returns:
            Tuple of (all_valid, violation_indices). all_valid is True if
            no timestamp violations were found. violation_indices lists
            the sequence numbers of entries that arrived out of order.
        """
        violations: list[int] = []
        for entry in self._entries:
            if "timestamp_violation" in entry:
                violations.append(entry.get("sequence", 0))
        return len(violations) == 0, violations

    def verify_sequences(self) -> bool:
        """Verify that sequence numbers are contiguous and start at 1.

        Detects deleted or inserted entries. Complements the hash chain
        (which detects modification) by also detecting omission.

        Returns:
            True if sequences are 1, 2, 3, ... N with no gaps.
        """
        for i, entry in enumerate(self._entries):
            if entry.get("sequence") != i + 1:
                return False
        return True
