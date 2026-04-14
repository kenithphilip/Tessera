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


def enrich_event(event: SecurityEvent) -> dict[str, Any]:
    """Add nist_controls and cwe_codes to an event dict.

    Returns a new dict with the original event fields plus:
    - nist_controls: list of NIST SP 800-53 control IDs
    - cwe_codes: list of CWE weakness IDs
    - owasp_asi: list of OWASP Agentic AI Top 10 category IDs (ASI-01..10)

    Args:
        event: The SecurityEvent to enrich.

    Returns:
        Dict with original fields plus compliance metadata.
    """
    enriched = event.to_dict()
    enriched["nist_controls"] = list(NIST_CONTROLS.get(event.kind, ()))
    enriched["cwe_codes"] = list(CWE_CODES.get(event.kind, ()))
    enriched["owasp_asi"] = list(OWASP_ASI.get(event.kind, ()))
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

    def __init__(self, inner_sink: Any = None) -> None:
        self._inner = inner_sink
        self._previous_hash: str = "0" * 64
        self._entries: list[dict[str, Any]] = []

    def __call__(self, event: SecurityEvent) -> None:
        enriched = enrich_event(event)
        enriched["previous_hash"] = self._previous_hash

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
