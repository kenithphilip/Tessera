"""SARIF 2.1.0 output sink for SecurityEvents.

Collects SecurityEvents during an agent run and serializes them
to the SARIF static analysis interchange format, suitable for
upload to GitHub Code Scanning, Semgrep App, or any SARIF consumer.

Usage:
    sarif = SARIFSink(tool_name="tessera", tool_version="0.0.1")
    register_sink(sarif)
    # ... run agent ...
    sarif.write("results.sarif")
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any

from tessera.events import EventKind, SecurityEvent

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_KIND_TO_RULE: dict[str, str] = {
    EventKind.POLICY_DENY: "tessera/policy-deny",
    EventKind.WORKER_SCHEMA_VIOLATION: "tessera/worker-schema-violation",
    EventKind.LABEL_VERIFY_FAILURE: "tessera/label-verify-failure",
    EventKind.SECRET_REDACTED: "tessera/secret-redacted",
    EventKind.IDENTITY_VERIFY_FAILURE: "tessera/identity-verify-failure",
    EventKind.PROOF_VERIFY_FAILURE: "tessera/proof-verify-failure",
    EventKind.PROVENANCE_VERIFY_FAILURE: "tessera/provenance-verify-failure",
    EventKind.DELEGATION_VERIFY_FAILURE: "tessera/delegation-verify-failure",
    EventKind.HUMAN_APPROVAL_REQUIRED: "tessera/human-approval-required",
    EventKind.HUMAN_APPROVAL_RESOLVED: "tessera/human-approval-resolved",
    EventKind.SESSION_EXPIRED: "tessera/session-expired",
    EventKind.CONTENT_INJECTION_DETECTED: "tessera/injection-detected",
}

# SARIF levels: error, warning, note, none
_KIND_TO_LEVEL: dict[str, str] = {
    EventKind.POLICY_DENY: "error",
    EventKind.WORKER_SCHEMA_VIOLATION: "error",
    EventKind.LABEL_VERIFY_FAILURE: "error",
    EventKind.SECRET_REDACTED: "warning",
    EventKind.IDENTITY_VERIFY_FAILURE: "error",
    EventKind.PROOF_VERIFY_FAILURE: "error",
    EventKind.PROVENANCE_VERIFY_FAILURE: "error",
    EventKind.DELEGATION_VERIFY_FAILURE: "error",
    EventKind.HUMAN_APPROVAL_REQUIRED: "warning",
    EventKind.HUMAN_APPROVAL_RESOLVED: "note",
    EventKind.SESSION_EXPIRED: "warning",
    EventKind.CONTENT_INJECTION_DETECTED: "error",
}


class SARIFSink:
    """Collects SecurityEvents and outputs SARIF 2.1.0 JSON.

    Implements the EventSink callable interface so it can be
    registered directly with ``register_sink(sarif_sink)``.

    Args:
        tool_name: Name of the tool in the SARIF driver block.
        tool_version: Version string for the SARIF driver block.
    """

    def __init__(
        self,
        tool_name: str = "tessera",
        tool_version: str = "0.0.1",
    ) -> None:
        self._tool_name = tool_name
        self._tool_version = tool_version
        self._events: list[SecurityEvent] = []
        self._lock = Lock()

    def __call__(self, event: SecurityEvent) -> None:
        """Sink interface: collect events."""
        with self._lock:
            self._events.append(event)

    def to_sarif(self) -> dict[str, Any]:
        """Return SARIF 2.1.0 JSON dict."""
        with self._lock:
            events = list(self._events)

        seen_rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for event in events:
            kind_str = str(event.kind)
            rule_id = _KIND_TO_RULE.get(kind_str, f"tessera/{kind_str}")
            level = _KIND_TO_LEVEL.get(kind_str, "warning")

            if rule_id not in seen_rules:
                seen_rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": kind_str},
                }

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{kind_str} by {event.principal}",
                },
                "properties": event.to_dict(),
            }
            results.append(result)

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self._tool_name,
                            "version": self._tool_version,
                            "rules": list(seen_rules.values()),
                        },
                    },
                    "results": results,
                },
            ],
        }

    def write(self, path: str) -> None:
        """Write SARIF JSON to file.

        Args:
            path: Filesystem path for the output file.
        """
        sarif = self.to_sarif()
        Path(path).write_text(json.dumps(sarif, indent=2, default=str))
