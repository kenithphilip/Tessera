"""Agent Audit SARIF correlation with Tessera runtime events.

Ingests Agent Audit SARIF output (static analysis findings) and
correlates them with runtime SecurityEvents by tool name and OWASP
category. This lets operators see when a statically flagged tool
actually fires at runtime, providing evidence that a theoretical
finding has practical impact.

Source attribution: SARIF 2.1.0 schema from OASIS TC; Agent Audit
rule ID format (AGENT-NNN) from Agent Audit project.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tessera.compliance import OWASP_ASI
from tessera.events import SecurityEvent


@dataclass(frozen=True)
class StaticFinding:
    """A finding from Agent Audit's static analysis.

    Args:
        rule_id: Agent Audit rule identifier (e.g., "AGENT-056").
        tool_name: Which tool was flagged.
        owasp_category: OWASP Agentic AI category (e.g., "ASI-01").
        message: Human-readable finding description.
        severity: Severity level: "BLOCK", "WARN", or "INFO".
        file_path: Source file where the finding was located.
        line: Line number of the finding.
    """

    rule_id: str
    tool_name: str
    owasp_category: str
    message: str
    severity: str
    file_path: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class CorrelatedFinding:
    """A runtime event that matches a static finding.

    Args:
        runtime_event: The SecurityEvent that fired at runtime.
        static_finding: The static analysis finding it matches.
        correlation_type: How they match: "tool_match", "owasp_match",
            or "both".
    """

    runtime_event: SecurityEvent
    static_finding: StaticFinding
    correlation_type: str


class SARIFCorrelator:
    """Correlate Agent Audit static findings with Tessera runtime events.

    Usage::

        correlator = SARIFCorrelator()
        correlator.load_sarif("agent-audit-results.sarif")

        # Register as an event sink
        register_sink(correlator.correlate_sink)

        # When a runtime event fires for a tool that was also flagged
        # statically, the correlator enriches the event with the static
        # finding details.
    """

    def __init__(self) -> None:
        self._static_findings: list[StaticFinding] = []
        self._correlated: list[CorrelatedFinding] = []

    def load_sarif(self, path: str) -> int:
        """Load Agent Audit SARIF output.

        Parses a SARIF 2.1.0 JSON file and extracts findings. Each
        SARIF result is mapped to a StaticFinding using the rule ID,
        tool name (from properties or message), and OWASP category
        (from properties).

        Args:
            path: Filesystem path to the SARIF JSON file.

        Returns:
            Number of findings loaded.
        """
        data = json.loads(Path(path).read_text())
        count = 0
        for run in data.get("runs", []):
            for result in run.get("results", []):
                finding = _sarif_result_to_finding(result)
                if finding is not None:
                    self._static_findings.append(finding)
                    count += 1
        return count

    def load_findings(self, findings: list[StaticFinding]) -> None:
        """Load findings directly (for testing without SARIF files).

        Args:
            findings: List of StaticFinding objects to add.
        """
        self._static_findings.extend(findings)

    def correlate_sink(self, event: SecurityEvent) -> None:
        """Event sink: check if this runtime event matches any static finding.

        Suitable for use with register_sink(). Any correlations found
        are accumulated in correlated_findings.

        Args:
            event: The SecurityEvent to check.
        """
        for corr in self.correlate(event):
            self._correlated.append(corr)

    def correlate(self, event: SecurityEvent) -> list[CorrelatedFinding]:
        """Check a single event against loaded static findings.

        Correlation logic:
        - "tool_match": event detail["tool"] matches finding tool_name
        - "owasp_match": event OWASP ASI categories overlap with
          finding owasp_category
        - "both": both tool and OWASP match

        Args:
            event: The SecurityEvent to correlate.

        Returns:
            List of CorrelatedFinding objects (may be empty).
        """
        results: list[CorrelatedFinding] = []
        event_tool = event.detail.get("tool", "")
        event_owasp = set(OWASP_ASI.get(event.kind, ()))

        for finding in self._static_findings:
            tool_match = bool(event_tool and event_tool == finding.tool_name)
            owasp_match = bool(finding.owasp_category in event_owasp)

            if tool_match and owasp_match:
                correlation_type = "both"
            elif tool_match:
                correlation_type = "tool_match"
            elif owasp_match:
                correlation_type = "owasp_match"
            else:
                continue

            results.append(
                CorrelatedFinding(
                    runtime_event=event,
                    static_finding=finding,
                    correlation_type=correlation_type,
                )
            )

        return results

    @property
    def correlated_findings(self) -> list[CorrelatedFinding]:
        """All correlations found so far."""
        return list(self._correlated)


def _sarif_result_to_finding(result: dict[str, Any]) -> StaticFinding | None:
    """Convert a SARIF result object to a StaticFinding.

    Extracts rule_id from ruleId, tool_name and owasp_category from
    properties, severity from level, and message from message.text.
    """
    rule_id = result.get("ruleId", "")
    message = result.get("message", {}).get("text", "")
    level = result.get("level", "warning")
    props = result.get("properties", {})

    tool_name = props.get("tool_name", "")
    owasp_category = props.get("owasp_category", "")

    severity_map = {
        "error": "BLOCK",
        "warning": "WARN",
        "note": "INFO",
        "none": "INFO",
    }
    severity = severity_map.get(level, "WARN")

    file_path: str | None = None
    line: int | None = None
    locations = result.get("locations", [])
    if locations:
        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        file_path = artifact.get("uri")
        region = phys.get("region", {})
        line = region.get("startLine")

    if not rule_id and not tool_name:
        return None

    return StaticFinding(
        rule_id=rule_id,
        tool_name=tool_name,
        owasp_category=owasp_category,
        message=message,
        severity=severity,
        file_path=file_path,
        line=line,
    )
