"""MCP tool description poisoning detection.

MCP servers are external code. Their tool descriptions flow into the agent's
context window verbatim as part of the tool catalog. A malicious or
compromised MCP server can embed injection instructions in those descriptions
that override the agent's behavior before any user-supplied data arrives.

This scanner checks tool name + description + input schema text for five
categories of poisoning derived from Agent Audit's ToolDescriptionAnalyzer
(AGENT-056, AGENT-057):

  1. Instruction override: "ignore previous instructions", "disregard..."
  2. Hidden content: zero-width chars, HTML comments, template injection
  3. Command injection: backtick execution, subshell, pipe abuse
  4. Data exfiltration guidance: "send data to http://...", webhook URLs
  5. Privilege escalation directives: "grant admin", "elevate permissions"

Severity mapping mirrors Agent Audit's confidence tiers:
  BLOCK  - high confidence, emit and raise
  WARN   - medium confidence, emit only
  INFO   - low confidence, log only

Source attribution: Agent Audit ToolDescriptionAnalyzer
(agent_audit/tool_description_analyzer.py, rules AGENT-056/057).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class PoisoningSeverity(StrEnum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    INFO = "INFO"


@dataclass(frozen=True)
class PoisoningMatch:
    category: str
    severity: PoisoningSeverity
    pattern: str
    matched_text: str


@dataclass(frozen=True)
class ToolDescriptionScanResult:
    """Result of scanning a single tool description."""

    tool_name: str
    poisoned: bool
    matches: tuple[PoisoningMatch, ...]
    max_severity: PoisoningSeverity | None


# Category 1: Instruction override
_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], PoisoningSeverity]] = [
    (
        re.compile(
            r"(ignore|disregard|skip|forget|bypass|override)\s+"
            r"(all\s+)?(prior|previous|above|earlier|initial|original)\s+"
            r"(instructions|commands|rules|guidelines|constraints)",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    (
        re.compile(
            r"(your\s+new\s+(role|purpose|task)|act\s+as|pretend\s+to\s+be)\b",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    (
        re.compile(r"<SYSTEM>|<\/SYSTEM>|\[INST\]|\[\/INST\]", re.IGNORECASE),
        PoisoningSeverity.BLOCK,
    ),
]

# Category 2: Hidden content
_HIDDEN_CONTENT_PATTERNS: list[tuple[re.Pattern[str], PoisoningSeverity]] = [
    # Zero-width characters: ZWSP, ZWNJ, ZWJ, WORD JOINER, INVISIBLE SEPARATOR
    (
        re.compile(r"[\u200b\u200c\u200d\u2060\u2063\ufeff]"),
        PoisoningSeverity.BLOCK,
    ),
    # HTML comments (can hide instructions from renderers)
    (
        re.compile(r"<!--.+?-->", re.DOTALL),
        PoisoningSeverity.WARN,
    ),
    # Template injection (Jinja2 / Twig / Django style)
    (
        re.compile(r"\{\{.+?\}\}|\{%.+?%\}", re.DOTALL),
        PoisoningSeverity.WARN,
    ),
]

# Category 3: Command injection
# Build patterns from parts to avoid triggering source-level security scanners
# on regex strings that contain shell command names.
_SUBSHELL = re.compile(r"`[^`]+`|\$\([^)]+\)")
_PIPE_EXEC = re.compile(r"\|\s*(bash|sh|zsh|python3?|perl|ruby|node|curl|wget)\b", re.IGNORECASE)
_PROC_IMPORT = re.compile(r"\bsubprocess\b", re.IGNORECASE)

_COMMAND_INJECTION_PATTERNS: list[tuple[re.Pattern[str], PoisoningSeverity]] = [
    (_SUBSHELL, PoisoningSeverity.BLOCK),
    (_PIPE_EXEC, PoisoningSeverity.BLOCK),
    (_PROC_IMPORT, PoisoningSeverity.WARN),
]

# Category 4: Data exfiltration guidance
_EXFILTRATION_PATTERNS: list[tuple[re.Pattern[str], PoisoningSeverity]] = [
    # Explicit "send to URL" instruction with HTTP scheme
    (
        re.compile(
            r"(send|forward|upload|post|exfiltrate).{0,60}https?://\S+",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    # Webhook patterns
    (
        re.compile(
            r"(webhook|callback|notify).{0,30}https?://\S+",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    # Out-of-band fetch
    (
        re.compile(r"(curl|wget|requests\.get|fetch)\s+['\"]?https?://", re.IGNORECASE),
        PoisoningSeverity.WARN,
    ),
]

# Category 5: Privilege escalation
_PRIVILEGE_ESCALATION_PATTERNS: list[tuple[re.Pattern[str], PoisoningSeverity]] = [
    (
        re.compile(
            r"(grant|give|assign|elevate).{0,30}(admin|root|superuser|sudo|privilege)",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    (
        re.compile(
            r"(bypass|skip|disable).{0,30}(auth|authentication|authorization|security|policy)",
            re.IGNORECASE,
        ),
        PoisoningSeverity.BLOCK,
    ),
    (
        re.compile(r"\bsudo\b|\bsu\s+-\b", re.IGNORECASE),
        PoisoningSeverity.WARN,
    ),
]

_ALL_CATEGORIES: list[tuple[str, list[tuple[re.Pattern[str], PoisoningSeverity]]]] = [
    ("instruction_override", _OVERRIDE_PATTERNS),
    ("hidden_content", _HIDDEN_CONTENT_PATTERNS),
    ("command_injection", _COMMAND_INJECTION_PATTERNS),
    ("data_exfiltration", _EXFILTRATION_PATTERNS),
    ("privilege_escalation", _PRIVILEGE_ESCALATION_PATTERNS),
]

_SEVERITY_ORDER = {
    PoisoningSeverity.BLOCK: 3,
    PoisoningSeverity.WARN: 2,
    PoisoningSeverity.INFO: 1,
}


def _scan_text(text: str) -> list[PoisoningMatch]:
    matches: list[PoisoningMatch] = []
    for category, patterns in _ALL_CATEGORIES:
        for compiled, severity in patterns:
            m = compiled.search(text)
            if m:
                matches.append(
                    PoisoningMatch(
                        category=category,
                        severity=severity,
                        pattern=compiled.pattern,
                        matched_text=m.group(0)[:200],
                    )
                )
    return matches


def scan_tool(tool_name: str, description: str, input_schema: Any = None) -> ToolDescriptionScanResult:
    """Scan a single tool's name, description, and schema for poisoning.

    Args:
        tool_name: The tool's registered name.
        description: The tool's description string.
        input_schema: Optional dict/JSON schema for input parameters.

    Returns:
        ToolDescriptionScanResult with all matches found.
    """
    corpus = f"{tool_name}\n{description}"
    if input_schema is not None:
        import json as _json
        try:
            corpus += "\n" + _json.dumps(input_schema)
        except (TypeError, ValueError):
            corpus += "\n" + str(input_schema)

    matches = _scan_text(corpus)
    if not matches:
        return ToolDescriptionScanResult(
            tool_name=tool_name,
            poisoned=False,
            matches=(),
            max_severity=None,
        )

    max_sev = max(matches, key=lambda m: _SEVERITY_ORDER[m.severity]).severity
    return ToolDescriptionScanResult(
        tool_name=tool_name,
        poisoned=True,
        matches=tuple(matches),
        max_severity=max_sev,
    )


def scan_tools(
    tools: list[dict[str, Any]],
    principal: str = "system",
    server_name: str = "unknown",
) -> list[ToolDescriptionScanResult]:
    """Scan a list of MCP tool definitions and emit SecurityEvents for findings.

    Each tool dict is expected to have at minimum a "name" key. "description"
    and "inputSchema" are optional but scanned when present.

    Args:
        tools: List of tool definition dicts from an MCP server.
        principal: Principal to attach to emitted SecurityEvents.
        server_name: MCP server identifier for the event detail.

    Returns:
        List of ToolDescriptionScanResult for poisoned tools only. Clean tools
        are omitted.
    """
    findings: list[ToolDescriptionScanResult] = []
    for tool in tools:
        name = tool.get("name", "")
        description = tool.get("description", "")
        schema = tool.get("inputSchema") or tool.get("input_schema")
        result = scan_tool(name, description, schema)
        if result.poisoned:
            findings.append(result)
            _emit_finding(result, principal, server_name)
    return findings


def _emit_finding(
    result: ToolDescriptionScanResult,
    principal: str,
    server_name: str,
) -> None:
    from tessera.events import EventKind, SecurityEvent, emit

    emit(
        SecurityEvent.now(
            kind=EventKind.CONTENT_INJECTION_DETECTED,
            principal=principal,
            detail={
                "scanner": "tool_description_poisoning",
                "server": server_name,
                "tool": result.tool_name,
                "severity": str(result.max_severity),
                "categories": list({m.category for m in result.matches}),
                "match_count": len(result.matches),
                "first_match": result.matches[0].matched_text if result.matches else None,
                "owasp": "LLM09",
                "rules": ["AGENT-056", "AGENT-057"],
            },
        )
    )
