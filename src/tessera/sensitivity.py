"""Information flow control via sensitivity labels.

Tessera's trust labels answer "who said this?": USER, TOOL, UNTRUSTED.
This module adds an orthogonal axis that answers "how bad if this
leaks?": Public, Internal, Confidential, HighlyConfidential.

The two axes are independent. A USER-trusted prompt can contain
HighlyConfidential data (someone pasted their SSN). An UNTRUSTED web
page can be Public (news). You need both axes to reason about
outbound control.

Model: simplified Bell-LaPadula "no write-down" adapted for AI agent
trajectories. Once a trajectory ingests data at a given sensitivity
level, its effective label is raised to the max level seen (high-water
mark). Outbound tool calls (web fetch, email, external API, webhooks)
are gated against the high-water mark.

This module is a Tessera primitive. It is composable with any policy
engine. Pair it with ``tessera.policy`` to block tainted tool calls
AND confidential exfiltration in the same pipeline.

References:
- Bell-LaPadula confidentiality model (1976)
- Sondera sondera-coding-agent-hooks IFC policies
  (https://github.com/sondera-ai/sondera-coding-agent-hooks)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from fnmatch import fnmatch
from typing import Callable


class SensitivityLabel(IntEnum):
    """Sensitivity levels for content in the context window.

    Ordered from least to most sensitive. Comparisons use the standard
    IntEnum ordering (Public < Internal < Confidential < HighlyConfidential).
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    HIGHLY_CONFIDENTIAL = 3


@dataclass(frozen=True)
class SensitivityClassification:
    """Result of classifying text sensitivity.

    Attributes:
        label: The detected sensitivity level (highest match wins).
        matched_patterns: Names of the patterns that fired.
        score: Confidence 0.0-1.0 that the label is correct.
    """

    label: SensitivityLabel
    matched_patterns: tuple[str, ...]
    score: float


# Patterns that mark content as HIGHLY_CONFIDENTIAL. These are regex
# patterns that are nearly always sensitive when present in text.
_HIGHLY_CONFIDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_pat", re.compile(r"\bgh[ps]_[A-Za-z0-9_]{36,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]+\b")),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
)


# Patterns that mark content as CONFIDENTIAL. These are strong signals
# but allow legitimate discussion of the concept without triggering a
# HIGHLY_CONFIDENTIAL label.
_CONFIDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("confidential_marker", re.compile(r"\b(CONFIDENTIAL|PRIVILEGED|PROPRIETARY)\b")),
    ("password_field", re.compile(r"\b(password|passwd|pwd|secret)\s*[:=]", re.IGNORECASE)),
    (
        "credential_field",
        re.compile(r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]", re.IGNORECASE),
    ),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("email_with_name", re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+[^@]*<[A-Za-z0-9._%+-]+@")),
)


# Patterns that mark content as INTERNAL. Weaker signals that suggest
# non-public business content.
_INTERNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("internal_marker", re.compile(r"\b(INTERNAL|FOR INTERNAL USE|INTERNAL ONLY)\b")),
    (
        "financial_term",
        re.compile(r"\b(revenue|ebitda|arr|mrr|burn rate|runway|quarterly results)\b", re.IGNORECASE),
    ),
    ("meeting_notes", re.compile(r"\b(meeting notes|action items|retrospective)\b", re.IGNORECASE)),
    ("employee_record", re.compile(r"\b(salary|compensation|performance review|headcount)\b", re.IGNORECASE)),
)


def classify(text: str) -> SensitivityClassification:
    """Classify text into a sensitivity level using regex heuristics.

    Scans top-down from HIGHLY_CONFIDENTIAL. Returns the highest level
    that has at least one match, along with the pattern names that
    fired and a confidence score.

    Args:
        text: The text to classify.

    Returns:
        A SensitivityClassification. Falls back to PUBLIC with score 1.0
        when nothing matches.
    """
    if not text:
        return SensitivityClassification(
            label=SensitivityLabel.PUBLIC,
            matched_patterns=(),
            score=1.0,
        )

    for label, patterns, confidence in (
        (SensitivityLabel.HIGHLY_CONFIDENTIAL, _HIGHLY_CONFIDENTIAL_PATTERNS, 0.95),
        (SensitivityLabel.CONFIDENTIAL, _CONFIDENTIAL_PATTERNS, 0.85),
        (SensitivityLabel.INTERNAL, _INTERNAL_PATTERNS, 0.70),
    ):
        matches = [name for name, pat in patterns if pat.search(text)]
        if matches:
            return SensitivityClassification(
                label=label,
                matched_patterns=tuple(matches),
                score=confidence,
            )

    return SensitivityClassification(
        label=SensitivityLabel.PUBLIC,
        matched_patterns=(),
        score=1.0,
    )


ClassifierFn = Callable[[str], SensitivityClassification]


@dataclass
class SensitivityContext:
    """High-water-mark tracker for trajectory sensitivity.

    Sensitivity is monotonic non-decreasing within a trajectory: once
    data at level N has been observed, ``max_sensitivity`` stays at or
    above N until explicitly reset.

    Args:
        classifier: Override the default classifier. Must return a
            SensitivityClassification. Useful for plugging in an
            LLM-based classifier.

    Usage::

        ctx = SensitivityContext()
        ctx.observe("Your SSN is 123-45-6789")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL

        # Later observations cannot lower the label:
        ctx.observe("Public news article")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL
    """

    classifier: ClassifierFn = field(default=classify)
    _max: SensitivityLabel = field(default=SensitivityLabel.PUBLIC, init=False)
    _classifications: list[SensitivityClassification] = field(default_factory=list, init=False)

    def observe(self, text: str) -> SensitivityClassification:
        """Classify text and update the high-water mark.

        Returns the classification so callers can emit events or log
        which patterns fired.
        """
        classification = self.classifier(text)
        self._classifications.append(classification)
        if classification.label > self._max:
            self._max = classification.label
        return classification

    @property
    def max_sensitivity(self) -> SensitivityLabel:
        """The highest sensitivity level observed so far."""
        return self._max

    @property
    def classifications(self) -> list[SensitivityClassification]:
        """All classifications observed, in order."""
        return list(self._classifications)

    def reset(self) -> None:
        """Clear the high-water mark and all classifications.

        Call this between trajectories. Do not call mid-trajectory or
        IFC guarantees break.
        """
        self._max = SensitivityLabel.PUBLIC
        self._classifications.clear()


# Default outbound tool patterns (glob-matched against tool_name).
# Callers can pass their own list to check_outbound.
_DEFAULT_OUTBOUND_PATTERNS: tuple[str, ...] = (
    "send_*",
    "*_webhook",
    "web_fetch",
    "fetch_url",
    "http_*",
    "post_*",
    "upload_*",
    "external_*",
    "publish_*",
    "tweet",
    "discord_*",
    "slack_send_*",
)


def is_outbound_tool(
    tool_name: str,
    patterns: tuple[str, ...] = _DEFAULT_OUTBOUND_PATTERNS,
) -> bool:
    """Check whether a tool name matches an outbound channel pattern."""
    return any(fnmatch(tool_name, p) for p in patterns)


@dataclass(frozen=True)
class IFCDecision:
    """Result of an outbound information-flow-control check.

    Attributes:
        allowed: Whether the call is permitted.
        reason: Human-readable explanation.
        sensitivity: The trajectory's sensitivity label at decision time.
        tool_name: The tool that was checked.
    """

    allowed: bool
    reason: str
    sensitivity: SensitivityLabel
    tool_name: str


def check_outbound(
    tool_name: str,
    sensitivity: SensitivityLabel,
    has_injection: bool = False,
    outbound_patterns: tuple[str, ...] = _DEFAULT_OUTBOUND_PATTERNS,
) -> IFCDecision:
    """Evaluate whether an outbound tool call is allowed.

    Bell-LaPadula "no write-down" adapted for AI agents:

    - ``HighlyConfidential`` trajectory: block ALL outbound calls.
    - ``Confidential`` + injection signal: block outbound (defense in
      depth; the injection may be trying to exfiltrate).
    - ``Confidential`` alone: allowed (legitimate workflows exist).
    - ``Internal`` or ``Public``: always allowed.
    - Non-outbound tools: always allowed (not our concern).

    Args:
        tool_name: The tool being evaluated.
        sensitivity: The trajectory's high-water mark sensitivity.
        has_injection: True if the current context contains tainted
            segments (signals a possible exfiltration attempt).
        outbound_patterns: Override the default outbound tool patterns.

    Returns:
        An IFCDecision. Check ``decision.allowed`` before proceeding.
    """
    if not is_outbound_tool(tool_name, outbound_patterns):
        return IFCDecision(
            allowed=True,
            reason="not an outbound tool",
            sensitivity=sensitivity,
            tool_name=tool_name,
        )

    if sensitivity >= SensitivityLabel.HIGHLY_CONFIDENTIAL:
        return IFCDecision(
            allowed=False,
            reason=f"IFC: {sensitivity.name} trajectory blocked from all outbound channels",
            sensitivity=sensitivity,
            tool_name=tool_name,
        )

    if sensitivity >= SensitivityLabel.CONFIDENTIAL and has_injection:
        return IFCDecision(
            allowed=False,
            reason=(
                f"IFC: {sensitivity.name} trajectory with injection signal "
                "blocked from outbound (possible exfiltration)"
            ),
            sensitivity=sensitivity,
            tool_name=tool_name,
        )

    return IFCDecision(
        allowed=True,
        reason=f"allowed at {sensitivity.name}",
        sensitivity=sensitivity,
        tool_name=tool_name,
    )
