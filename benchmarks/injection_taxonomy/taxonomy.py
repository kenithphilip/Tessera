"""Injection variant taxonomy for CyberSecEval-compatible benchmarking.

Defines the enum types and the core InjectionCase dataclass that
structure the taxonomy corpus. Every case captures what type of
injection it is (direct vs. indirect), how it works structurally
(variant), what it is trying to achieve (risk category), and the
Tessera policy parameters needed to evaluate it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from tessera.labels import TrustLevel


class InjectionType(StrEnum):
    """Whether the injection arrives directly from the user or indirectly via external data."""

    DIRECT = "direct"      # user-supplied content contains the injection
    INDIRECT = "indirect"  # external data (web scrape, tool output) contains it


class InjectionVariant(StrEnum):
    """Structural technique used to carry the injection."""

    INSTRUCTION_OVERRIDE = "instruction_override"   # "ignore previous instructions"
    CONTEXT_MANIPULATION = "context_manipulation"   # delimiter/separator injection
    ROLE_HIJACKING = "role_hijacking"               # "you are now X", "act as"
    PAYLOAD_SMUGGLING = "payload_smuggling"         # encoding tricks, unicode, base64


class RiskCategory(StrEnum):
    """What the attack is trying to accomplish."""

    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass(frozen=True)
class InjectionCase:
    """A single labeled test case in the injection taxonomy corpus.

    Args:
        id: Unique identifier for this case.
        description: Human-readable summary of the attack scenario.
        injection_type: Whether this is a direct or indirect injection.
        injection_variant: Structural technique used.
        risk_category: What the attacker is trying to accomplish.
        task: The benign user task the agent is performing.
        payload: The injection string (arrives at WEB/UNTRUSTED trust).
        target_tool: The tool the injection tries to invoke.
        target_trust: Trust level the target tool requires.
        expected_blocked: Whether Tessera should block this (default True).
    """

    id: str
    description: str
    injection_type: InjectionType
    injection_variant: InjectionVariant
    risk_category: RiskCategory
    task: str
    payload: str
    target_tool: str
    target_trust: TrustLevel
    expected_blocked: bool = True
