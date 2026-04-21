"""tessera.sensitivity: per-trajectory IFC primitives.

Tracks data sensitivity across an agent trajectory and enforces an
outbound-flow policy. Sensitivity is an axis orthogonal to trust:
trust says "who said this" (USER, TOOL, UNTRUSTED), sensitivity says
"how bad if it leaks" (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED).

Components
----------
SensitivityLabel       : 4-level IntEnum lattice.
ClassificationRule     : named (id, label, pattern, description).
SensitivityClassifier  : pattern-based classifier with pluggable rules.
HWMStore               : Protocol for the high-water-mark backing store.
InMemoryHWMStore       : default store; swap for Redis in production.
HighWaterMark          : per-trajectory monotonic max of observed labels.
ToolClassification     : (outbound, max_sensitivity) per tool.
OutboundPolicy         : pure check over (tool name, HWM).
OutboundDecision       : result of OutboundPolicy.check.

Wiring
------
The /classify endpoint is the only place the HWM moves. evaluate_tool_call
reads the HWM and runs OutboundPolicy.check against it. Keeping reads
audit-pure means the deny reason in the audit log is reproducible from
the (HWM at decision time, tool registry).

The classifier here is intentionally pattern-based so false-positive
iteration is fast (same pattern as the directive/intent scanners).
Plug in an LLM or vendor DLP classifier by passing a custom rule set
or wrapping SensitivityClassifier with a different `classify` impl.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable, Mapping, Protocol


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


class SensitivityLabel(IntEnum):
    """Ordered sensitivity lattice. Higher value = more sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def from_str(cls, name: str) -> "SensitivityLabel":
        try:
            return cls[name.strip().upper()]
        except KeyError as e:
            raise ValueError(f"unknown sensitivity label: {name!r}") from e


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassificationRule:
    """A single labeled pattern. The highest-matching rule wins."""

    id: str
    label: SensitivityLabel
    pattern: re.Pattern
    description: str = ""


@dataclass(frozen=True)
class Classification:
    label: SensitivityLabel
    matched_rule_ids: tuple[str, ...] = ()


# Default rule set. Tuned conservatively. Extend via SensitivityClassifier(rules=...)
# or .register(...). All patterns are case-insensitive unless noted.
_DEFAULT_RULES: tuple[ClassificationRule, ...] = (
    # RESTRICTED -------------------------------------------------------------
    ClassificationRule(
        id="pii.ssn",
        label=SensitivityLabel.RESTRICTED,
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        description="US Social Security Number",
    ),
    ClassificationRule(
        id="pii.credit_card",
        label=SensitivityLabel.RESTRICTED,
        pattern=re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?"
            r"\d{4}[- ]?\d{4}[- ]?\d{4}\b"
        ),
        description="Major-issuer credit card",
    ),
    ClassificationRule(
        id="pii.aadhaar",
        label=SensitivityLabel.RESTRICTED,
        pattern=re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
        description="Aadhaar (12-digit)",
    ),
    # CONFIDENTIAL -----------------------------------------------------------
    ClassificationRule(
        id="secret.aws_access_key",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS access key id",
    ),
    ClassificationRule(
        id="secret.aws_secret",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(
            r"(?i)aws(.{0,20})?(secret|sk)[^a-z0-9]{0,5}[a-z0-9/+=]{40}"
        ),
        description="AWS secret access key (heuristic)",
    ),
    ClassificationRule(
        id="secret.gcp_sa_key",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        description="GCP service-account JSON",
    ),
    ClassificationRule(
        id="secret.private_key_pem",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
        ),
        description="PEM/OpenSSH private key block",
    ),
    ClassificationRule(
        id="secret.jwt",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        description="JWT",
    ),
    ClassificationRule(
        id="secret.github_token",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        description="GitHub token",
    ),
    ClassificationRule(
        id="secret.slack_token",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        description="Slack token",
    ),
    ClassificationRule(
        id="secret.generic_bearer",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(
            r"(?i)(?:authorization\s*:\s*bearer\s+|api[_-]?key\s*[:=]\s*)[A-Za-z0-9._\-]{20,}"
        ),
        description="Bearer / api-key header (heuristic)",
    ),
    ClassificationRule(
        id="marker.confidential_header",
        label=SensitivityLabel.CONFIDENTIAL,
        pattern=re.compile(r"(?i)\b(?:strictly\s+)?confidential\b|\bnda\b|\bprivileged\b"),
        description="Explicit confidentiality marker",
    ),
    # INTERNAL ---------------------------------------------------------------
    ClassificationRule(
        id="marker.internal_header",
        label=SensitivityLabel.INTERNAL,
        pattern=re.compile(r"(?i)\binternal(?:\s+only)?\b|\bcompany\s+confidential\b"),
        description="Explicit internal marker",
    ),
)


class SensitivityClassifier:
    """Pattern-based sensitivity classifier.

    The classifier walks all rules and returns the maximum label whose
    pattern matched. Matching is stateless and thread-safe; runtime
    rule additions are guarded by a lock.

    Args:
        rules: Additional rules to add (in order of registration).
        include_defaults: If False, start with no rules. Useful for
            tests and DLP integrations that supply their own taxonomy.
    """

    def __init__(
        self,
        rules: Iterable[ClassificationRule] | None = None,
        include_defaults: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        base = list(_DEFAULT_RULES) if include_defaults else []
        if rules:
            base.extend(rules)
        self._rules: list[ClassificationRule] = base

    def register(self, rule: ClassificationRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def rules(self) -> tuple[ClassificationRule, ...]:
        with self._lock:
            return tuple(self._rules)

    def classify(self, content: str | bytes | Mapping) -> Classification:
        text = _coerce_text(content)
        if not text:
            return Classification(SensitivityLabel.PUBLIC)

        best = SensitivityLabel.PUBLIC
        matched: list[str] = []
        with self._lock:
            rules_snapshot = tuple(self._rules)

        for rule in rules_snapshot:
            if rule.pattern.search(text):
                matched.append(rule.id)
                if rule.label > best:
                    best = rule.label

        return Classification(label=best, matched_rule_ids=tuple(matched))


def _coerce_text(content: str | bytes | Mapping) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if isinstance(content, Mapping):
        try:
            return json.dumps(content, default=str)
        except Exception:
            return str(content)
    return str(content)


# ---------------------------------------------------------------------------
# High-water mark
# ---------------------------------------------------------------------------


class HWMStore(Protocol):
    """Pluggable backing store for high-water marks. Swap for Redis in prod."""

    def get(self, trajectory_id: str) -> SensitivityLabel: ...
    def set(self, trajectory_id: str, label: SensitivityLabel) -> None: ...
    def delete(self, trajectory_id: str) -> None: ...


class InMemoryHWMStore:
    """Thread-safe in-memory store. Suitable for single-process proxies."""

    def __init__(self) -> None:
        self._data: dict[str, SensitivityLabel] = {}
        self._lock = threading.Lock()

    def get(self, trajectory_id: str) -> SensitivityLabel:
        with self._lock:
            return self._data.get(trajectory_id, SensitivityLabel.PUBLIC)

    def set(self, trajectory_id: str, label: SensitivityLabel) -> None:
        with self._lock:
            self._data[trajectory_id] = label

    def delete(self, trajectory_id: str) -> None:
        with self._lock:
            self._data.pop(trajectory_id, None)


@dataclass
class HighWaterMark:
    """Per-trajectory monotonic max of observed sensitivity labels.

    `observe` is the only way the mark moves; it never goes down. Call
    `reset` at end-of-trajectory (session close, agent reset) to release.
    """

    store: HWMStore = field(default_factory=InMemoryHWMStore)

    def observe(self, trajectory_id: str, label: SensitivityLabel) -> SensitivityLabel:
        current = self.store.get(trajectory_id)
        if label > current:
            self.store.set(trajectory_id, label)
            return label
        return current

    def get(self, trajectory_id: str) -> SensitivityLabel:
        return self.store.get(trajectory_id)

    def reset(self, trajectory_id: str) -> None:
        self.store.delete(trajectory_id)


# ---------------------------------------------------------------------------
# Outbound policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolClassification:
    """How a tool is treated w.r.t. outbound data flow.

    Attributes:
        outbound: True if the tool can emit data outside the trust
            boundary (HTTP, email, webhook, etc.).
        max_sensitivity: Highest label allowed to flow through this tool.
            If the trajectory's HWM exceeds this, OutboundPolicy denies.
    """

    outbound: bool
    max_sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL


@dataclass(frozen=True)
class OutboundDecision:
    allowed: bool
    reason: str = ""
    hwm: SensitivityLabel = SensitivityLabel.PUBLIC
    tool_max: SensitivityLabel = SensitivityLabel.RESTRICTED
    source: str = "tessera.sensitivity"


class OutboundPolicy:
    """Decide whether a tool call is permitted given the trajectory's HWM.

    `registry` maps tool name to ToolClassification. Unknown tools fall
    back to `default_outbound` / `default_max_sensitivity`. Keep the
    registry authoritative in AgentMesh config and pass it in at startup.

    `check()` is a pure function. It reads the HWM but never mutates it.
    Mutations happen only via `HighWaterMark.observe`, which is invoked
    by the /classify endpoint or the proxy's labeling pipeline.

    Args:
        registry: Tool name -> ToolClassification.
        default_outbound: Treatment for tools not in the registry.
        default_max_sensitivity: Envelope for unknown outbound tools.
    """

    def __init__(
        self,
        registry: Mapping[str, ToolClassification] | None = None,
        default_outbound: bool = False,
        default_max_sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL,
    ) -> None:
        self._registry: dict[str, ToolClassification] = dict(registry or {})
        self._default = ToolClassification(
            outbound=default_outbound,
            max_sensitivity=default_max_sensitivity,
        )

    def register(self, tool_name: str, classification: ToolClassification) -> None:
        self._registry[tool_name] = classification

    def classify_tool(self, tool_name: str) -> ToolClassification:
        return self._registry.get(tool_name, self._default)

    def check(self, tool_name: str, hwm: SensitivityLabel) -> OutboundDecision:
        tc = self.classify_tool(tool_name)
        if not tc.outbound:
            return OutboundDecision(
                allowed=True,
                reason="inbound/local tool",
                hwm=hwm,
                tool_max=tc.max_sensitivity,
            )
        if hwm > tc.max_sensitivity:
            return OutboundDecision(
                allowed=False,
                reason=(
                    f"trajectory high-water mark is {hwm.name}; "
                    f"tool {tool_name!r} permits at most {tc.max_sensitivity.name}"
                ),
                hwm=hwm,
                tool_max=tc.max_sensitivity,
            )
        return OutboundDecision(
            allowed=True,
            reason="within tool sensitivity envelope",
            hwm=hwm,
            tool_max=tc.max_sensitivity,
        )


__all__ = [
    "SensitivityLabel",
    "ClassificationRule",
    "Classification",
    "SensitivityClassifier",
    "HWMStore",
    "InMemoryHWMStore",
    "HighWaterMark",
    "ToolClassification",
    "OutboundDecision",
    "OutboundPolicy",
]
