"""Action Critic: metadata-only second opinion on tool calls.

The Action Critic is a lightweight model that reviews each tool call
the planner proposes against a small set of principles (data
minimization, origin consistency, irreversibility, least privilege,
no exfiltration, untrusted-arg reasonableness; see
``principles/v1.yaml``). It NEVER sees raw untrusted text; only the
metadata of the proposed call: tool name, argument shapes (types,
lengths, character classes), per-argument :class:`ProvenanceLabel`
summaries, the principal, and risk signals derived from policy
state.

The critic returns one of:

- :attr:`Decision.ALLOW`: the call may proceed.
- :attr:`Decision.DENY`: the call must be blocked.
- :attr:`Decision.REQUIRE_APPROVAL`: a human-in-the-loop must
  approve before the call fires.

Three backend implementations are stubbed for the v0.12 wave:

- :class:`LocalSmallCritic`: small open-weight model
  (Llama-4-Scout / Qwen3-7B). Fastest path; sub-100ms p50.
- :class:`ProviderAgnosticCritic`: routes to the existing
  :mod:`tessera.guardrail` backend for caching and retries.
- :class:`SamePlannerCritic`: uses the same model that proposed
  the action. Cheap but riskier because the planner is the entity
  being audited; gated behind ``TESSERA_ALLOW_SHARED_CRITIC=1``.

For v0.12 every backend is a no-op stub returning REQUIRE_APPROVAL,
so the security path is observable end-to-end without forcing a
new model dependency. Phase 2 wave 2A wires real backends.

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 2.
- ``docs/adr/0006-arg-level-provenance-primary.md``.
- LlamaFirewall AlignmentCheck.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
    ProvenanceLabel,
    Public,
    SecrecyLevel,
)


# ---------------------------------------------------------------------------
# Enforcement mode env var (mirrors policy.tool_critical_args).
# ---------------------------------------------------------------------------


class CriticMode(StrEnum):
    """Values for the ``TESSERA_CRITIC`` env var."""

    OFF = "off"
    STUB = "stub"
    ON = "on"


def get_critic_mode() -> CriticMode:
    """Return the active critic mode.

    Default is :attr:`CriticMode.OFF` for v0.12 so the critic does
    not gate calls until Phase 2 wave 2A wires real backends.
    Operators can opt in to ``stub`` (calls always require approval,
    useful for end-to-end observability tests) or ``on`` (real
    backend dispatch).
    """
    raw = os.environ.get("TESSERA_CRITIC", "off").strip().lower()
    try:
        return CriticMode(raw)
    except ValueError:
        return CriticMode.OFF


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class LabelSummary(BaseModel):
    """Compact ``ProvenanceLabel`` summary for the critic.

    Critics MUST NOT see raw untrusted bytes; the integrity /
    secrecy / capacity dimensions are sufficient for principle
    evaluation and avoid leaking adversarial payloads into the
    critic's context.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    integrity: IntegrityLevel
    secrecy: SecrecyLevel
    capacity: InformationCapacity
    source_count: int = Field(ge=0)
    reader_principals: tuple[str, ...] | None = None

    @classmethod
    def from_label(cls, label: ProvenanceLabel) -> "LabelSummary":
        readers: tuple[str, ...] | None = None
        if not isinstance(label.readers, Public):
            readers = tuple(sorted(label.readers))
        return cls(
            integrity=label.integrity,
            secrecy=label.secrecy,
            capacity=label.capacity,
            source_count=len(label.sources),
            reader_principals=readers,
        )


class ArgShape(BaseModel):
    """Structural summary of one tool-call argument.

    Carries no raw bytes from the argument's value; only its
    type, length, character-class footprint, and label summary.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    name: str
    type_hint: str
    length: int = Field(ge=0)
    char_classes: tuple[str, ...] = Field(default_factory=tuple)
    label: LabelSummary


class RiskSignals(BaseModel):
    """Pre-computed deterministic risk signals from policy state."""

    model_config = ConfigDict(strict=True, frozen=True)

    irreversibility_class: str = "unknown"
    sensitivity_class: str = "unknown"
    rate_limit_pressure: float = Field(default=0.0, ge=0.0, le=1.0)
    has_recent_denials: bool = False
    has_dependent_args: bool = False


class ActionReview(BaseModel):
    """Input passed to the critic for one tool call.

    The critic NEVER receives the raw arguments; only :class:`ArgShape`
    entries that have been pre-summarized. This is the load-bearing
    boundary: any backend that breaks it (e.g. by stuffing the raw
    args into a prompt) is a security regression.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    tool: str
    principal: str
    args: tuple[ArgShape, ...]
    risk: RiskSignals = Field(default_factory=RiskSignals)
    correlation_id: str | None = None


class Decision(StrEnum):
    """The outcome the critic returns for one tool call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class CriticDecision(BaseModel):
    """The critic's verdict on one :class:`ActionReview`."""

    model_config = ConfigDict(strict=True, frozen=True)

    decision: Decision
    reason: str
    triggered_principles: tuple[str, ...] = Field(default_factory=tuple)
    backend: str = "stub"
    latency_ms: float = Field(default=0.0, ge=0.0)
    cache_hit: bool = False


# ---------------------------------------------------------------------------
# Backend protocol + stubs
# ---------------------------------------------------------------------------


class CriticBackend(Protocol):
    """Backends implement one method: review one action.

    Implementations must NEVER materialize the raw argument values
    from outside the :class:`ActionReview` they receive; the
    boundary is enforced structurally by the model.
    """

    name: str

    def review(self, action: ActionReview) -> CriticDecision: ...


@dataclass(frozen=True)
class LocalSmallCritic:
    """Stub for a small open-weight critic model.

    The v0.12 stub returns REQUIRE_APPROVAL on every call and emits
    :attr:`EventKind.CRITIC_APPROVAL_REQUIRED`. Phase 2 wave 2A
    wires Llama-4-Scout / Qwen3-7B via Together / Groq.
    """

    name: str = "local_small"

    def review(self, action: ActionReview) -> CriticDecision:
        decision = CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="stub: real backend not wired in v0.12",
            backend=self.name,
        )
        _emit_decision(action, decision)
        return decision


@dataclass(frozen=True)
class ProviderAgnosticCritic:
    """Stub backend that will route to :mod:`tessera.guardrail`.

    Will use the existing guardrail SHA-256 cache and circuit
    breaker. Returns REQUIRE_APPROVAL today.
    """

    name: str = "provider_agnostic"

    def review(self, action: ActionReview) -> CriticDecision:
        decision = CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="stub: real backend not wired in v0.12",
            backend=self.name,
        )
        _emit_decision(action, decision)
        return decision


@dataclass(frozen=True)
class SamePlannerCritic:
    """Stub backend that would use the planner's own model.

    Gated behind ``TESSERA_ALLOW_SHARED_CRITIC=1`` because using
    the planner-as-critic creates an obvious self-attestation
    weakness: the planner is the entity being audited.
    """

    name: str = "same_planner"

    def review(self, action: ActionReview) -> CriticDecision:
        if os.environ.get("TESSERA_ALLOW_SHARED_CRITIC", "").strip() != "1":
            decision = CriticDecision(
                decision=Decision.DENY,
                reason="same-planner critic disabled; set TESSERA_ALLOW_SHARED_CRITIC=1 to enable",
                backend=self.name,
                triggered_principles=("least_privilege",),
            )
            _emit_decision(action, decision)
            return decision
        decision = CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="stub: real backend not wired in v0.12",
            backend=self.name,
        )
        _emit_decision(action, decision)
        return decision


# ---------------------------------------------------------------------------
# Top-level review() entry point
# ---------------------------------------------------------------------------


_DEFAULT_BACKEND: CriticBackend = ProviderAgnosticCritic()


def set_default_backend(backend: CriticBackend) -> None:
    """Replace the process-wide default critic backend."""
    global _DEFAULT_BACKEND
    _DEFAULT_BACKEND = backend


def get_default_backend() -> CriticBackend:
    return _DEFAULT_BACKEND


def review(
    action: ActionReview,
    *,
    backend: CriticBackend | None = None,
) -> CriticDecision:
    """Run the configured critic backend on one action.

    Returns ALLOW immediately when ``TESSERA_CRITIC=off``. Otherwise
    dispatches to the backend (default :class:`ProviderAgnosticCritic`
    stub).
    """
    mode = get_critic_mode()
    if mode == CriticMode.OFF:
        return CriticDecision(
            decision=Decision.ALLOW,
            reason="critic disabled (TESSERA_CRITIC=off)",
            backend="off",
        )
    chosen = backend or _DEFAULT_BACKEND
    return chosen.review(action)


def _emit_decision(action: ActionReview, decision: CriticDecision) -> None:
    """Map a :class:`CriticDecision` to the matching SecurityEvent."""
    kind_map = {
        Decision.ALLOW: EventKind.CRITIC_ALLOW,
        Decision.DENY: EventKind.CRITIC_DENY,
        Decision.REQUIRE_APPROVAL: EventKind.CRITIC_APPROVAL_REQUIRED,
    }
    emit_event(
        SecurityEvent.now(
            kind=kind_map[decision.decision],
            principal=action.principal,
            detail={
                "tool": action.tool,
                "backend": decision.backend,
                "reason": decision.reason,
                "triggered_principles": list(decision.triggered_principles),
                "cache_hit": decision.cache_hit,
                "latency_ms": decision.latency_ms,
            },
            correlation_id=action.correlation_id,
        )
    )


__all__ = [
    "ActionReview",
    "ArgShape",
    "CriticBackend",
    "CriticDecision",
    "CriticMode",
    "Decision",
    "LabelSummary",
    "LocalSmallCritic",
    "ProviderAgnosticCritic",
    "RiskSignals",
    "SamePlannerCritic",
    "get_critic_mode",
    "get_default_backend",
    "review",
    "set_default_backend",
]
