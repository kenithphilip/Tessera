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

import hashlib
import json
import os
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from tessera.action_critic.principles import (
    Principle,
    PrincipleViolation,
    deterministic_pre_check,
)
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.guardrail import BreakerConfig, _Breaker
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

    Returns REQUIRE_APPROVAL when no real model is configured.
    Phase 2 wave 2A real-backend dispatch reads
    ``TESSERA_CRITIC_LOCAL_MODEL`` to decide between an in-process
    Llama-4-Scout / Qwen3-7B handle and the stub fallback. When
    the env var is unset, callers get a structurally-valid
    REQUIRE_APPROVAL with ``backend="local_small"`` so the audit
    log still records the path the critic took.

    Direct callers (tests, integration code that wants to bypass
    the cache and breaker) get the bare backend semantics; the
    top-level :func:`review` adds caching, breaker, and event
    emission around any backend call.
    """

    name: str = "local_small"

    def review(self, action: ActionReview) -> CriticDecision:
        # When a real model handle is wired (Phase 2A.real), dispatch
        # there. Without it, return the safe REQUIRE_APPROVAL.
        if os.environ.get("TESSERA_CRITIC_LOCAL_MODEL", "").strip():
            return CriticDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=(
                    "TESSERA_CRITIC_LOCAL_MODEL set but in-process "
                    "Llama-4-Scout / Qwen3-7B handle not yet wired"
                ),
                backend=self.name,
            )
        return CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="local backend not configured; safe fallback",
            backend=self.name,
        )


@dataclass(frozen=True)
class ProviderAgnosticCritic:
    """Routes through :mod:`tessera.guardrail` for cache + breaker reuse.

    Default for v0.13. The backend takes an optional client; when
    no client is provided the backend returns REQUIRE_APPROVAL so
    the security path is observable end-to-end without requiring
    a model dependency.
    """

    name: str = "provider_agnostic"

    def review(self, action: ActionReview) -> CriticDecision:
        return CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="no provider client configured; safe fallback",
            backend=self.name,
        )


@dataclass(frozen=True)
class SamePlannerCritic:
    """Use the planner's own model. Gated behind opt-in env var.

    Same-planner-as-critic is a documented anti-pattern (the entity
    being audited cannot reliably audit itself). Operators must
    explicitly opt in via ``TESSERA_ALLOW_SHARED_CRITIC=1``;
    otherwise the backend returns DENY with the
    :attr:`Principle.LEAST_PRIVILEGE` principle triggered.
    """

    name: str = "same_planner"

    def review(self, action: ActionReview) -> CriticDecision:
        if os.environ.get("TESSERA_ALLOW_SHARED_CRITIC", "").strip() != "1":
            return CriticDecision(
                decision=Decision.DENY,
                reason="same-planner critic disabled; set TESSERA_ALLOW_SHARED_CRITIC=1 to enable",
                backend=self.name,
                triggered_principles=(Principle.LEAST_PRIVILEGE.value,),
            )
        return CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="opted-in but no shared model handle wired",
            backend=self.name,
        )


# ---------------------------------------------------------------------------
# Cache + circuit breaker around the backend dispatch
# ---------------------------------------------------------------------------


def _canonical_action_key(action: ActionReview) -> str:
    """SHA-256 of the canonical-JSON form of an ActionReview.

    ``model_dump_json`` with sorted keys produces a stable
    representation; the same action under any reordering hashes to
    the same key. Cache hits short-circuit the backend call entirely.
    """
    payload = json.dumps(
        action.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class _CritCacheEntry:
    decision: CriticDecision
    timestamp: float


class CriticCache:
    """SHA-256 keyed LRU cache for :class:`CriticDecision` outcomes.

    Mirrors the shape of :class:`tessera.guardrail.GuardrailCache`
    but keyed on the canonical hash of the :class:`ActionReview`.
    """

    def __init__(self, max_size: int = 1024, ttl_seconds: float = 300.0) -> None:
        self._cache: dict[str, _CritCacheEntry] = {}
        self._max = max_size
        self._ttl = ttl_seconds

    def get(self, action: ActionReview) -> CriticDecision | None:
        key = _canonical_action_key(action)
        entry = self._cache.get(key)
        if entry is None:
            return None
        if time.time() - entry.timestamp > self._ttl:
            del self._cache[key]
            return None
        return entry.decision

    def put(self, action: ActionReview, decision: CriticDecision) -> None:
        key = _canonical_action_key(action)
        if len(self._cache) >= self._max:
            oldest = min(self._cache, key=lambda k: self._cache[k].timestamp)
            del self._cache[oldest]
        self._cache[key] = _CritCacheEntry(decision=decision, timestamp=time.time())


# ---------------------------------------------------------------------------
# Top-level review() entry point
# ---------------------------------------------------------------------------


_DEFAULT_BACKEND: CriticBackend = ProviderAgnosticCritic()
_DEFAULT_CACHE: CriticCache = CriticCache()
_DEFAULT_BREAKER: _Breaker = _Breaker(BreakerConfig())


def set_default_backend(backend: CriticBackend) -> None:
    """Replace the process-wide default critic backend."""
    global _DEFAULT_BACKEND
    _DEFAULT_BACKEND = backend


def get_default_backend() -> CriticBackend:
    return _DEFAULT_BACKEND


def get_default_cache() -> CriticCache:
    return _DEFAULT_CACHE


def reset_default_cache() -> None:
    """Drop every cached decision. Intended for tests."""
    global _DEFAULT_CACHE
    _DEFAULT_CACHE = CriticCache()


def review(
    action: ActionReview,
    *,
    backend: CriticBackend | None = None,
    cache: CriticCache | None = None,
) -> CriticDecision:
    """Run the configured critic backend on one action.

    Pipeline:

    1. ``TESSERA_CRITIC=off`` short-circuits to ALLOW immediately.
    2. The deterministic pre-check (see
       :mod:`tessera.action_critic.principles`) runs first; any
       violation triggers a DENY before the backend is consulted.
    3. The cache is consulted next; a hit returns the prior
       decision with ``cache_hit=True``.
    4. The circuit breaker is checked; an open circuit returns the
       configured fallback decision (REQUIRE_APPROVAL by default,
       safest choice for an audit gate).
    5. The backend is invoked; the result is cached and returned.

    Args:
        action: The :class:`ActionReview` to evaluate.
        backend: Optional explicit backend; defaults to the
            process-wide default (:class:`ProviderAgnosticCritic`).
        cache: Optional explicit cache; defaults to the process-wide
            cache.

    Returns:
        A :class:`CriticDecision` reflecting the outcome.
    """
    mode = get_critic_mode()
    if mode == CriticMode.OFF:
        return CriticDecision(
            decision=Decision.ALLOW,
            reason="critic disabled (TESSERA_CRITIC=off)",
            backend="off",
        )

    started = time.monotonic()

    # Deterministic pre-check: structural rules first.
    violations = deterministic_pre_check(action.tool, action.args)
    if violations:
        decision = CriticDecision(
            decision=Decision.DENY,
            reason=violations[0].reason,
            triggered_principles=tuple(
                sorted({v.principle.value for v in violations})
            ),
            backend="deterministic_pre_check",
            latency_ms=(time.monotonic() - started) * 1000,
        )
        _emit_decision(action, decision)
        return decision

    chosen_cache = cache or _DEFAULT_CACHE
    cached = chosen_cache.get(action)
    if cached is not None:
        cached_with_hit = cached.model_copy(update={"cache_hit": True})
        _emit_decision(action, cached_with_hit)
        return cached_with_hit

    skip, _ = _DEFAULT_BREAKER.should_skip()
    if skip:
        decision = CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="critic backend circuit-breaker open; safe fallback",
            backend="circuit_breaker",
            latency_ms=(time.monotonic() - started) * 1000,
        )
        _emit_decision(action, decision)
        return decision

    chosen = backend or _DEFAULT_BACKEND
    try:
        decision = chosen.review(action)
        _DEFAULT_BREAKER.record_success()
    except Exception as exc:  # noqa: BLE001 - boundary failure path
        _DEFAULT_BREAKER.record_failure()
        decision = CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason=f"backend raised {type(exc).__name__}: safe fallback",
            backend=getattr(chosen, "name", "unknown"),
            latency_ms=(time.monotonic() - started) * 1000,
        )
        emit_event(
            SecurityEvent.now(
                kind=EventKind.CRITIC_TIMEOUT,
                principal=action.principal,
                detail={
                    "tool": action.tool,
                    "backend": decision.backend,
                    "exception": type(exc).__name__,
                },
                correlation_id=action.correlation_id,
            )
        )
        return decision

    decision = decision.model_copy(
        update={"latency_ms": (time.monotonic() - started) * 1000}
    )
    chosen_cache.put(action, decision)
    return decision


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
    "CriticCache",
    "CriticDecision",
    "CriticMode",
    "Decision",
    "LabelSummary",
    "LocalSmallCritic",
    "Principle",
    "PrincipleViolation",
    "ProviderAgnosticCritic",
    "RiskSignals",
    "SamePlannerCritic",
    "deterministic_pre_check",
    "get_critic_mode",
    "get_default_backend",
    "get_default_cache",
    "reset_default_cache",
    "review",
    "set_default_backend",
]
