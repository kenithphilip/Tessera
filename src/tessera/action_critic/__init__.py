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

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

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

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    name: str
    type_hint: str
    length: int = Field(ge=0)
    char_classes: tuple[str, ...] = Field(default_factory=tuple)
    label: LabelSummary


class ActionImpact(StrEnum):
    """SEP-1913 actionImpact annotation values.

    Mirrors the enum in :data:`tessera.mcp.manifest_schema.MCP_MANIFEST_STATEMENT_SCHEMA`.
    Drives the circuit-breaker fail-mode at the critic boundary:
    DESTRUCTIVE actions never PASS_THROUGH on breaker open; benign
    reads do.
    """

    BENIGN = "benign"
    SIDE_EFFECT = "side-effect"
    DESTRUCTIVE = "destructive"


class RiskSignals(BaseModel):
    """Pre-computed deterministic risk signals from policy state."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

    irreversibility_class: str = "unknown"
    sensitivity_class: str = "unknown"
    rate_limit_pressure: float = Field(default=0.0, ge=0.0, le=1.0)
    has_recent_denials: bool = False
    has_dependent_args: bool = False
    action_impact: ActionImpact = ActionImpact.SIDE_EFFECT


class ActionReview(BaseModel):
    """Input passed to the critic for one tool call.

    The critic NEVER receives the raw arguments; only :class:`ArgShape`
    entries that have been pre-summarized. This is the load-bearing
    boundary: any backend that breaks it (e.g. by stuffing the raw
    args into a prompt) is a security regression.
    """

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

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

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

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


_CRITIC_SYSTEM_PROMPT = (
    "You are an Action Critic for an AI agent system. You receive "
    "metadata about a tool call the planner wants to make: the tool "
    "name, the SHAPES of the arguments (no raw values), per-argument "
    "provenance label summaries, and risk signals. You decide whether "
    "the call should ALLOW, DENY, or REQUIRE_APPROVAL based on six "
    "principles: data_minimization, origin_consistency, irreversibility, "
    "least_privilege, no_exfiltration, untrusted_arg_reasonable.\n\n"
    "Respond with a JSON object: "
    '{"decision": "allow|deny|require_approval", '
    '"reason": "<one sentence>", '
    '"triggered_principles": ["..."]}'
)


def _decision_from_json(payload: str, backend_name: str) -> CriticDecision:
    """Parse a JSON response from a real LLM into a CriticDecision.

    Tolerates a wrapping code-fence or leading prose; extracts the
    first balanced JSON object. Falls back to REQUIRE_APPROVAL on
    any parse failure (no parsed JSON means we cannot trust the
    backend output).
    """
    text = payload.strip()
    # Strip surrounding code fence if present.
    if text.startswith("```"):
        # Find the fence end.
        try:
            text = text.split("```", 2)[1]
            if text.lower().startswith("json"):
                text = text[4:]
        except IndexError:
            pass
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return CriticDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason="backend returned unparseable JSON; safe fallback",
            backend=backend_name,
        )
    decision_raw = str(data.get("decision", "require_approval")).lower()
    try:
        decision = Decision(decision_raw)
    except ValueError:
        decision = Decision.REQUIRE_APPROVAL
    reason = str(data.get("reason", ""))[:240]
    principles_raw = data.get("triggered_principles") or []
    if not isinstance(principles_raw, list):
        principles_raw = []
    triggered = tuple(str(p) for p in principles_raw)
    return CriticDecision(
        decision=decision,
        reason=reason or "no reason provided",
        triggered_principles=triggered,
        backend=backend_name,
    )


def _build_user_prompt(action: ActionReview) -> str:
    """Render an ActionReview as a JSON-only user prompt.

    The prompt carries argument SHAPES and label summaries, never raw
    values. The structural boundary is enforced by ActionReview's
    Pydantic config (no value field anywhere on ArgShape).
    """
    return (
        "Tool call metadata to review (no raw values):\n"
        + json.dumps(action.model_dump(mode="json"), indent=2, sort_keys=True)
    )


@dataclass
class LocalSmallCritic:
    """Small open-weight critic via Together / Groq HTTP API.

    Reads ``TESSERA_CRITIC_LOCAL_MODEL`` (e.g. ``llama-4-scout-17b``
    or ``qwen3-7b-instruct``) plus one of:

    - ``TOGETHER_API_KEY`` for the Together inference endpoint
    - ``GROQ_API_KEY`` for the Groq inference endpoint

    When neither key is configured the backend returns
    REQUIRE_APPROVAL so the audit log still records the path; this
    keeps deployments observable without forcing a paid model
    dependency at v0.13. The HTTP call is a thin wrapper around
    the standard Chat-Completions schema both providers expose.

    Default model: ``meta-llama/Llama-4-Scout-17B-16E-Instruct`` on
    Together. Override per request via ``TESSERA_CRITIC_LOCAL_MODEL``.
    """

    name: str = "local_small"
    timeout: float = 5.0
    http_client: Any = None
    model_override: str | None = None

    def _resolve_provider(self) -> tuple[str, str, str] | None:
        """Return (api_url, api_key, model) or None when not configured."""
        model = (
            self.model_override
            or os.environ.get("TESSERA_CRITIC_LOCAL_MODEL", "").strip()
            or "meta-llama/Llama-4-Scout-17B-16E-Instruct"
        )
        if os.environ.get("TOGETHER_API_KEY", "").strip():
            return (
                "https://api.together.xyz/v1/chat/completions",
                os.environ["TOGETHER_API_KEY"].strip(),
                model,
            )
        if os.environ.get("GROQ_API_KEY", "").strip():
            return (
                "https://api.groq.com/openai/v1/chat/completions",
                os.environ["GROQ_API_KEY"].strip(),
                model,
            )
        return None

    def review(self, action: ActionReview) -> CriticDecision:
        provider = self._resolve_provider()
        if provider is None:
            return CriticDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=(
                    "no provider key (TOGETHER_API_KEY or GROQ_API_KEY) configured; "
                    "safe fallback"
                ),
                backend=self.name,
            )
        url, api_key, model = provider
        client = self.http_client
        if client is None:
            try:
                import httpx
            except ImportError:  # pragma: no cover - dep is required
                return CriticDecision(
                    decision=Decision.REQUIRE_APPROVAL,
                    reason="httpx unavailable; safe fallback",
                    backend=self.name,
                )
            client = httpx.Client(timeout=self.timeout)
        try:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "temperature": 0.0,
                    "max_tokens": 256,
                    "messages": [
                        {"role": "system", "content": _CRITIC_SYSTEM_PROMPT},
                        {"role": "user", "content": _build_user_prompt(action)},
                    ],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
        except Exception as exc:  # noqa: BLE001 - network boundary
            return CriticDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"backend error: {type(exc).__name__}",
                backend=self.name,
            )
        return _decision_from_json(text, self.name)


@dataclass
class ProviderAgnosticCritic:
    """Routes through :mod:`tessera.guardrail` for cache + breaker reuse.

    Default backend for v0.13. The backend wraps an Anthropic or
    OpenAI client (the same shape :class:`tessera.guardrail.LLMGuardrail`
    expects) and uses the provider's structured response to drive
    the critic decision. When no client is configured, returns
    REQUIRE_APPROVAL so the audit path stays observable.
    """

    name: str = "provider_agnostic"
    client: Any = None
    model: str = "claude-haiku-4-5-20251001"
    max_tokens: int = 256
    timeout: float = 5.0

    def _resolve_client_type(self) -> str | None:
        if self.client is None:
            return None
        if hasattr(self.client, "messages"):
            return "anthropic"
        if hasattr(self.client, "chat"):
            return "openai"
        return None

    def review(self, action: ActionReview) -> CriticDecision:
        client_type = self._resolve_client_type()
        if client_type is None:
            return CriticDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason="no provider client configured; safe fallback",
                backend=self.name,
            )
        prompt = _build_user_prompt(action)
        try:
            if client_type == "anthropic":
                resp = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=_CRITIC_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = resp.content[0].text
            else:
                resp = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=0.0,
                    messages=[
                        {"role": "system", "content": _CRITIC_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
                text = resp.choices[0].message.content
        except Exception as exc:  # noqa: BLE001
            return CriticDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"backend error: {type(exc).__name__}",
                backend=self.name,
            )
        return _decision_from_json(text, self.name)


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

    ``model_dump`` with sorted keys produces a stable representation;
    the same action under any reordering hashes to the same key.
    Cache hits short-circuit the backend call entirely.
    """
    payload = json.dumps(
        action.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CriticCache:
    """SHA-256 keyed LRU cache for :class:`CriticDecision` outcomes.

    Reuses :class:`tessera.guardrail.GuardrailCache` for the LRU /
    TTL machinery and adapts the key shape to the canonical-JSON
    hash of the :class:`ActionReview`. ``GuardrailCache`` already
    has the SHA-256 + TTL + eviction logic; we only adapt the
    key-derivation step.
    """

    def __init__(self, max_size: int = 1024, ttl_seconds: float = 300.0) -> None:
        from tessera.guardrail import GuardrailCache

        self._inner = GuardrailCache(
            max_size=max_size, ttl_seconds=ttl_seconds
        )

    @staticmethod
    def _to_decision_payload(decision: CriticDecision) -> Any:
        """GuardrailCache stores GuardrailDecision; we round-trip
        a CriticDecision through a JSON string keyed via the inner
        cache's text+tool_name slot."""
        return decision.model_dump_json()

    @staticmethod
    def _from_decision_payload(payload: Any) -> CriticDecision | None:
        """Reconstruct a CriticDecision from the inner cache's stored
        slot. Returns None on any decode failure."""
        if payload is None:
            return None
        try:
            return CriticDecision.model_validate_json(payload)
        except Exception:  # noqa: BLE001
            return None

    def get(self, action: ActionReview) -> CriticDecision | None:
        key = _canonical_action_key(action)
        entry = self._inner.get(key, "critic")
        if entry is None:
            return None
        # GuardrailDecision.category is the only string slot in
        # the GuardrailDecision schema; we store the canonical-JSON
        # CriticDecision there. This keeps GuardrailCache as the
        # single LRU + TTL implementation in the tree.
        return self._from_decision_payload(entry.category)

    def put(self, action: ActionReview, decision: CriticDecision) -> None:
        from tessera.guardrail import GuardrailDecision

        key = _canonical_action_key(action)
        encoded = self._to_decision_payload(decision)
        self._inner.put(
            key,
            "critic",
            GuardrailDecision(
                is_injection=False,
                confidence=0.0,
                category=encoded,
            ),
        )


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
        # actionImpact gating: when the backend is down, the
        # fallback differs by impact class. DESTRUCTIVE actions
        # cannot proceed without a live critic and a positive
        # confirmation, so we DENY rather than defer to a human
        # that may not be reachable. SIDE-EFFECT and BENIGN actions
        # fall back to REQUIRE_APPROVAL (the conservative default
        # for any action whose review path is degraded).
        if action.risk.action_impact == ActionImpact.DESTRUCTIVE:
            fallback_decision = Decision.DENY
            fallback_reason = (
                "critic backend circuit-breaker open AND tool is "
                "destructive; deny rather than defer"
            )
        else:
            fallback_decision = Decision.REQUIRE_APPROVAL
            fallback_reason = (
                "critic backend circuit-breaker open; safe fallback "
                f"for action_impact={action.risk.action_impact.value}"
            )
        decision = CriticDecision(
            decision=fallback_decision,
            reason=fallback_reason,
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
    "ActionImpact",
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
