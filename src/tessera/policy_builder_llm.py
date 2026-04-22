"""LLM-driven proposer that emits Proposal objects from a constrained template set.

Layered on top of :mod:`tessera.policy_builder`. Reuses the same
:class:`Proposal` shape so callers can score LLM-generated proposals
through the existing :func:`score_proposal` machinery without caring
where the proposal came from.

Why constrained templates, not free-form CEL synthesis
------------------------------------------------------
LLMs are bad at writing CEL. They hallucinate predicates, miss the
column-major operator semantics, and forget which fields are in scope.
A misgenerated CEL rule that fails to compile is an obvious bug; a
misgenerated CEL rule that compiles but expresses the wrong predicate
is a silent security regression.

This module avoids the problem by keeping the LLM in the
"explanation / recommendation" lane, never in the "code synthesis"
lane. The LLM sees a per-tool aggregate summary and returns structured
output (Pydantic schema) drawn from a small fixed template set:

* ``tighten`` / ``loosen`` a tool's required_trust by one step,
* ``mark_read_only`` to set ``side_effects=False``,
* ``register_tool`` for a tool that appears in audit but isn't in
  ``policy.requirements``.

Each template compiles to a known-good Policy mutation, so the
Proposal's ``new_policy_factory`` always produces a valid Policy.
The LLM contributes signal (which tools to look at, why) and the
deterministic templates contribute correctness.

Failure mode
------------
The proposer wraps a circuit breaker (same pattern as
:class:`tessera.guardrail.LLMGuardrail`). When the breaker is open or
the LLM fails, :meth:`propose` returns an empty list. This is a
"nice to have" feature, not safety-critical, so a quiet failure that
preserves the deterministic baseline is the right behavior.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from tessera.guardrail import BreakerConfig, _Breaker
from tessera.labels import TrustLevel
from tessera.policy import Policy, ResourceType, ToolRequirement
from tessera.policy_builder import (
    Proposal,
    ProposalEvidence,
    ProposalKind,
    _clone_policy_with,
    _collect_evidence,
    _current_requirement,
    _make_loosen,
    _make_tighten,
    _step,
)
from tessera.replay import LabelStore


# ---------------------------------------------------------------------------
# Structured LLM output schema
# ---------------------------------------------------------------------------


_TRUST_LEVEL_NAMES = ("UNTRUSTED", "TOOL", "USER", "SYSTEM")


class LLMProposal(BaseModel, frozen=True):
    """One proposal as the LLM returns it. Constrained to known templates."""

    kind: Literal["tighten", "loosen", "mark_read_only", "register_tool"]
    tool_name: str = Field(min_length=1, max_length=200)
    target_trust: Literal["UNTRUSTED", "TOOL", "USER", "SYSTEM"] | None = None
    rationale: str = Field(default="", max_length=500)
    confidence: float = Field(ge=0.0, le=1.0)


class LLMProposalBatch(BaseModel, frozen=True):
    """The LLM returns a small batch of these."""

    proposals: list[LLMProposal] = Field(default_factory=list, max_length=20)


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT = (
    "You are a security policy reviewer for an AI agent system. "
    "You are given per-tool decision counts and label statistics from a "
    "Tessera audit log. Your job is to suggest small, targeted edits to "
    "the policy from a fixed template set.\n\n"
    "Templates you may use:\n"
    "- tighten: raise required_trust by one step (UNTRUSTED -> TOOL -> "
    "USER -> SYSTEM). Use when allows are labeled INCORRECT.\n"
    "- loosen: lower required_trust by one step. Use when denies are "
    "labeled INCORRECT.\n"
    "- mark_read_only: set side_effects=False. Use when a tool only "
    "reads data and is being denied for taint when it should be exempt.\n"
    "- register_tool: add a default requirement. Use when a tool appears "
    "in audit but is not in the policy.\n\n"
    "Rules:\n"
    "1. Only propose edits supported by the label evidence in the input. "
    "Do not invent.\n"
    "2. Keep proposals to at most 5. Less is better.\n"
    "3. Confidence 0.9+ is reserved for proposals where >= 5 labeled "
    "INCORRECT entries point at the same fix. Use lower confidence "
    "for thinner evidence.\n"
    "4. If no edits are warranted, return an empty proposals list.\n\n"
    "Respond with ONLY a JSON object matching this schema:\n"
    '{"proposals": [{"kind": "tighten|loosen|mark_read_only|register_tool", '
    '"tool_name": "...", "target_trust": "UNTRUSTED|TOOL|USER|SYSTEM"|null, '
    '"rationale": "...", "confidence": 0.0-1.0}]}'
)


def _format_evidence(
    evidence_map: dict[str, ProposalEvidence],
    current_policy: Policy,
) -> str:
    """Render the per-tool stats into a compact prompt."""
    lines = []
    for tool_name, ev in sorted(evidence_map.items()):
        cur = _current_requirement(current_policy, tool_name)
        registered = (tool_name, ResourceType.TOOL) in current_policy.requirements
        lines.append(
            f"tool={tool_name} "
            f"observed={ev.total_observations} "
            f"denied={ev.denied} allowed={ev.allowed} "
            f"labels(deny: correct={ev.labeled_correct_denials} "
            f"incorrect={ev.labeled_incorrect_denials}; "
            f"allow: correct={ev.labeled_correct_allows} "
            f"incorrect={ev.labeled_incorrect_allows}) "
            f"current_required_trust={cur.required_trust.name} "
            f"side_effects={cur.side_effects} "
            f"registered={registered}"
        )
    return "\n".join(lines) if lines else "(no observations)"


# ---------------------------------------------------------------------------
# Template -> Proposal compilers
# ---------------------------------------------------------------------------


def _compile_proposal(
    raw: LLMProposal,
    *,
    current_policy: Policy,
    evidence_map: dict[str, ProposalEvidence],
) -> Proposal | None:
    """Convert one LLMProposal into a real Proposal, or None if invalid.

    Drops anything that:
      - Targets a tool not seen in audit (LLM hallucination guard).
      - Tries to step past the trust ladder boundary.
      - Is structurally incoherent (e.g. tighten with no target).
    """
    ev = evidence_map.get(raw.tool_name)
    if ev is None:
        return None

    if raw.kind == "tighten":
        return _make_tighten(ev, current_policy)
    if raw.kind == "loosen":
        return _make_loosen(ev, current_policy)
    if raw.kind == "mark_read_only":
        return _make_read_only(ev, current_policy)
    if raw.kind == "register_tool":
        return _make_register(ev, raw, current_policy)
    return None


def _make_read_only(
    ev: ProposalEvidence, current_policy: Policy,
) -> Proposal | None:
    cur = _current_requirement(current_policy, ev.tool_name)
    if not cur.side_effects:
        return None  # Already read-only.
    factory = _clone_policy_factory_with_side_effects(
        current_policy, ev.tool_name, side_effects=False,
    )
    return Proposal(
        kind=ProposalKind.LOOSEN_REQUIREMENT,  # Read-only is a form of loosen.
        tool_name=ev.tool_name,
        current_required_trust=cur.required_trust,
        proposed_required_trust=cur.required_trust,
        summary=(
            f"Mark {ev.tool_name} as read-only "
            f"(side_effects=False)"
        ),
        rationale=(
            f"{ev.tool_name} appears to read-only on its observed traffic; "
            f"setting side_effects=False exempts it from the taint-floor "
            f"denial. Replay against the labeled history will catch any "
            f"regression on labeled-CORRECT denials."
        ),
        evidence=ev,
        diff=f"{ev.tool_name}: side_effects True -> False",
        new_policy_factory=factory,
    )


def _make_register(
    ev: ProposalEvidence,
    raw: LLMProposal,
    current_policy: Policy,
) -> Proposal | None:
    if (ev.tool_name, ResourceType.TOOL) in current_policy.requirements:
        return None  # Already registered; tighten/loosen is the right path.
    target_name = raw.target_trust or "USER"
    if target_name not in _TRUST_LEVEL_NAMES:
        return None
    target = TrustLevel[target_name]
    factory = _clone_policy_with(current_policy, ev.tool_name, target)
    return Proposal(
        kind=ProposalKind.TIGHTEN_REQUIREMENT,
        tool_name=ev.tool_name,
        current_required_trust=current_policy.default_required_trust,
        proposed_required_trust=target,
        summary=(
            f"Register {ev.tool_name} with required_trust={target.name}"
        ),
        rationale=(
            f"{ev.tool_name} appears in audit but has no explicit "
            f"requirement; falls back to default_required_trust="
            f"{current_policy.default_required_trust.name}. "
            f"An explicit registration makes the rule audit-friendly."
        ),
        evidence=ev,
        diff=(
            f"{ev.tool_name}: register required_trust="
            f"{target.name}"
        ),
        new_policy_factory=factory,
    )


def _clone_policy_factory_with_side_effects(
    base: Policy, tool_name: str, *, side_effects: bool,
):
    """Like ``_clone_policy_with`` but flips ``side_effects`` instead of trust."""
    snapshot_reqs = dict(base.requirements)
    snapshot_request = dict(base.request_requirements)
    snapshot_base = dict(base.base_requirements) if base.base_requirements else None
    default = base.default_required_trust
    backend = base.backend
    fail_closed = base.fail_closed_backend_errors
    cel_engine = base.cel_engine
    scope = base.scope
    cur = _current_requirement(base, tool_name)

    def factory() -> Policy:
        p = Policy(
            requirements=dict(snapshot_reqs),
            default_required_trust=default,
            backend=backend,
            fail_closed_backend_errors=fail_closed,
            base_requirements=dict(snapshot_base) if snapshot_base else None,
            request_requirements=dict(snapshot_request),
            scope=scope,
            cel_engine=cel_engine,
        )
        p.requirements[(tool_name, ResourceType.TOOL)] = ToolRequirement(
            name=tool_name,
            resource_type=ResourceType.TOOL,
            required_trust=cur.required_trust,
            side_effects=side_effects,
        )
        return p

    return factory


# ---------------------------------------------------------------------------
# Proposer
# ---------------------------------------------------------------------------


class LLMPolicyProposer:
    """Wraps an LLM client to produce :class:`Proposal` objects.

    Usage::

        from anthropic import Anthropic
        proposer = LLMPolicyProposer(
            client=Anthropic(),
            model="claude-haiku-4-5-20251001",
        )
        proposals = proposer.propose(
            audit_log_path,
            current_policy=current_policy,
            labels=label_store,
        )

    Args:
        client: Anthropic or OpenAI-compatible client.
        model: Model name.
        client_type: ``"anthropic"`` or ``"openai"``. Auto-detected from
            the client object when not provided.
        max_tokens: Cap on the LLM response budget.
        breaker: Optional :class:`BreakerConfig`. Defaults to the same
            shape as :class:`tessera.guardrail.LLMGuardrail` (5 failures,
            30s open).
    """

    def __init__(
        self,
        client: Any,
        model: str,
        *,
        client_type: str | None = None,
        max_tokens: int = 600,
        breaker: BreakerConfig | None = None,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._breaker = _Breaker(breaker or BreakerConfig())

        if client_type is not None:
            self._client_type = client_type
        elif hasattr(client, "messages"):
            self._client_type = "anthropic"
        elif hasattr(client, "chat"):
            self._client_type = "openai"
        else:
            raise ValueError(
                "Cannot auto-detect client type. "
                "Pass client_type='anthropic' or 'openai'."
            )

    def propose(
        self,
        audit_log_path: str | Path,
        *,
        current_policy: Policy,
        labels: LabelStore | None = None,
    ) -> list[Proposal]:
        """Return zero or more proposals based on labeled audit history.

        Returns ``[]`` when:
          - The breaker is open.
          - The LLM raises or returns unparseable output.
          - There is no observed audit data.
        """
        skip, _ = self._breaker.should_skip()
        if skip:
            return []

        evidence_map = _collect_evidence(audit_log_path, labels=labels)
        if not evidence_map:
            return []

        user_msg = (
            f"Current default_required_trust: "
            f"{current_policy.default_required_trust.name}\n\n"
            f"Per-tool observations:\n{_format_evidence(evidence_map, current_policy)}"
        )

        try:
            raw_response = self._call_llm(user_msg)
            batch = self._parse_response(raw_response)
            self._breaker.record_success()
        except (Exception,):  # noqa: BLE001
            self._breaker.record_failure()
            return []

        proposals: list[Proposal] = []
        for raw in batch.proposals:
            compiled = _compile_proposal(
                raw,
                current_policy=current_policy,
                evidence_map=evidence_map,
            )
            if compiled is not None:
                proposals.append(compiled)
        return proposals

    @property
    def breaker_state(self):
        return self._breaker.snapshot()

    def _call_llm(self, user_msg: str) -> str:
        if self._client_type == "anthropic":
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            return response.content[0].text
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.0,
        )
        return response.choices[0].message.content

    def _parse_response(self, raw: str) -> LLMProposalBatch:
        """Strip code fences, locate the JSON object, validate against schema."""
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(
                ln for ln in lines if not ln.strip().startswith("```")
            ).strip()
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]
        data = json.loads(text)
        try:
            return LLMProposalBatch.model_validate(data)
        except ValidationError as e:
            raise ValueError(f"LLM returned invalid proposal batch: {e}")


__all__ = [
    "LLMPolicyProposer",
    "LLMProposal",
    "LLMProposalBatch",
]
