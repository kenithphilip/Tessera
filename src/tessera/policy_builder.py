"""Suggest policy edits from audit history, then score them via replay.

This is the deterministic foundation of the policy-builder workflow.
It reads the JSONL audit log, aggregates per-tool decision counts and
ground-truth labels, and proposes targeted ToolRequirement adjustments
where the data is unambiguous. Each proposal carries a factory that
returns a candidate :class:`tessera.policy.Policy`; pass that factory
to :func:`score_proposal` to measure the proposal's impact against the
recorded history via :mod:`tessera.replay`.

There is no LLM in this module on purpose. An LLM-driven proposer can
be layered on top: it generates additional :class:`Proposal` objects
(e.g. CEL-rule synthesis), and reuses :func:`score_proposal` for
evaluation. Keeping the analyzer deterministic gives operators an
explainable baseline they can trust before any model is involved.

Heuristics
----------
Both rules require ground-truth labels (:class:`tessera.replay.Label`)
on the audit entries; without labels there is no signal that a current
decision is wrong, so the analyzer emits no proposals.

* **LOOSEN** ``required_trust`` for tool *T* by one step when at least
  three deny entries for *T* are labeled INCORRECT and the labeled
  INCORRECT denials outnumber labeled CORRECT denials.
* **TIGHTEN** ``required_trust`` for tool *T* by one step when at least
  three allow entries for *T* are labeled INCORRECT and the labeled
  INCORRECT allows outnumber labeled CORRECT allows.

A "step" walks the canonical TrustLevel ladder
``UNTRUSTED -> TOOL -> USER -> SYSTEM``. The analyzer never proposes
moves outside the ladder; if a proposal would land at the same level
as the current requirement, it is skipped.

Why labels matter so much
-------------------------
Without labels, "tool X is denied 50 times" is ambiguous: it could
mean the rule is correct (50 attacks blocked) or that the rule is
wrong (50 legitimate calls blocked). Labels resolve the ambiguity.
The proposal scorer then checks the proposal against the *full* labeled
history, so a fix-it-here change that breaks ten other cases gets
caught as a regression.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Callable

from tessera.audit_log import ReplayEnvelope
from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import (
    DecisionKind,
    Policy,
    ResourceType,
    ToolRequirement,
)
from tessera.replay import (
    Label,
    LabelStore,
    PolicyDecision,
    ReplayStats,
    iter_replay_cases,
    run_replay,
)


# ---------------------------------------------------------------------------
# Trust level ladder helpers
# ---------------------------------------------------------------------------


_LADDER: tuple[TrustLevel, ...] = (
    TrustLevel.UNTRUSTED,
    TrustLevel.TOOL,
    TrustLevel.USER,
    TrustLevel.SYSTEM,
)


def _step(level: TrustLevel, *, up: bool) -> TrustLevel | None:
    """Move one step up or down the trust ladder. None if at the boundary."""
    try:
        idx = _LADDER.index(level)
    except ValueError:
        return None
    new_idx = idx + (1 if up else -1)
    if 0 <= new_idx < len(_LADDER):
        return _LADDER[new_idx]
    return None


# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------


class ProposalKind(StrEnum):
    """What this proposal does to the current policy."""

    TIGHTEN_REQUIREMENT = "tighten_requirement"
    LOOSEN_REQUIREMENT = "loosen_requirement"


@dataclass(frozen=True)
class ProposalEvidence:
    """Per-tool counts that support a proposal.

    Attributes:
        tool_name: Tool the proposal targets.
        total_observations: Number of audit entries seen for this tool.
        denied: Of the observations, how many recorded a deny.
        allowed: Of the observations, how many recorded an allow.
        labeled_correct_denials: Denies marked CORRECT by a reviewer.
        labeled_incorrect_denials: Denies marked INCORRECT (false positives).
        labeled_correct_allows: Allows marked CORRECT.
        labeled_incorrect_allows: Allows marked INCORRECT (false negatives).
        decision_sources: Counter of decision_source values seen.
        decision_reasons: Counter of decision_reason values seen.
    """

    tool_name: str
    total_observations: int
    denied: int
    allowed: int
    labeled_correct_denials: int
    labeled_incorrect_denials: int
    labeled_correct_allows: int
    labeled_incorrect_allows: int
    decision_sources: dict[str, int] = field(default_factory=dict)
    decision_reasons: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Proposal:
    """A candidate edit to the current policy.

    Attributes:
        kind: The category of change.
        tool_name: Tool the change targets.
        current_required_trust: The level set before this proposal.
        proposed_required_trust: The level the proposal would move to.
        summary: One-line human-readable description.
        rationale: Multi-line explanation of why this proposal exists.
        evidence: The counts that drove the proposal.
        diff: Compact human-readable diff (e.g.
            ``"http.post: required_trust USER -> TOOL"``).
        new_policy_factory: Callable returning the candidate Policy.
            Pure, no side effects; safe to call repeatedly.
    """

    kind: ProposalKind
    tool_name: str
    current_required_trust: TrustLevel
    proposed_required_trust: TrustLevel
    summary: str
    rationale: str
    evidence: ProposalEvidence
    diff: str
    new_policy_factory: Callable[[], Policy]


@dataclass(frozen=True)
class ProposalImpact:
    """A proposal plus the replay stats from running it.

    The candidate is run against the full audit history (filtered by the
    same trajectory / time bounds the caller passes to
    :func:`score_proposal`). The leverage signal is:

    * ``stats.fixed`` - proposal flips a deny-or-allow that was labeled
      INCORRECT (good outcome).
    * ``stats.regressed`` - proposal flips a deny-or-allow that was
      labeled CORRECT (bad outcome).

    A net positive ``fixed - regressed`` means the change pays for itself
    on the labeled subset; the unlabeled cases are reported in
    ``stats.disagreed`` for reviewer follow-up.
    """

    proposal: Proposal
    stats: ReplayStats

    @property
    def net_fixes(self) -> int:
        """Convenience: positive numbers are wins, negative are regressions."""
        return self.stats.fixed - self.stats.regressed


# ---------------------------------------------------------------------------
# Counting + analysis
# ---------------------------------------------------------------------------


def _collect_evidence(
    audit_log_path: str | Path,
    *,
    labels: LabelStore | None,
) -> dict[str, ProposalEvidence]:
    """Aggregate per-tool counts from audit history."""
    counts: dict[str, dict] = defaultdict(lambda: {
        "total": 0,
        "denied": 0,
        "allowed": 0,
        "labeled_correct_denials": 0,
        "labeled_incorrect_denials": 0,
        "labeled_correct_allows": 0,
        "labeled_incorrect_allows": 0,
        "sources": Counter(),
        "reasons": Counter(),
    })
    for case in iter_replay_cases(audit_log_path):
        env = case.envelope
        c = counts[env.tool_name]
        c["total"] += 1
        if env.decision_allowed:
            c["allowed"] += 1
        else:
            c["denied"] += 1
        if env.decision_source:
            c["sources"][env.decision_source] += 1
        if env.decision_reason:
            c["reasons"][env.decision_reason] += 1

        if labels is not None:
            lbl = labels.get(case.seq, case.record_hash)
            if lbl == Label.CORRECT:
                if env.decision_allowed:
                    c["labeled_correct_allows"] += 1
                else:
                    c["labeled_correct_denials"] += 1
            elif lbl == Label.INCORRECT:
                if env.decision_allowed:
                    c["labeled_incorrect_allows"] += 1
                else:
                    c["labeled_incorrect_denials"] += 1

    return {
        tool: ProposalEvidence(
            tool_name=tool,
            total_observations=c["total"],
            denied=c["denied"],
            allowed=c["allowed"],
            labeled_correct_denials=c["labeled_correct_denials"],
            labeled_incorrect_denials=c["labeled_incorrect_denials"],
            labeled_correct_allows=c["labeled_correct_allows"],
            labeled_incorrect_allows=c["labeled_incorrect_allows"],
            decision_sources=dict(c["sources"]),
            decision_reasons=dict(c["reasons"]),
        )
        for tool, c in counts.items()
    }


def _current_requirement(policy: Policy, tool_name: str) -> ToolRequirement:
    """Return the requirement registered for ``tool_name`` or the default."""
    req = policy.requirements.get((tool_name, ResourceType.TOOL))
    if req is not None:
        return req
    return ToolRequirement(
        name=tool_name,
        resource_type=ResourceType.TOOL,
        required_trust=policy.default_required_trust,
        side_effects=True,
    )


def _clone_policy_with(
    base: Policy, tool_name: str, new_level: TrustLevel,
) -> Callable[[], Policy]:
    """Return a factory that builds a Policy with ``tool_name`` retuned.

    The factory snapshots the current requirements at call time, so a
    later mutation of ``base`` does not retroactively change a stored
    proposal. ``cel_engine``, ``backend``, and other fields are passed
    through untouched.
    """
    snapshot_reqs = dict(base.requirements)
    snapshot_request = dict(base.request_requirements)
    snapshot_base = dict(base.base_requirements) if base.base_requirements else None
    default = base.default_required_trust
    backend = base.backend
    fail_closed = base.fail_closed_backend_errors
    cel_engine = base.cel_engine
    scope = base.scope
    side_effects = _current_requirement(base, tool_name).side_effects

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
            required_trust=new_level,
            side_effects=side_effects,
        )
        return p

    return factory


def _make_loosen(
    ev: ProposalEvidence, current_policy: Policy,
) -> Proposal | None:
    cur = _current_requirement(current_policy, ev.tool_name)
    new_level = _step(cur.required_trust, up=False)
    if new_level is None or new_level == cur.required_trust:
        return None
    return Proposal(
        kind=ProposalKind.LOOSEN_REQUIREMENT,
        tool_name=ev.tool_name,
        current_required_trust=cur.required_trust,
        proposed_required_trust=new_level,
        summary=(
            f"Lower required_trust on {ev.tool_name} from "
            f"{cur.required_trust.name} to {new_level.name}"
        ),
        rationale=(
            f"{ev.labeled_incorrect_denials} of {ev.denied} recorded "
            f"denials for {ev.tool_name} are labeled INCORRECT, "
            f"vs {ev.labeled_correct_denials} labeled CORRECT. "
            f"Loosening the trust requirement would let the labeled-"
            f"incorrect denials through without changing tools whose "
            f"requirements are not registered against this entry."
        ),
        evidence=ev,
        diff=(
            f"{ev.tool_name}: required_trust "
            f"{cur.required_trust.name} -> {new_level.name}"
        ),
        new_policy_factory=_clone_policy_with(
            current_policy, ev.tool_name, new_level,
        ),
    )


def _make_tighten(
    ev: ProposalEvidence, current_policy: Policy,
) -> Proposal | None:
    cur = _current_requirement(current_policy, ev.tool_name)
    new_level = _step(cur.required_trust, up=True)
    if new_level is None or new_level == cur.required_trust:
        return None
    return Proposal(
        kind=ProposalKind.TIGHTEN_REQUIREMENT,
        tool_name=ev.tool_name,
        current_required_trust=cur.required_trust,
        proposed_required_trust=new_level,
        summary=(
            f"Raise required_trust on {ev.tool_name} from "
            f"{cur.required_trust.name} to {new_level.name}"
        ),
        rationale=(
            f"{ev.labeled_incorrect_allows} of {ev.allowed} recorded "
            f"allows for {ev.tool_name} are labeled INCORRECT, "
            f"vs {ev.labeled_correct_allows} labeled CORRECT. "
            f"Tightening the trust requirement would deny the labeled-"
            f"incorrect allows; a replay against the full history "
            f"will catch any regressions on labeled CORRECT allows."
        ),
        evidence=ev,
        diff=(
            f"{ev.tool_name}: required_trust "
            f"{cur.required_trust.name} -> {new_level.name}"
        ),
        new_policy_factory=_clone_policy_with(
            current_policy, ev.tool_name, new_level,
        ),
    )


def analyze(
    audit_log_path: str | Path,
    *,
    current_policy: Policy,
    labels: LabelStore | None = None,
    min_label_signal: int = 3,
) -> list[Proposal]:
    """Read audit history and emit ToolRequirement proposals.

    Args:
        audit_log_path: Path to the JSONL audit log.
        current_policy: The Policy in force right now. Proposals are
            built relative to its requirements.
        labels: Optional :class:`LabelStore` of ground-truth labels.
            Without labels the analyzer returns an empty list (the
            heuristics here all require label signal).
        min_label_signal: Minimum number of labeled INCORRECT entries
            of a single class (deny or allow) needed to emit a proposal
            for that tool. Default 3 keeps single-event noise out.

    Returns:
        A list of :class:`Proposal` objects, possibly empty. Pass each
        through :func:`score_proposal` to measure impact.
    """
    if labels is None:
        return []
    evidence_map = _collect_evidence(audit_log_path, labels=labels)
    proposals: list[Proposal] = []
    for tool_name, ev in evidence_map.items():
        # LOOSEN: many denials labeled incorrect, outweighing correct denials.
        if (
            ev.labeled_incorrect_denials >= min_label_signal
            and ev.labeled_incorrect_denials > ev.labeled_correct_denials
        ):
            p = _make_loosen(ev, current_policy)
            if p is not None:
                proposals.append(p)
        # TIGHTEN: many allows labeled incorrect, outweighing correct allows.
        if (
            ev.labeled_incorrect_allows >= min_label_signal
            and ev.labeled_incorrect_allows > ev.labeled_correct_allows
        ):
            p = _make_tighten(ev, current_policy)
            if p is not None:
                proposals.append(p)
    return proposals


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _candidate_for(policy: Policy, *, signing_key: bytes) -> Callable:
    """Wrap a Policy as a replay candidate callable.

    The signing key is used only to satisfy ``make_segment``; the policy
    engine ignores label signatures during evaluate(), so the placeholder
    key never affects the verdict.
    """
    def candidate(envelope: ReplayEnvelope) -> PolicyDecision:
        ctx = Context()
        for seg in envelope.segments:
            try:
                level = TrustLevel(int(seg.get("trust_level", 0)))
            except (ValueError, TypeError):
                level = TrustLevel.UNTRUSTED
            ctx.add(make_segment(
                str(seg.get("content_sha256", "")),
                Origin.WEB,
                "policy_builder",
                key=signing_key,
                trust_level=level,
            ))
        decision = policy.evaluate(
            context=ctx,
            tool_name=envelope.tool_name,
            args=envelope.args,
        )
        return PolicyDecision(
            allowed=decision.kind == DecisionKind.ALLOW,
            reason=decision.reason,
            source="tessera.policy_builder.candidate",
        )
    return candidate


def score_proposal(
    proposal: Proposal,
    audit_log_path: str | Path,
    *,
    labels: LabelStore | None = None,
    signing_key: bytes = b"\x00" * 32,
) -> ProposalImpact:
    """Replay the proposal against the audit log and return its impact.

    ``labels``, when provided, drives the ``fixed`` and ``regressed``
    counts on the returned :class:`ReplayStats`. Without labels, those
    counts are zero and only ``agreed`` / ``disagreed`` are populated.
    """
    candidate = _candidate_for(
        proposal.new_policy_factory(),
        signing_key=signing_key,
    )
    stats, _ = run_replay(audit_log_path, candidate, labels=labels)
    return ProposalImpact(proposal=proposal, stats=stats)


def analyze_and_score(
    audit_log_path: str | Path,
    *,
    current_policy: Policy,
    labels: LabelStore | None = None,
    min_label_signal: int = 3,
    signing_key: bytes = b"\x00" * 32,
) -> list[ProposalImpact]:
    """Convenience: analyze, score every proposal, return ranked by net fixes.

    Sorted descending by ``net_fixes``; ties broken by the proposal that
    flips fewer overall cases (smaller blast radius wins).
    """
    proposals = analyze(
        audit_log_path,
        current_policy=current_policy,
        labels=labels,
        min_label_signal=min_label_signal,
    )
    impacts = [
        score_proposal(
            p, audit_log_path,
            labels=labels, signing_key=signing_key,
        )
        for p in proposals
    ]
    impacts.sort(
        key=lambda i: (-i.net_fixes, i.stats.disagreed),
    )
    return impacts


__all__ = [
    "Proposal",
    "ProposalEvidence",
    "ProposalImpact",
    "ProposalKind",
    "analyze",
    "analyze_and_score",
    "score_proposal",
]
