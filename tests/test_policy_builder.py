"""Tests for tessera.policy_builder: deterministic policy proposals from audit history."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tessera.audit_log import (
    JSONLHashchainSink,
    ReplayEnvelope,
    make_replay_detail,
)
from tessera.events import EventKind, SecurityEvent
from tessera.labels import TrustLevel
from tessera.policy import Policy, ResourceType, ToolRequirement
from tessera.policy_builder import (
    Proposal,
    ProposalImpact,
    ProposalKind,
    analyze,
    analyze_and_score,
    score_proposal,
)
from tessera.replay import Label, LabelStore, iter_replay_cases


def _envelope(
    *,
    tool_name: str = "http.post",
    trust_level: int = 0,
    decision_allowed: bool = False,
    decision_source: str = "tessera.policy",
    decision_reason: str = "min_trust(0) < required(100)",
    trajectory_id: str = "t1",
) -> ReplayEnvelope:
    return ReplayEnvelope(
        trajectory_id=trajectory_id,
        tool_name=tool_name,
        args={"url": "https://example.com"},
        segments=[{"trust_level": trust_level, "content_sha256": "abc"}],
        decision_allowed=decision_allowed,
        decision_source=decision_source,
        decision_reason=decision_reason,
    )


def _seed(sink: JSONLHashchainSink, env: ReplayEnvelope, *, kind=EventKind.POLICY_DENY) -> None:
    sink(SecurityEvent(
        kind=kind,
        principal="agent",
        detail=make_replay_detail(env),
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    ))


def _label_all(
    label_store: LabelStore, audit_path, label: Label,
    *, predicate=lambda case: True,
) -> None:
    for case in iter_replay_cases(audit_path):
        if predicate(case):
            label_store.set(case.seq, case.record_hash, label)


def _policy_with(tool: str, level: TrustLevel) -> Policy:
    p = Policy()
    p.requirements[(tool, ResourceType.TOOL)] = ToolRequirement(
        name=tool,
        resource_type=ResourceType.TOOL,
        required_trust=level,
        side_effects=True,
    )
    return p


class TestAnalyzeWithoutLabels:
    def test_returns_empty_when_no_labels(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(10):
            _seed(sink, _envelope(decision_allowed=False))
        proposals = analyze(audit, current_policy=Policy())
        assert proposals == []


class TestLoosenHeuristic:
    def test_loosens_when_denials_labeled_incorrect(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        # Five denies, all on http.post. The policy currently requires USER.
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="http.post",
                trust_level=0,
                decision_allowed=False,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)

        policy = _policy_with("http.post", TrustLevel.USER)
        proposals = analyze(audit, current_policy=policy, labels=labels)
        assert len(proposals) == 1
        p = proposals[0]
        assert p.kind == ProposalKind.LOOSEN_REQUIREMENT
        assert p.tool_name == "http.post"
        assert p.current_required_trust == TrustLevel.USER
        assert p.proposed_required_trust == TrustLevel.TOOL
        # Diff is human-readable and references the change.
        assert "USER" in p.diff and "TOOL" in p.diff

    def test_no_proposal_when_correct_outweigh_incorrect(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(8):
            _seed(sink, _envelope(decision_allowed=False))
        labels = LabelStore()
        # 3 INCORRECT, 5 CORRECT. Heuristic requires INCORRECT > CORRECT.
        cases = list(iter_replay_cases(audit))
        for c in cases[:3]:
            labels.set(c.seq, c.record_hash, Label.INCORRECT)
        for c in cases[3:]:
            labels.set(c.seq, c.record_hash, Label.CORRECT)

        proposals = analyze(
            audit,
            current_policy=_policy_with("http.post", TrustLevel.USER),
            labels=labels,
        )
        assert proposals == []

    def test_no_proposal_when_below_threshold(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(2):
            _seed(sink, _envelope(decision_allowed=False))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        proposals = analyze(
            audit,
            current_policy=_policy_with("http.post", TrustLevel.USER),
            labels=labels,
            min_label_signal=3,
        )
        assert proposals == []

    def test_no_proposal_at_lowest_level(self, tmp_path) -> None:
        # Already at UNTRUSTED; cannot loosen further.
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="echo",
                trust_level=0,
                decision_allowed=False,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        proposals = analyze(
            audit,
            current_policy=_policy_with("echo", TrustLevel.UNTRUSTED),
            labels=labels,
        )
        # No proposal: cannot step below UNTRUSTED.
        assert proposals == []


class TestTightenHeuristic:
    def test_tightens_when_allows_labeled_incorrect(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        # Five allows on db.write. Policy currently allows at TOOL.
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="db.write",
                trust_level=int(TrustLevel.USER),
                decision_allowed=True,
                decision_source="tessera.policy",
                decision_reason="min_trust(100) >= required(50)",
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        policy = _policy_with("db.write", TrustLevel.TOOL)
        proposals = analyze(audit, current_policy=policy, labels=labels)
        assert len(proposals) == 1
        p = proposals[0]
        assert p.kind == ProposalKind.TIGHTEN_REQUIREMENT
        assert p.proposed_required_trust == TrustLevel.USER

    def test_no_tighten_at_top_of_ladder(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="root",
                trust_level=int(TrustLevel.SYSTEM),
                decision_allowed=True,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        proposals = analyze(
            audit,
            current_policy=_policy_with("root", TrustLevel.SYSTEM),
            labels=labels,
        )
        # Already at SYSTEM, cannot tighten further.
        assert proposals == []


class TestScoreProposal:
    def test_loosen_proposal_fixes_incorrect_denials(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        # http.post denied at trust_level=TOOL (50). Policy currently
        # requires USER (100) so all five are denials. The proposal
        # loosens to TOOL (50), so all five flip to allow.
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="http.post",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)

        policy = _policy_with("http.post", TrustLevel.USER)
        proposals = analyze(audit, current_policy=policy, labels=labels)
        assert proposals
        impact = score_proposal(proposals[0], audit, labels=labels)
        assert isinstance(impact, ProposalImpact)
        # All five flips: deny -> allow on labeled-incorrect entries.
        assert impact.stats.disagreed == 5
        assert impact.stats.flipped_deny_to_allow == 5
        assert impact.stats.fixed == 5
        assert impact.stats.regressed == 0
        assert impact.net_fixes == 5

    def test_tighten_proposal_regresses_correct_allows(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        # All allows are labeled CORRECT. A tighten proposal would
        # regress every one; we synthesize the proposal manually and
        # confirm the scorer reports it as a regression.
        for _ in range(4):
            _seed(sink, _envelope(
                tool_name="db.read",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=True,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.CORRECT)

        policy = _policy_with("db.read", TrustLevel.TOOL)
        # Manually create the tighten proposal via the same path
        # the analyzer would use, even though the heuristic would
        # not fire here.
        from tessera.policy_builder import _make_tighten
        from tessera.policy_builder import _collect_evidence
        evidence = _collect_evidence(audit, labels=labels)["db.read"]
        proposal = _make_tighten(evidence, policy)
        assert proposal is not None

        impact = score_proposal(proposal, audit, labels=labels)
        assert impact.stats.flipped_allow_to_deny == 4
        assert impact.stats.regressed == 4
        assert impact.stats.fixed == 0
        assert impact.net_fixes == -4


class TestEndToEndRanking:
    def test_analyze_and_score_returns_sorted(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        # Two tools, both with deny patterns labeled INCORRECT.
        # Tool "small" gets 3 denies; tool "big" gets 7. Both should
        # produce LOOSEN proposals; "big" should rank first by net_fixes.
        for _ in range(3):
            _seed(sink, _envelope(
                tool_name="small",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        for _ in range(7):
            _seed(sink, _envelope(
                tool_name="big",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)

        policy = Policy()
        policy.requirements[("small", ResourceType.TOOL)] = ToolRequirement(
            name="small", resource_type=ResourceType.TOOL,
            required_trust=TrustLevel.USER, side_effects=True,
        )
        policy.requirements[("big", ResourceType.TOOL)] = ToolRequirement(
            name="big", resource_type=ResourceType.TOOL,
            required_trust=TrustLevel.USER, side_effects=True,
        )
        ranked = analyze_and_score(audit, current_policy=policy, labels=labels)
        assert len(ranked) == 2
        assert ranked[0].proposal.tool_name == "big"
        assert ranked[1].proposal.tool_name == "small"
        assert ranked[0].net_fixes == 7
        assert ranked[1].net_fixes == 3
