"""Tests for tessera.policy_builder_llm."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from tessera.audit_log import (
    JSONLHashchainSink,
    ReplayEnvelope,
    make_replay_detail,
)
from tessera.events import EventKind, SecurityEvent
from tessera.guardrail import BreakerConfig
from tessera.labels import TrustLevel
from tessera.policy import Policy, ResourceType, ToolRequirement
from tessera.policy_builder import ProposalKind
from tessera.policy_builder_llm import (
    LLMPolicyProposer,
    LLMProposal,
    LLMProposalBatch,
)
from tessera.replay import Label, LabelStore, iter_replay_cases


def _envelope(
    *,
    tool_name="http.post",
    trust_level=50,
    decision_allowed=False,
):
    return ReplayEnvelope(
        trajectory_id="t1",
        tool_name=tool_name,
        args={"url": "https://example.com"},
        segments=[{"trust_level": trust_level, "content_sha256": "abc"}],
        decision_allowed=decision_allowed,
        decision_source="tessera.policy",
        decision_reason="recorded",
    )


def _seed(sink, env, kind=EventKind.POLICY_DENY):
    sink(SecurityEvent(
        kind=kind,
        principal="agent",
        detail=make_replay_detail(env),
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    ))


def _label_all(label_store, audit_path, label):
    for case in iter_replay_cases(audit_path):
        label_store.set(case.seq, case.record_hash, label)


def _policy_with(tool, level):
    p = Policy()
    p.requirements[(tool, ResourceType.TOOL)] = ToolRequirement(
        name=tool, resource_type=ResourceType.TOOL,
        required_trust=level, side_effects=True,
    )
    return p


def _mock_client(response_text: str):
    client = MagicMock()
    block = MagicMock()
    block.text = response_text
    response = MagicMock()
    response.content = [block]
    client.messages.create.return_value = response
    return client


def _failing_client(exc=RuntimeError("provider down")):
    client = MagicMock()
    client.messages.create.side_effect = exc
    return client


def _llm_response(proposals: list[dict]) -> str:
    return json.dumps({"proposals": proposals})


class TestLLMSchema:
    def test_valid_proposal_parses(self) -> None:
        p = LLMProposal(
            kind="tighten",
            tool_name="db.write",
            target_trust="USER",
            rationale="four allows labeled incorrect",
            confidence=0.9,
        )
        assert p.kind == "tighten"

    def test_unknown_kind_rejected(self) -> None:
        with pytest.raises(Exception):
            LLMProposal(
                kind="delete_everything",  # not in Literal
                tool_name="x", confidence=1.0,
            )

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            LLMProposal(kind="tighten", tool_name="x", confidence=1.5)
        with pytest.raises(Exception):
            LLMProposal(kind="tighten", tool_name="x", confidence=-0.1)


class TestProposeBasic:
    def test_returns_proposals_for_known_tools(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(5):
            _seed(sink, _envelope(
                tool_name="http.post",
                trust_level=int(TrustLevel.TOOL),
                decision_allowed=False,
            ))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)

        client = _mock_client(_llm_response([
            {
                "kind": "loosen",
                "tool_name": "http.post",
                "target_trust": "TOOL",
                "rationale": "five labeled-incorrect denials",
                "confidence": 0.9,
            },
        ]))
        proposer = LLMPolicyProposer(client=client, model="test")
        policy = _policy_with("http.post", TrustLevel.USER)
        proposals = proposer.propose(audit, current_policy=policy, labels=labels)
        assert len(proposals) == 1
        assert proposals[0].tool_name == "http.post"
        assert proposals[0].kind == ProposalKind.LOOSEN_REQUIREMENT

    def test_drops_proposals_for_unknown_tools(self, tmp_path) -> None:
        # LLM hallucinates a tool name not present in audit -> drop.
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(3):
            _seed(sink, _envelope(tool_name="real_tool"))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)

        client = _mock_client(_llm_response([
            {
                "kind": "loosen",
                "tool_name": "imaginary_tool",
                "target_trust": "TOOL",
                "rationale": "hallucinated",
                "confidence": 0.5,
            },
            {
                "kind": "loosen",
                "tool_name": "real_tool",
                "target_trust": "TOOL",
                "rationale": "real evidence",
                "confidence": 0.9,
            },
        ]))
        proposer = LLMPolicyProposer(client=client, model="test")
        proposals = proposer.propose(
            audit,
            current_policy=_policy_with("real_tool", TrustLevel.USER),
            labels=labels,
        )
        # Hallucinated proposal dropped; real one kept.
        assert len(proposals) == 1
        assert proposals[0].tool_name == "real_tool"

    def test_register_tool_proposal(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(3):
            _seed(sink, _envelope(tool_name="unregistered.fn"))
        labels = LabelStore()
        _label_all(labels, audit, Label.CORRECT)
        client = _mock_client(_llm_response([
            {
                "kind": "register_tool",
                "tool_name": "unregistered.fn",
                "target_trust": "USER",
                "rationale": "tool appears in audit but unregistered",
                "confidence": 0.85,
            },
        ]))
        proposer = LLMPolicyProposer(client=client, model="test")
        # Empty Policy -> no requirement registered for unregistered.fn.
        proposals = proposer.propose(
            audit, current_policy=Policy(), labels=labels,
        )
        assert len(proposals) == 1
        p = proposals[0]
        assert p.kind == ProposalKind.TIGHTEN_REQUIREMENT
        assert p.tool_name == "unregistered.fn"
        assert p.proposed_required_trust == TrustLevel.USER

    def test_mark_read_only(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(3):
            _seed(sink, _envelope(tool_name="read_only_op"))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        client = _mock_client(_llm_response([
            {
                "kind": "mark_read_only",
                "tool_name": "read_only_op",
                "target_trust": None,
                "rationale": "fetch operation, no writes",
                "confidence": 0.8,
            },
        ]))
        proposer = LLMPolicyProposer(client=client, model="test")
        proposals = proposer.propose(
            audit,
            current_policy=_policy_with("read_only_op", TrustLevel.USER),
            labels=labels,
        )
        assert len(proposals) == 1
        assert "side_effects" in proposals[0].diff


class TestFailureModes:
    def test_empty_list_when_llm_raises(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        _seed(sink, _envelope())
        proposer = LLMPolicyProposer(client=_failing_client(), model="test")
        result = proposer.propose(
            audit,
            current_policy=Policy(),
            labels=LabelStore(),
        )
        assert result == []

    def test_breaker_opens_after_failures(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        _seed(sink, _envelope())
        labels = LabelStore()
        proposer = LLMPolicyProposer(
            client=_failing_client(),
            model="test",
            breaker=BreakerConfig(failure_threshold=2),
        )
        proposer.propose(audit, current_policy=Policy(), labels=labels)
        proposer.propose(audit, current_policy=Policy(), labels=labels)
        # Breaker should be open now.
        assert proposer.breaker_state.state == "open"
        # Subsequent calls do not invoke the LLM.
        proposer.propose(audit, current_policy=Policy(), labels=labels)
        assert proposer._client.messages.create.call_count == 2

    def test_unparseable_response_returns_empty(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        _seed(sink, _envelope())
        client = _mock_client("not json at all")
        proposer = LLMPolicyProposer(client=client, model="test")
        result = proposer.propose(
            audit,
            current_policy=Policy(),
            labels=LabelStore(),
        )
        assert result == []

    def test_no_audit_returns_empty(self, tmp_path) -> None:
        audit = tmp_path / "missing.jsonl"
        client = _mock_client(_llm_response([]))
        proposer = LLMPolicyProposer(client=client, model="test")
        result = proposer.propose(
            audit, current_policy=Policy(), labels=LabelStore(),
        )
        assert result == []
        # LLM should not have been invoked.
        assert client.messages.create.call_count == 0


class TestMarkdownStripping:
    def test_handles_code_fence_wrapped_response(self, tmp_path) -> None:
        audit = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(audit)
        for _ in range(3):
            _seed(sink, _envelope(tool_name="http.post"))
        labels = LabelStore()
        _label_all(labels, audit, Label.INCORRECT)
        wrapped = "```json\n" + _llm_response([
            {
                "kind": "loosen",
                "tool_name": "http.post",
                "target_trust": "TOOL",
                "rationale": "ok",
                "confidence": 0.8,
            },
        ]) + "\n```"
        client = _mock_client(wrapped)
        proposer = LLMPolicyProposer(client=client, model="test")
        proposals = proposer.propose(
            audit,
            current_policy=_policy_with("http.post", TrustLevel.USER),
            labels=labels,
        )
        assert len(proposals) == 1
