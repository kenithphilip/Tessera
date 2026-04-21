"""Tests for tessera.replay: re-running historical decisions against a candidate policy."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from tessera.audit_log import (
    JSONLHashchainSink,
    ReplayEnvelope,
    make_replay_detail,
)
from tessera.events import EventKind, SecurityEvent
from tessera.replay import (
    Agreement,
    Label,
    LabelStore,
    PolicyDecision,
    ReplayCase,
    ReplayResult,
    iter_replay_cases,
    replay,
    run_replay,
    score,
)


def _envelope(
    trajectory_id: str = "t1",
    tool_name: str = "http.post",
    decision_allowed: bool = False,
    **kwargs,
) -> ReplayEnvelope:
    return ReplayEnvelope(
        trajectory_id=trajectory_id,
        tool_name=tool_name,
        args=kwargs.get("args", {"body": "hello"}),
        user_prompt=kwargs.get("user_prompt", ""),
        segments=kwargs.get("segments", []),
        sensitivity_hwm=kwargs.get("sensitivity_hwm", "PUBLIC"),
        decision_allowed=decision_allowed,
        decision_source=kwargs.get("decision_source", "tessera.policy"),
        decision_reason=kwargs.get("decision_reason", ""),
    )


def _write_event(
    sink: JSONLHashchainSink,
    envelope: ReplayEnvelope,
    *,
    kind: EventKind = EventKind.POLICY_DENY,
    when: datetime | None = None,
    principal: str = "agent",
    **extra,
) -> None:
    detail = make_replay_detail(envelope, **extra)
    ts = (when or datetime.now(timezone.utc)).isoformat()
    sink(SecurityEvent(
        kind=kind,
        principal=principal,
        detail=detail,
        timestamp=ts,
        correlation_id=None,
        trace_id=None,
    ))


class TestIterReplayCases:
    def test_yields_envelopes_from_audit(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="a", decision_allowed=False))
        _write_event(sink, _envelope(trajectory_id="b", decision_allowed=True))

        cases = list(iter_replay_cases(path))
        assert len(cases) == 2
        assert [c.envelope.trajectory_id for c in cases] == ["a", "b"]
        assert cases[0].seq == 1
        assert cases[0].record_hash  # non-empty

    def test_skips_entries_without_replay_envelope(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        # No replay envelope in detail.
        sink(SecurityEvent(
            kind=EventKind.POLICY_DENY,
            principal="agent",
            detail={"check": "some_guard"},
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=None,
            trace_id=None,
        ))
        _write_event(sink, _envelope(trajectory_id="b"))

        cases = list(iter_replay_cases(path))
        assert len(cases) == 1
        assert cases[0].envelope.trajectory_id == "b"

    def test_filters_by_kind(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="deny"), kind=EventKind.POLICY_DENY)
        _write_event(
            sink,
            _envelope(trajectory_id="gr"),
            kind=EventKind.GUARDRAIL_DECISION,
        )

        cases = list(iter_replay_cases(path, kinds=["policy_deny"]))
        assert [c.envelope.trajectory_id for c in cases] == ["deny"]

    def test_filters_by_trajectory(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="keep"))
        _write_event(sink, _envelope(trajectory_id="drop"))

        cases = list(iter_replay_cases(path, trajectory_id="keep"))
        assert [c.envelope.trajectory_id for c in cases] == ["keep"]

    def test_filters_by_time_range(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        early = datetime(2026, 1, 1, tzinfo=timezone.utc)
        mid = datetime(2026, 6, 1, tzinfo=timezone.utc)
        late = datetime(2026, 12, 1, tzinfo=timezone.utc)
        _write_event(sink, _envelope(trajectory_id="e"), when=early)
        _write_event(sink, _envelope(trajectory_id="m"), when=mid)
        _write_event(sink, _envelope(trajectory_id="l"), when=late)

        cases = list(iter_replay_cases(
            path,
            since=mid,
            until=late - timedelta(days=1),
        ))
        assert [c.envelope.trajectory_id for c in cases] == ["m"]


class TestReplay:
    def test_agreement_when_candidate_matches(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(decision_allowed=False))

        cases = list(iter_replay_cases(path))
        results = list(replay(cases, lambda env: PolicyDecision(allowed=False)))
        assert len(results) == 1
        assert results[0].agreement == Agreement.AGREED

    def test_disagreement_when_candidate_flips(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(decision_allowed=False))

        cases = list(iter_replay_cases(path))
        results = list(replay(
            cases,
            lambda env: PolicyDecision(allowed=True, reason="loosened"),
        ))
        assert results[0].agreement == Agreement.DISAGREED
        assert results[0].new_decision.allowed is True

    def test_error_is_captured_and_iteration_continues(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="bad", decision_allowed=False))
        _write_event(sink, _envelope(trajectory_id="good", decision_allowed=False))

        def flaky(env: ReplayEnvelope) -> PolicyDecision:
            if env.trajectory_id == "bad":
                raise RuntimeError("boom")
            return PolicyDecision(allowed=False)

        cases = list(iter_replay_cases(path))
        results = list(replay(cases, flaky))
        assert [r.agreement for r in results] == [
            Agreement.ERRORED,
            Agreement.AGREED,
        ]
        assert results[0].error is not None
        assert "boom" in results[0].error
        assert results[0].new_decision is None


class TestScore:
    def _case(self, seq: int, decision_allowed: bool) -> ReplayCase:
        return ReplayCase(
            seq=seq,
            record_hash=f"h{seq}",
            timestamp="2026-01-01T00:00:00+00:00",
            envelope=_envelope(decision_allowed=decision_allowed),
        )

    def test_counts_agreement_buckets(self) -> None:
        results = [
            ReplayResult(
                case=self._case(1, False),
                agreement=Agreement.AGREED,
                new_decision=PolicyDecision(allowed=False),
            ),
            ReplayResult(
                case=self._case(2, True),
                agreement=Agreement.DISAGREED,
                new_decision=PolicyDecision(allowed=False),
            ),
            ReplayResult(
                case=self._case(3, False),
                agreement=Agreement.DISAGREED,
                new_decision=PolicyDecision(allowed=True),
            ),
            ReplayResult(
                case=self._case(4, True),
                agreement=Agreement.ERRORED,
                new_decision=None,
                error="oops",
            ),
        ]
        stats = score(results)
        assert stats.total == 4
        assert stats.agreed == 1
        assert stats.disagreed == 2
        assert stats.errored == 1
        assert stats.flipped_allow_to_deny == 1
        assert stats.flipped_deny_to_allow == 1

    def test_labels_drive_fixed_and_regressed(self) -> None:
        results = [
            # Original said deny, candidate says allow. Labeled incorrect =
            # fix (the new policy agrees with the human judgment).
            ReplayResult(
                case=self._case(1, False),
                agreement=Agreement.DISAGREED,
                new_decision=PolicyDecision(allowed=True),
            ),
            # Original said allow, candidate says deny. Labeled correct =
            # regression (new policy breaks a call the human approved).
            ReplayResult(
                case=self._case(2, True),
                agreement=Agreement.DISAGREED,
                new_decision=PolicyDecision(allowed=False),
            ),
        ]
        labels = LabelStore()
        labels.set(1, "h1", Label.INCORRECT)
        labels.set(2, "h2", Label.CORRECT)

        stats = score(results, labels=labels)
        assert stats.fixed == 1
        assert stats.regressed == 1
        assert stats.labels["incorrect"] == 1
        assert stats.labels["correct"] == 1

    def test_stale_label_hash_is_treated_as_unreviewed(self) -> None:
        results = [
            ReplayResult(
                case=self._case(1, True),
                agreement=Agreement.DISAGREED,
                new_decision=PolicyDecision(allowed=False),
            ),
        ]
        labels = LabelStore()
        labels.set(1, "different-hash", Label.CORRECT)
        stats = score(results, labels=labels)
        # Stored hash does not match the case's hash, so the label is stale.
        assert stats.regressed == 0
        assert stats.labels["unreviewed"] == 1


class TestLabelStore:
    def test_defaults_to_unreviewed(self) -> None:
        store = LabelStore()
        assert store.get(1) == Label.UNREVIEWED

    def test_set_and_get(self) -> None:
        store = LabelStore()
        store.set(1, "h1", Label.CORRECT)
        assert store.get(1, "h1") == Label.CORRECT

    def test_hash_mismatch_returns_unreviewed(self) -> None:
        store = LabelStore()
        store.set(1, "h1", Label.INCORRECT)
        assert store.get(1, "other") == Label.UNREVIEWED

    def test_round_trip_via_disk(self, tmp_path) -> None:
        store = LabelStore()
        store.set(1, "h1", Label.CORRECT)
        store.set(5, "h5", Label.INCORRECT)
        path = tmp_path / "labels.json"
        store.dump(path)
        # File is human-readable JSON.
        raw = json.loads(path.read_text())
        assert raw["1"] == {"hash": "h1", "label": "correct"}
        # Reload.
        loaded = LabelStore.load(path)
        assert loaded.get(1, "h1") == Label.CORRECT
        assert loaded.get(5, "h5") == Label.INCORRECT

    def test_load_missing_file_yields_empty_store(self, tmp_path) -> None:
        store = LabelStore.load(tmp_path / "never-written.json")
        assert store.all() == {}


class TestRunReplay:
    def test_end_to_end(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="a", decision_allowed=False))
        _write_event(sink, _envelope(trajectory_id="b", decision_allowed=True))
        _write_event(sink, _envelope(trajectory_id="c", decision_allowed=False))

        # Candidate: allow everything.
        stats, results = run_replay(path, lambda env: PolicyDecision(allowed=True))
        assert stats.total == 3
        assert stats.agreed == 1      # only trajectory b
        assert stats.disagreed == 2   # a and c flipped deny -> allow
        assert stats.flipped_deny_to_allow == 2
        assert len(results) == 3

    def test_labels_reused_across_runs(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        _write_event(sink, _envelope(trajectory_id="only", decision_allowed=False))

        # Capture the record hash for labeling.
        cases = list(iter_replay_cases(path))
        labels = LabelStore()
        labels.set(cases[0].seq, cases[0].record_hash, Label.INCORRECT)

        # Candidate flips. Labeled incorrect -> fix.
        stats, _ = run_replay(
            path,
            lambda env: PolicyDecision(allowed=True),
            labels=labels,
        )
        assert stats.fixed == 1
        assert stats.regressed == 0
