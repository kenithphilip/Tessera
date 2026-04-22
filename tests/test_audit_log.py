"""Tests for tessera.audit_log: hash-chained append-only audit sink."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

import pytest

from tessera.audit_log import (
    ChainedRecord,
    GENESIS_HASH,
    JSONLHashchainSink,
    ReplayEnvelope,
    VerificationResult,
    iter_records,
    make_replay_detail,
    verify_chain,
)
from tessera.events import EventKind, SecurityEvent


def _event(detail: dict | None = None, kind: EventKind = EventKind.POLICY_DENY) -> SecurityEvent:
    return SecurityEvent(
        kind=kind,
        principal="test",
        detail=detail or {"check": "unit-test"},
        timestamp=datetime.now(timezone.utc).isoformat(),
        correlation_id=None,
        trace_id=None,
    )


class TestAppend:
    def test_empty_file_starts_at_genesis(self, tmp_path) -> None:
        sink = JSONLHashchainSink(tmp_path / "audit.jsonl")
        assert sink.last_seq == 0
        assert sink.last_hash == GENESIS_HASH

    def test_first_event_uses_genesis_prev_hash(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        sink(_event())
        records = list(iter_records(path))
        assert len(records) == 1
        assert records[0].seq == 1
        assert records[0].prev_hash == GENESIS_HASH
        assert records[0].hash != GENESIS_HASH

    def test_chain_links_events(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        sink(_event({"n": 1}))
        sink(_event({"n": 2}))
        sink(_event({"n": 3}))
        records = list(iter_records(path))
        assert len(records) == 3
        assert records[0].prev_hash == GENESIS_HASH
        assert records[1].prev_hash == records[0].hash
        assert records[2].prev_hash == records[1].hash
        assert [r.seq for r in records] == [1, 2, 3]

    def test_file_is_jsonl(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(3):
            sink(_event({"n": i}))
        content = path.read_text()
        lines = [ln for ln in content.split("\n") if ln.strip()]
        assert len(lines) == 3
        # Each line must parse as JSON on its own.
        for ln in lines:
            json.loads(ln)


class TestRecovery:
    def test_recovers_tail_on_reopen(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        sink(_event({"n": 1}))
        sink(_event({"n": 2}))
        # Open a new sink on the same file.
        sink2 = JSONLHashchainSink(path)
        assert sink2.last_seq == 2
        sink2(_event({"n": 3}))
        records = list(iter_records(path))
        assert [r.seq for r in records] == [1, 2, 3]
        assert records[2].prev_hash == records[1].hash

    def test_recovery_handles_corrupt_tail(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text("this is not json\n")
        # Should not raise.
        sink = JSONLHashchainSink(path)
        # Stays at genesis so the next event starts a new chain
        # (verification will catch the resulting gap if anyone trusts
        # the whole file).
        assert sink.last_seq == 0


class TestVerification:
    def test_intact_chain_verifies(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(5):
            sink(_event({"n": i}))
        result = verify_chain(path)
        assert result.valid
        assert result.records_checked == 5
        assert result.first_bad_seq is None

    def test_missing_file_is_invalid(self, tmp_path) -> None:
        result = verify_chain(tmp_path / "does-not-exist.jsonl")
        assert not result.valid
        assert "not found" in result.reason

    def test_modified_detail_breaks_chain(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(3):
            sink(_event({"n": i}))
        # Tamper: modify the detail of record 2, leave the hash alone.
        lines = path.read_text().splitlines()
        data = json.loads(lines[1])
        data["detail"] = {"n": "TAMPERED"}
        lines[1] = json.dumps(data, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        result = verify_chain(path)
        assert not result.valid
        assert result.first_bad_seq == 2
        assert "hash mismatch" in result.reason

    def test_modified_hash_breaks_chain(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(3):
            sink(_event({"n": i}))
        lines = path.read_text().splitlines()
        data = json.loads(lines[1])
        # Also update the recorded hash to match the new detail -- but
        # this breaks the NEXT record's prev_hash check.
        data["detail"] = {"n": "TAMPERED"}
        fake_hash = "f" * 64
        data["hash"] = fake_hash
        lines[1] = json.dumps(data, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")

        result = verify_chain(path)
        assert not result.valid
        # Either hash check fails on record 2, or prev_hash check fails on 3.
        assert result.first_bad_seq in (2, 3)

    def test_sequence_gap_detected(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(3):
            sink(_event({"n": i}))
        # Delete the middle line entirely.
        lines = path.read_text().splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n")

        result = verify_chain(path)
        assert not result.valid
        assert "sequence gap" in result.reason


class TestSealedTruncation:
    """Truncation with a valid internal chain must still be caught."""

    def test_seal_catches_truncation(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        seal_key = b"k" * 32
        sink = JSONLHashchainSink(path, seal_key=seal_key)
        for i in range(5):
            sink(_event({"n": i}))
        # Truncate to 3 lines. The truncated file is internally valid
        # (first three records still link correctly), but the seal
        # still references seq 5.
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:3]) + "\n")

        result = verify_chain(path, seal_key=seal_key)
        assert not result.valid
        assert result.seal_valid is False

    def test_seal_valid_on_intact_file(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        seal_key = b"k" * 32
        sink = JSONLHashchainSink(path, seal_key=seal_key)
        for i in range(3):
            sink(_event({"n": i}))
        result = verify_chain(path, seal_key=seal_key)
        assert result.valid
        assert result.seal_valid is True

    def test_seal_tampered_detected(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        seal_key = b"k" * 32
        sink = JSONLHashchainSink(path, seal_key=seal_key)
        sink(_event({"n": 1}))
        # Tamper with the seal itself.
        seal_path = path.with_suffix(path.suffix + ".seal")
        seal = json.loads(seal_path.read_text())
        seal["tag"] = "0" * 64
        seal_path.write_text(json.dumps(seal))
        result = verify_chain(path, seal_key=seal_key)
        assert not result.valid
        assert result.seal_valid is False


class TestConcurrency:
    def test_concurrent_writers_keep_chain_intact(self, tmp_path) -> None:
        """Multiple threads calling the same sink must not corrupt the chain."""
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        writes_per_thread = 50
        threads: list[threading.Thread] = []

        def writer(thread_id: int) -> None:
            for i in range(writes_per_thread):
                sink(_event({"thread": thread_id, "i": i}))

        for tid in range(4):
            t = threading.Thread(target=writer, args=(tid,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        result = verify_chain(path)
        assert result.valid
        assert result.records_checked == writes_per_thread * 4
        # Sequence numbers must be contiguous and unique.
        records = list(iter_records(path))
        seqs = [r.seq for r in records]
        assert seqs == list(range(1, len(seqs) + 1))


class TestReplayEnvelope:
    def test_envelope_round_trip(self) -> None:
        env = ReplayEnvelope(
            trajectory_id="t1",
            tool_name="bash.run",
            args={"command": "ls"},
            user_prompt="list the dir",
            segments=[{"trust_level": 100, "content_sha256": "abc"}],
            sensitivity_hwm="CONFIDENTIAL",
            decision_allowed=False,
            decision_source="tessera.destructive_guard",
            decision_reason="fs.rm_rf_root",
        )
        detail = make_replay_detail(env, check="destructive_guard", rule_id="fs.rm_rf_root")
        assert detail["check"] == "destructive_guard"
        assert detail["replay"]["trajectory_id"] == "t1"
        assert detail["replay"]["decision_source"] == "tessera.destructive_guard"
        assert detail["replay"]["decision_allowed"] is False

    def test_envelope_survives_chained_record(self, tmp_path) -> None:
        """Round-trip the replay envelope through the sink."""
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        env = ReplayEnvelope(
            trajectory_id="t1",
            tool_name="http.post",
            args={"body": "secret"},
            decision_allowed=False,
            decision_source="tessera.sensitivity",
        )
        detail = make_replay_detail(env, check="ifc_outbound")
        event = SecurityEvent(
            kind=EventKind.POLICY_DENY,
            principal="agent",
            detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=None,
            trace_id=None,
        )
        sink(event)
        result = verify_chain(path)
        assert result.valid

        records = list(iter_records(path))
        assert records[0].detail["replay"]["tool_name"] == "http.post"
        assert records[0].detail["replay"]["decision_source"] == "tessera.sensitivity"


class TestIterRecords:
    def test_iter_records_yields_all(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = JSONLHashchainSink(path)
        for i in range(10):
            sink(_event({"n": i}))
        records = list(iter_records(path))
        assert len(records) == 10
        assert [r.detail["n"] for r in records] == list(range(10))

    def test_iter_records_skips_corrupt_lines(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text("not-json\n" + '{"seq":1,"timestamp":"x","kind":"policy_deny","principal":"","detail":{},"correlation_id":null,"trace_id":null,"prev_hash":"0","hash":"0"}\n')
        records = list(iter_records(path))
        # One valid record remains.
        assert len(records) == 1
