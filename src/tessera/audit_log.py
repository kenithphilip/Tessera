"""Append-only, hash-chained audit log.

Every record carries a ``prev_hash`` linking it to the predecessor.
Tamper targeted at any single event breaks the chain for every
subsequent event, so verification catches mid-sequence modifications
without access to the original signing key. Truncation is detected
by optional sealing (write the last known (seq, hash) pair to a
separate file signed with an HMAC key).

Why this exists
---------------
``tessera.evidence`` is a signed blob: one SHA-256 over a whole
bundle, then HMAC- or JWT-signed. That lets you ship a snapshot but
does NOT give per-event tamper evidence at rest. ``EvidenceBuffer``
is an in-memory ``deque(maxlen=...)`` that silently drops events.
Neither is a durable audit log.

This module adds one.

Design choices
--------------
- JSONL on disk. One event per line. Each line is the canonical form
  plus the computed hash. Human-readable, greppable, trivially
  streamable to SIEMs.
- ``prev_hash`` chain. First event hashes over a genesis value of 64
  zeros.
- Canonical hash payload excludes the ``hash`` field itself (obviously)
  and uses ``json.dumps(..., sort_keys=True, separators=(",", ":"))``
  so the bytes are deterministic across runs.
- Thread-safe: a ``threading.Lock`` guards the file append; ``O_APPEND``
  plus a ``fsync`` cadence gives durability within that lock.
- Recovery on open: if the file exists, read its tail to restore the
  last sequence number and hash. The sink resumes the chain cleanly.

Schema widening for replay
--------------------------
The eval/replay system needs the full envelope the evaluator saw at
decision time. This module does NOT force a schema on ``SecurityEvent.detail``,
but provides :class:`ReplayEnvelope` and :func:`make_replay_detail` so
callers that want replayability can populate their detail dict with
a consistent shape. Events emitted without the replay envelope are
still valid audit records; they just can't be replayed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from tessera.events import SecurityEvent

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Replay envelope (schema-widening helper)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplayEnvelope:
    """The information needed to re-evaluate a decision against a new policy.

    Embed in a ``SecurityEvent.detail`` under the ``replay`` key when
    the evaluator wants the decision to be replayable. The eval system
    reads this to reconstruct the evaluator inputs.

    Attributes:
        trajectory_id: Session / trajectory identifier.
        tool_name: Tool under evaluation.
        args: Tool call arguments as seen by the evaluator (already
            flattened if the evaluator flattened them).
        user_prompt: User's prompt at decision time (may be truncated).
        segments: Snapshot of context segments, each a dict with
            ``trust_level`` (int) and ``content_sha256`` (identifier
            only, not the plaintext). Keep this light: replay needs
            structure, not full content.
        sensitivity_hwm: Sensitivity label name at decision time.
        decision_allowed: The original decision, for agreed/disagreed
            scoring.
        decision_source: The component that produced the decision.
        decision_reason: Human-readable reason.
    """

    trajectory_id: str
    tool_name: str
    args: dict[str, Any]
    user_prompt: str = ""
    segments: list[dict[str, Any]] = field(default_factory=list)
    sensitivity_hwm: str = "PUBLIC"
    decision_allowed: bool = True
    decision_source: str = ""
    decision_reason: str = ""


def make_replay_detail(envelope: ReplayEnvelope, **extra: Any) -> dict[str, Any]:
    """Build a ``detail`` dict that embeds ``envelope`` under ``replay``.

    Args:
        envelope: Populated :class:`ReplayEnvelope`.
        **extra: Any additional fields to merge at the top level of
            ``detail`` (e.g. ``check="destructive_guard"``, ``rule_id=...``).

    Returns:
        Detail dict suitable for ``SecurityEvent.now(..., detail=...)``.
    """
    base: dict[str, Any] = dict(extra)
    base["replay"] = {
        "trajectory_id": envelope.trajectory_id,
        "tool_name": envelope.tool_name,
        "args": envelope.args,
        "user_prompt": envelope.user_prompt,
        "segments": envelope.segments,
        "sensitivity_hwm": envelope.sensitivity_hwm,
        "decision_allowed": envelope.decision_allowed,
        "decision_source": envelope.decision_source,
        "decision_reason": envelope.decision_reason,
    }
    return base


# ---------------------------------------------------------------------------
# Record + canonical hash
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainedRecord:
    """One entry in the audit log with its chain hash.

    The ``hash`` covers everything except itself.
    """

    seq: int
    timestamp: str
    kind: str
    principal: str
    detail: dict[str, Any]
    correlation_id: str | None
    trace_id: str | None
    prev_hash: str
    hash: str

    def to_line(self) -> str:
        """Serialize to a single JSONL line with a trailing newline."""
        return json.dumps(
            {
                "seq": self.seq,
                "timestamp": self.timestamp,
                "kind": self.kind,
                "principal": self.principal,
                "detail": self.detail,
                "correlation_id": self.correlation_id,
                "trace_id": self.trace_id,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def from_line(line: str) -> "ChainedRecord":
        data = json.loads(line)
        return ChainedRecord(
            seq=int(data["seq"]),
            timestamp=str(data["timestamp"]),
            kind=str(data["kind"]),
            principal=str(data["principal"]),
            detail=dict(data.get("detail") or {}),
            correlation_id=data.get("correlation_id"),
            trace_id=data.get("trace_id"),
            prev_hash=str(data["prev_hash"]),
            hash=str(data["hash"]),
        )


def _compute_hash(
    *,
    seq: int,
    timestamp: str,
    kind: str,
    principal: str,
    detail: dict[str, Any],
    correlation_id: str | None,
    trace_id: str | None,
    prev_hash: str,
) -> str:
    payload = {
        "seq": seq,
        "timestamp": timestamp,
        "kind": kind,
        "principal": principal,
        "detail": detail,
        "correlation_id": correlation_id,
        "trace_id": trace_id,
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------


class JSONLHashchainSink:
    """Event sink that appends each event to a JSONL file with a chain hash.

    Call as ``register_sink(JSONLHashchainSink("/var/log/tessera/audit.jsonl"))``.

    Args:
        path: Destination file. Parent directory is created if missing.
        fsync_every: How often to call ``fsync``. ``1`` (default) syncs
            after every write (durable but slower). Larger values batch
            for throughput at the cost of possibly losing the last few
            records on power loss.
        seal_key: Optional HMAC key. When provided, a companion file
            ``<path>.seal`` is written with ``{"seq","hash","tag"}``
            after each append. ``tag`` is ``HMAC-SHA256(seq|hash)`` so
            truncation of the main file is detected even if the chain
            inside the truncated file is still internally valid.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        fsync_every: int = 1,
        seal_key: bytes | None = None,
    ) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_seq = 0
        self._last_hash = GENESIS_HASH
        self._fsync_every = max(1, int(fsync_every))
        self._writes_since_fsync = 0
        self._seal_key = seal_key
        self._recover()

    def _recover(self) -> None:
        """Restore ``_last_seq`` and ``_last_hash`` from the file tail.

        Reads backwards in chunks to find the last newline. Small files
        are read directly. If the file is empty or missing, state stays
        at genesis.
        """
        if not self._path.exists() or self._path.stat().st_size == 0:
            return
        size = self._path.stat().st_size
        # For small files, read whole; for large, seek from end.
        chunk = 4096
        with open(self._path, "rb") as f:
            if size <= chunk:
                data = f.read()
            else:
                f.seek(max(0, size - chunk))
                data = f.read()
        # Find the last complete line.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return
        # Strip trailing whitespace, take the last non-empty line.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return
        try:
            record = ChainedRecord.from_line(lines[-1])
        except Exception:
            # Corrupt tail: leave state at genesis. First new write will
            # fail verification but the sink itself remains functional.
            return
        self._last_seq = record.seq
        self._last_hash = record.hash

    def __call__(self, event: SecurityEvent) -> None:
        with self._lock:
            seq = self._last_seq + 1
            prev_hash = self._last_hash
            kind_name = event.kind.value if hasattr(event.kind, "value") else str(event.kind)
            principal = event.principal or ""
            detail = event.detail or {}
            record_hash = _compute_hash(
                seq=seq,
                timestamp=event.timestamp,
                kind=kind_name,
                principal=principal,
                detail=detail,
                correlation_id=event.correlation_id,
                trace_id=event.trace_id,
                prev_hash=prev_hash,
            )
            record = ChainedRecord(
                seq=seq,
                timestamp=event.timestamp,
                kind=kind_name,
                principal=principal,
                detail=detail,
                correlation_id=event.correlation_id,
                trace_id=event.trace_id,
                prev_hash=prev_hash,
                hash=record_hash,
            )
            line = record.to_line()
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                self._writes_since_fsync += 1
                if self._writes_since_fsync >= self._fsync_every:
                    f.flush()
                    os.fsync(f.fileno())
                    self._writes_since_fsync = 0
            self._last_seq = seq
            self._last_hash = record_hash
            if self._seal_key is not None:
                self._write_seal(seq, record_hash)

    def _write_seal(self, seq: int, last_hash: str) -> None:
        """Write the seal file atomically with rename."""
        assert self._seal_key is not None
        tag = hmac.new(
            self._seal_key,
            f"{seq}|{last_hash}".encode(),
            hashlib.sha256,
        ).hexdigest()
        seal_path = self._path.with_suffix(self._path.suffix + ".seal")
        tmp = seal_path.with_suffix(seal_path.suffix + ".tmp")
        tmp.write_text(
            json.dumps({"seq": seq, "hash": last_hash, "tag": tag}),
            encoding="utf-8",
        )
        os.replace(tmp, seal_path)

    @property
    def last_seq(self) -> int:
        return self._last_seq

    @property
    def last_hash(self) -> str:
        return self._last_hash


# ---------------------------------------------------------------------------
# Verification + replay reader
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of walking the chain.

    Attributes:
        valid: True iff the chain is intact end-to-end.
        records_checked: Number of records successfully verified.
        first_bad_seq: Sequence number where verification failed, or None.
        reason: Human-readable explanation when ``valid`` is False.
        seal_valid: True if a seal file was present AND its
            ``(seq, hash, tag)`` matched the computed tail. False if
            the seal existed but did not match (e.g. truncation). None
            if no seal file was consulted.
    """

    valid: bool
    records_checked: int
    first_bad_seq: int | None = None
    reason: str = ""
    seal_valid: bool | None = None


def verify_chain(
    path: str | Path,
    *,
    seal_key: bytes | None = None,
) -> VerificationResult:
    """Walk the JSONL file and verify the chain.

    When ``seal_key`` is provided and a ``<path>.seal`` file exists, the
    function also verifies that the seal's tag is valid AND that its
    ``(seq, hash)`` matches the last record in the file. A truncated
    file with an intact internal chain is caught here.
    """
    p = Path(path)
    if not p.exists():
        return VerificationResult(
            valid=False, records_checked=0,
            first_bad_seq=None, reason=f"file not found: {p}",
        )

    expected_prev = GENESIS_HASH
    expected_seq = 1
    records_checked = 0
    last_hash = GENESIS_HASH

    with open(p, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = ChainedRecord.from_line(line)
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    first_bad_seq=expected_seq,
                    reason=f"unparseable record at expected seq {expected_seq}: {e}",
                )

            if record.seq != expected_seq:
                return VerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    first_bad_seq=record.seq,
                    reason=(
                        f"sequence gap: expected {expected_seq}, "
                        f"got {record.seq}"
                    ),
                )

            if record.prev_hash != expected_prev:
                return VerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    first_bad_seq=record.seq,
                    reason=(
                        f"prev_hash mismatch at seq {record.seq}: "
                        f"expected {expected_prev[:16]}..., "
                        f"got {record.prev_hash[:16]}..."
                    ),
                )

            computed = _compute_hash(
                seq=record.seq,
                timestamp=record.timestamp,
                kind=record.kind,
                principal=record.principal,
                detail=record.detail,
                correlation_id=record.correlation_id,
                trace_id=record.trace_id,
                prev_hash=record.prev_hash,
            )
            if computed != record.hash:
                return VerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    first_bad_seq=record.seq,
                    reason=(
                        f"hash mismatch at seq {record.seq}: "
                        f"record says {record.hash[:16]}..., "
                        f"computed {computed[:16]}..."
                    ),
                )

            records_checked += 1
            expected_prev = record.hash
            expected_seq = record.seq + 1
            last_hash = record.hash

    seal_valid: bool | None = None
    if seal_key is not None:
        seal_path = p.with_suffix(p.suffix + ".seal")
        if seal_path.exists():
            try:
                seal = json.loads(seal_path.read_text(encoding="utf-8"))
                expected_tag = hmac.new(
                    seal_key,
                    f"{seal['seq']}|{seal['hash']}".encode(),
                    hashlib.sha256,
                ).hexdigest()
                tag_ok = hmac.compare_digest(str(seal.get("tag", "")), expected_tag)
                matches_tail = (
                    int(seal["seq"]) == (expected_seq - 1)
                    and str(seal["hash"]) == last_hash
                )
                seal_valid = tag_ok and matches_tail
                if not seal_valid:
                    return VerificationResult(
                        valid=False,
                        records_checked=records_checked,
                        first_bad_seq=None,
                        reason=(
                            "seal does not match tail (truncation?) "
                            if tag_ok else "seal HMAC invalid"
                        ),
                        seal_valid=False,
                    )
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    records_checked=records_checked,
                    first_bad_seq=None,
                    reason=f"seal unreadable: {e}",
                    seal_valid=False,
                )

    return VerificationResult(
        valid=True,
        records_checked=records_checked,
        first_bad_seq=None,
        reason="ok",
        seal_valid=seal_valid,
    )


def iter_records(path: str | Path) -> Iterator[ChainedRecord]:
    """Iterate records in order. Does not verify the chain.

    Use :func:`verify_chain` before trusting records for audit
    purposes; use this for replay, metrics, or streaming to a SIEM.
    """
    p = Path(path)
    if not p.exists():
        return
    with open(p, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                yield ChainedRecord.from_line(line)
            except Exception:
                continue


__all__ = [
    "GENESIS_HASH",
    "ReplayEnvelope",
    "make_replay_detail",
    "ChainedRecord",
    "JSONLHashchainSink",
    "VerificationResult",
    "verify_chain",
    "iter_records",
]
