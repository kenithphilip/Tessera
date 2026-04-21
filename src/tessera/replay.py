"""Replay historical decisions against a candidate policy.

Given a hash-chained audit log produced by :mod:`tessera.audit_log`,
reconstruct the inputs to each decision (from the ``replay`` envelope
embedded in ``SecurityEvent.detail``) and re-run them against a
candidate policy callable. Compare the candidate's decision to the
one that was recorded at the time, and score the result.

This is the shortest useful feedback loop for policy authoring: change
a rule, replay, see how many historical decisions flip. Ground-truth
labels (correct / incorrect / unreviewed) live as audit annotations in
a :class:`LabelStore`. Labels are keyed by ``(seq, record_hash)`` so
they stay attached to the same event across rewrites; re-running with
the same labels yields deterministic ``fixed`` / ``regressed`` counts.

Scope
-----
This module does NOT re-execute the tool. It does NOT call the LLM.
It only re-runs the policy callable against the recorded envelope.
The candidate may consult its own signers, CEL engine, or backends,
but it must be pure with respect to the envelope: side effects will
corrupt the replay run.

Only audit entries whose ``detail`` contains a ``replay`` key (i.e.
were produced via :func:`tessera.audit_log.make_replay_detail`) are
replayable. Other entries are skipped.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Protocol

from tessera.audit_log import ChainedRecord, ReplayEnvelope, iter_records


# ---------------------------------------------------------------------------
# Core shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplayCase:
    """One replayable audit entry.

    Attributes:
        seq: Sequence number from the audit log.
        record_hash: Hash of the audit record (stable key for labels).
        timestamp: Original decision timestamp.
        envelope: Reconstructed :class:`ReplayEnvelope` that drove the
            original decision.
    """

    seq: int
    record_hash: str
    timestamp: str
    envelope: ReplayEnvelope


@dataclass(frozen=True)
class PolicyDecision:
    """Decision returned by a candidate policy.

    Kept deliberately small: a bool and some human-readable text.
    Candidates that want to carry more detail can stuff it into
    ``metadata``; the scorer only reads ``allowed``.
    """

    allowed: bool
    reason: str = ""
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyFn(Protocol):
    """Callable signature for a candidate policy."""

    def __call__(self, envelope: ReplayEnvelope) -> PolicyDecision: ...


class Agreement(StrEnum):
    """Did the candidate match the recorded decision?"""

    AGREED = "agreed"
    DISAGREED = "disagreed"
    ERRORED = "errored"


@dataclass(frozen=True)
class ReplayResult:
    """One case plus the candidate's verdict.

    ``new_decision`` is None iff the candidate raised; ``error`` is
    populated in that case. Otherwise ``new_decision`` is always set.
    """

    case: ReplayCase
    agreement: Agreement
    new_decision: PolicyDecision | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Ground-truth labels
# ---------------------------------------------------------------------------


class Label(StrEnum):
    """Human judgment on whether the original decision was right.

    ``correct`` means the recorded decision was the right call.
    ``incorrect`` means it was wrong (allow that should have denied,
    or deny that should have allowed). ``unreviewed`` is the default
    until someone has looked.
    """

    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNREVIEWED = "unreviewed"


@dataclass
class LabelStore:
    """In-memory store of ground-truth labels keyed by ``(seq, hash)``.

    Keying on the record hash is belt-and-suspenders: sequence numbers
    are already unique within a chain, but the hash makes a label
    portable across a chain migration or an accidental rewrite of a
    prefix. A label whose stored hash no longer matches the current
    record hash is treated as stale (returns ``UNREVIEWED``).

    Persistence is a plain JSON file; no schema versioning, no lock.
    Multi-writer is not a goal; labels are an author-time workflow.
    """

    _labels: dict[int, tuple[str, Label]] = field(default_factory=dict)

    def set(self, seq: int, record_hash: str, label: Label) -> None:
        """Set the label for ``seq`` bound to ``record_hash``."""
        self._labels[int(seq)] = (str(record_hash), Label(label))

    def get(self, seq: int, record_hash: str | None = None) -> Label:
        """Return the label for ``seq`` or ``UNREVIEWED`` if unbound or stale.

        If ``record_hash`` is provided and does not match the stored
        hash, returns ``UNREVIEWED`` (the stored label is stale).
        """
        entry = self._labels.get(int(seq))
        if entry is None:
            return Label.UNREVIEWED
        stored_hash, label = entry
        if record_hash is not None and stored_hash != record_hash:
            return Label.UNREVIEWED
        return label

    def all(self) -> dict[int, tuple[str, Label]]:
        """Return a copy of the full label map."""
        return dict(self._labels)

    def dump(self, path: str | Path) -> None:
        """Write the store to ``path`` as JSON."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {
            str(seq): {"hash": h, "label": lbl.value}
            for seq, (h, lbl) in self._labels.items()
        }
        p.write_text(json.dumps(data, sort_keys=True, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "LabelStore":
        """Load a store from ``path``; returns an empty store if missing."""
        p = Path(path)
        store = cls()
        if not p.exists():
            return store
        raw = json.loads(p.read_text(encoding="utf-8"))
        for seq_str, entry in raw.items():
            store._labels[int(seq_str)] = (
                str(entry["hash"]),
                Label(entry["label"]),
            )
        return store


# ---------------------------------------------------------------------------
# Case construction and iteration
# ---------------------------------------------------------------------------


def _envelope_from_detail(detail: dict[str, Any]) -> ReplayEnvelope | None:
    """Reconstruct a :class:`ReplayEnvelope` from ``detail['replay']``.

    Returns None if the detail is missing the replay envelope or if
    required fields are absent. Callers should skip silently.
    """
    payload = detail.get("replay")
    if not isinstance(payload, dict):
        return None
    try:
        return ReplayEnvelope(
            trajectory_id=str(payload["trajectory_id"]),
            tool_name=str(payload["tool_name"]),
            args=dict(payload.get("args") or {}),
            user_prompt=str(payload.get("user_prompt", "")),
            segments=list(payload.get("segments") or []),
            sensitivity_hwm=str(payload.get("sensitivity_hwm", "PUBLIC")),
            decision_allowed=bool(payload.get("decision_allowed", True)),
            decision_source=str(payload.get("decision_source", "")),
            decision_reason=str(payload.get("decision_reason", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _in_time_range(
    timestamp: str,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    if since is None and until is None:
        return True
    try:
        ts = datetime.fromisoformat(timestamp)
    except ValueError:
        # Unparseable timestamps fall through the filter.
        return since is None and until is None
    if since is not None and ts < since:
        return False
    if until is not None and ts > until:
        return False
    return True


def iter_replay_cases(
    path: str | Path,
    *,
    kinds: Iterable[str] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    trajectory_id: str | None = None,
) -> Iterator[ReplayCase]:
    """Yield :class:`ReplayCase` for audit entries that carry a replay envelope.

    Filters:
        kinds: only yield records whose ``kind`` is in this set.
        since / until: inclusive timestamp bounds (ISO-8601).
        trajectory_id: only yield records whose envelope trajectory
            matches.

    Records without a replay envelope are silently skipped.
    """
    kind_set = {str(k) for k in kinds} if kinds is not None else None
    for record in iter_records(path):
        if kind_set is not None and record.kind not in kind_set:
            continue
        if not _in_time_range(record.timestamp, since, until):
            continue
        envelope = _envelope_from_detail(record.detail)
        if envelope is None:
            continue
        if trajectory_id is not None and envelope.trajectory_id != trajectory_id:
            continue
        yield ReplayCase(
            seq=record.seq,
            record_hash=record.hash,
            timestamp=record.timestamp,
            envelope=envelope,
        )


# ---------------------------------------------------------------------------
# Replay + scoring
# ---------------------------------------------------------------------------


def _decide_agreement(original: bool, candidate: PolicyDecision) -> Agreement:
    return Agreement.AGREED if candidate.allowed == original else Agreement.DISAGREED


def replay(
    cases: Iterable[ReplayCase],
    candidate: PolicyFn,
) -> Iterator[ReplayResult]:
    """Run ``candidate`` against each case, yielding a :class:`ReplayResult`.

    The candidate callable must not raise for a well-formed envelope.
    If it does, the result carries ``agreement=ERRORED`` and the
    exception message is captured in ``error``; replay continues.
    """
    for case in cases:
        try:
            new_decision = candidate(case.envelope)
        except Exception as e:  # noqa: BLE001 - we capture anything and continue
            yield ReplayResult(
                case=case,
                agreement=Agreement.ERRORED,
                new_decision=None,
                error=f"{type(e).__name__}: {e}",
            )
            continue
        agreement = _decide_agreement(case.envelope.decision_allowed, new_decision)
        yield ReplayResult(
            case=case,
            agreement=agreement,
            new_decision=new_decision,
            error=None,
        )


@dataclass(frozen=True)
class ReplayStats:
    """Summary of a replay run.

    Attributes:
        total: Number of cases replayed.
        agreed: Candidate matched the recorded decision.
        disagreed: Candidate flipped the recorded decision.
        errored: Candidate raised.
        flipped_allow_to_deny: Of the disagreements, how many were
            original-allow / candidate-deny (tightening).
        flipped_deny_to_allow: Of the disagreements, how many were
            original-deny / candidate-allow (loosening).
        labels: Count of each :class:`Label` across replayed cases.
        fixed: Cases labeled ``incorrect`` where the candidate flipped
            the decision (so the new policy corrects a known bad call).
        regressed: Cases labeled ``correct`` where the candidate flipped
            the decision (so the new policy breaks a known good call).
    """

    total: int
    agreed: int
    disagreed: int
    errored: int
    flipped_allow_to_deny: int
    flipped_deny_to_allow: int
    labels: dict[str, int]
    fixed: int
    regressed: int


def score(
    results: Iterable[ReplayResult],
    labels: LabelStore | None = None,
) -> ReplayStats:
    """Aggregate replay results into a :class:`ReplayStats`.

    When ``labels`` is provided, ``fixed`` / ``regressed`` are filled
    in from the label map. Without labels both are 0.
    """
    total = 0
    agreed = 0
    disagreed = 0
    errored = 0
    flipped_a2d = 0
    flipped_d2a = 0
    label_counter: Counter[str] = Counter()
    fixed = 0
    regressed = 0

    for result in results:
        total += 1
        if result.agreement == Agreement.AGREED:
            agreed += 1
        elif result.agreement == Agreement.DISAGREED:
            disagreed += 1
            if result.case.envelope.decision_allowed and result.new_decision is not None:
                if not result.new_decision.allowed:
                    flipped_a2d += 1
            elif (
                not result.case.envelope.decision_allowed
                and result.new_decision is not None
                and result.new_decision.allowed
            ):
                flipped_d2a += 1
        else:
            errored += 1

        if labels is not None:
            lbl = labels.get(result.case.seq, result.case.record_hash)
            label_counter[lbl.value] += 1
            if result.agreement == Agreement.DISAGREED:
                if lbl == Label.INCORRECT:
                    fixed += 1
                elif lbl == Label.CORRECT:
                    regressed += 1
        else:
            label_counter[Label.UNREVIEWED.value] += 1

    return ReplayStats(
        total=total,
        agreed=agreed,
        disagreed=disagreed,
        errored=errored,
        flipped_allow_to_deny=flipped_a2d,
        flipped_deny_to_allow=flipped_d2a,
        labels=dict(label_counter),
        fixed=fixed,
        regressed=regressed,
    )


def run_replay(
    audit_log_path: str | Path,
    candidate: PolicyFn,
    *,
    labels: LabelStore | None = None,
    kinds: Iterable[str] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    trajectory_id: str | None = None,
) -> tuple[ReplayStats, list[ReplayResult]]:
    """Convenience: iterate the audit log, replay, return stats and results.

    The returned list preserves replay order, so callers can render it
    directly in a UI or write it to a file.
    """
    cases = list(
        iter_replay_cases(
            audit_log_path,
            kinds=kinds,
            since=since,
            until=until,
            trajectory_id=trajectory_id,
        )
    )
    results = list(replay(cases, candidate))
    stats = score(results, labels=labels)
    return stats, results


__all__ = [
    "Agreement",
    "Label",
    "LabelStore",
    "PolicyDecision",
    "PolicyFn",
    "ReplayCase",
    "ReplayResult",
    "ReplayStats",
    "iter_replay_cases",
    "replay",
    "run_replay",
    "score",
]
