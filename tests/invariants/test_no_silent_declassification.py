"""No-silent-declassification invariants for worker.recovery.

The Phase 1B-iv label-recovery boundary is the ONLY place in
Tessera where labels can be reconstructed after passing through
a serialization boundary that strips them. The contract: every
recovered label is at least as restrictive as the join of
matched segments, and an unmatched field is over-tainted with
the union of all untrusted segment labels (NEVER with a more
permissive label than what the worker saw).

A regression here would let an attacker quietly bypass policy by
hiding a payload inside a field whose recovery missed all
matches, then having the recovery default to a trusted label.
The tests pin against that.

References
----------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.5
- ``docs/adr/0006-arg-level-provenance-primary.md``
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink
from tessera.labels import Origin, TrustLevel
from tessera.taint.label import IntegrityLevel, ProvenanceLabel
from tessera.worker.recovery import (
    FieldRecovery,
    RecoveryResult,
    field_provenance_recovery,
)

_KEY = b"k" * 32


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _capture_events() -> list[SecurityEvent]:
    """Capture security events from every test."""
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


def _untrusted_segment(content: str, segment_id: str = "seg-x") -> Any:
    """Build an untrusted context segment."""
    return make_segment(
        content=content,
        origin=Origin.WEB,
        principal="untrusted",
        key=_KEY,
        trust_level=TrustLevel.UNTRUSTED,
    )


def _trusted_segment(content: str, segment_id: str = "seg-u") -> Any:
    return make_segment(
        content=content,
        origin=Origin.USER,
        principal="alice",
        key=_KEY,
        trust_level=TrustLevel.USER,
    )


class _SimpleReport(BaseModel):
    """Minimal worker-style report for these tests."""

    have_enough_information: bool = True
    entities: list[str] = []
    notes: dict[str, str] = {}


# --- Recovery contract ------------------------------------------------------


def test_matched_field_inherits_segment_label() -> None:
    seg = _untrusted_segment("the wire transfer to IBAN GB12 ABCD 0000 11", "seg-1")
    ctx = Context()
    ctx.add(seg)
    report = _SimpleReport(entities=["IBAN GB12 ABCD 0000 11"])
    result = field_provenance_recovery(report, ctx)
    rec = result.by_path()["entities.0"]
    assert rec.match_count == 1
    assert rec.fallback_overtaint is False
    assert rec.label.integrity == IntegrityLevel.UNTRUSTED


def test_unmatched_field_falls_back_to_overtaint() -> None:
    seg = _untrusted_segment("the wire transfer to IBAN GB12", "seg-1")
    ctx = Context()
    ctx.add(seg)
    # Field value not present in any segment.
    report = _SimpleReport(entities=["FABRICATED PAYLOAD NOT IN ANY SEGMENT"])
    result = field_provenance_recovery(report, ctx)
    rec = result.by_path()["entities.0"]
    assert rec.match_count == 0
    assert rec.fallback_overtaint is True
    # Over-taint defaults to the join of all untrusted segments,
    # so the integrity must be UNTRUSTED.
    assert rec.label.integrity == IntegrityLevel.UNTRUSTED


def test_short_value_is_always_overtainted(_capture_events) -> None:
    """Short values match too many segments; force over-taint."""
    seg = _untrusted_segment("of the IBAN of the test", "seg-1")
    ctx = Context()
    ctx.add(seg)
    report = _SimpleReport(entities=["of"])
    result = field_provenance_recovery(report, ctx)
    rec = result.by_path()["entities.0"]
    assert rec.match_count == 0
    assert rec.fallback_overtaint is True
    fallback_events = [
        e for e in _capture_events
        if e.kind == EventKind.LABEL_RECOVERY_FALLBACK_OVERTAINT
    ]
    assert any(
        e.detail.get("reason") == "below_min_match_length"
        for e in fallback_events
    )


def test_match_event_emitted_for_each_matched_field(_capture_events) -> None:
    seg = _untrusted_segment("the IBAN GB12 ABCD 0000 11 is the recipient", "seg-1")
    ctx = Context()
    ctx.add(seg)
    report = _SimpleReport(entities=["IBAN GB12 ABCD 0000 11"])
    field_provenance_recovery(report, ctx)
    match_events = [
        e for e in _capture_events
        if e.kind == EventKind.LABEL_RECOVERY_MATCH
    ]
    assert len(match_events) == 1
    assert match_events[0].detail["field_path"] == "entities.0"
    assert match_events[0].detail["match_count"] == 1


def test_recursive_walk_into_dict(_capture_events) -> None:
    seg = _untrusted_segment("the recommendation is Riverside View Hotel", "seg-1")
    ctx = Context()
    ctx.add(seg)
    report = _SimpleReport(notes={"hotel": "Riverside View Hotel"})
    result = field_provenance_recovery(report, ctx)
    paths = {r.field_path for r in result.recoveries}
    assert "notes.hotel" in paths


def test_joined_label_aggregates_all_recoveries() -> None:
    seg_a = _untrusted_segment("alpha bravo charlie delta", "seg-1")
    seg_b = _untrusted_segment("echo foxtrot golf hotel", "seg-2")
    ctx = Context()
    ctx.add(seg_a)
    ctx.add(seg_b)
    report = _SimpleReport(
        entities=["alpha bravo charlie delta", "echo foxtrot golf hotel"]
    )
    result = field_provenance_recovery(report, ctx)
    # Both are UNTRUSTED; join must be UNTRUSTED, with sources from
    # both segments.
    assert result.joined_label.integrity == IntegrityLevel.UNTRUSTED
    assert len(result.joined_label.sources) >= 2


def test_recovery_does_not_lower_integrity_below_segments() -> None:
    """Property: recovery NEVER produces a label more trusted than
    the LEAST trusted untrusted segment that the worker actually saw.
    A regression here would be a silent declassification."""
    seg_untrusted = _untrusted_segment("payload from web evil example", "seg-untrusted")
    seg_endorsed = _untrusted_segment("legit endorsed tool output", "seg-endorsed")
    ctx = Context()
    ctx.add(seg_untrusted)
    ctx.add(seg_endorsed)
    # Field value matches NEITHER segment, so over-taint applies.
    report = _SimpleReport(entities=["totally fabricated content"])
    result = field_provenance_recovery(report, ctx)
    rec = result.by_path()["entities.0"]
    # IntegrityLevel: TRUSTED=0 < ENDORSED=1 < UNTRUSTED=2.
    # max() of two UNTRUSTED segments must remain UNTRUSTED.
    assert rec.label.integrity == IntegrityLevel.UNTRUSTED


def test_no_untrusted_segments_returns_trusted_default(_capture_events) -> None:
    """When the worker saw no untrusted segments, recovery cannot
    label anything as untrusted (nothing was untrusted)."""
    seg = _trusted_segment("alice typed this herself", "seg-user")
    ctx = Context()
    ctx.add(seg)
    report = _SimpleReport(entities=["alice typed this herself"])
    result = field_provenance_recovery(report, ctx, principal="alice")
    rec = result.by_path()["entities.0"]
    # Trusted user fallback applies.
    assert rec.label.integrity == IntegrityLevel.TRUSTED
