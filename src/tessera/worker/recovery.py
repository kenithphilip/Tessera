"""Field-level provenance recovery for Worker reports.

The Worker model returns a Pydantic report whose string fields lost
their :class:`~tessera.taint.tstr.TaintedStr` labels at the JSON
serialization boundary (Pydantic's ``model_dump_json`` reduces every
:class:`str` subclass to a bare ``str``). This module re-attaches a
provenance label to each field by comparing the field value to the
text of the untrusted segments the worker actually saw.

Recovery rules
--------------

For each string field (or list / dict of strings) in the report:

1. Pre-tokenize every untrusted context segment.
2. Compute the literal-substring match between the field value and
   each segment text. A field is *grounded in* a segment when the
   field's text appears as a contiguous substring of the segment's
   text. (Substring rather than token overlap: the worker quoted the
   segment, so an exact match is the strong signal.)
3. If exactly one segment matches, the field's label is that
   segment's :class:`~tessera.taint.label.ProvenanceLabel`. Emit
   :attr:`~tessera.events.EventKind.LABEL_RECOVERY_MATCH`.
4. If multiple segments match, the field's label is the join of the
   matching segments' labels. Emit
   :attr:`~tessera.events.EventKind.LABEL_RECOVERY_MATCH` with
   ``match_count > 1``.
5. If no segment matches, fall back to *over-tainting*: the field is
   labeled with the join of *every* untrusted segment's label, the
   safest choice. Emit
   :attr:`~tessera.events.EventKind.LABEL_RECOVERY_FALLBACK_OVERTAINT`
   so SOC teams can pivot on every miss (worker fabrication or model
   hallucination is the most common cause of an unmatched field).

The recovery is deterministic: same report + same context produces
the same labels. No LLM call is involved. The labels carried back are
the legitimate, in-flight :class:`ProvenanceLabel` instances on the
context segments, not freshly minted ones.

References
----------

- CaMeL: ``Defeating Prompt Injections by Design`` Section 4.2
  (label recovery boundaries).
- FIDES: ``Practical and Provable Security against Prompt
  Injection Attacks`` Section 5.1 (substring grounding heuristic).
- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from pydantic import BaseModel

from tessera.context import Context
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.taint.label import (
    ProvenanceLabel,
    SegmentRef,
    join_labels,
)


@dataclass(frozen=True, slots=True)
class FieldRecovery:
    """Recovery outcome for one field in a Worker report.

    Attributes:
        field_path: Dotted path to the field, e.g. ``"entities.0"``
            or ``"numbers.amount"``. Lists use indices, dicts use
            keys.
        value: The field value as it appeared in the report.
        label: The recovered :class:`ProvenanceLabel`. May be the
            join of multiple segments' labels.
        match_count: Number of context segments whose text contained
            the field as a literal substring. Zero means the
            over-taint fallback fired.
        fallback_overtaint: True when no segment matched and the
            label is the union of all untrusted segments' labels.
    """

    field_path: str
    value: str
    label: ProvenanceLabel
    match_count: int
    fallback_overtaint: bool


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Aggregate outcome of recovering provenance for a Worker report.

    Attributes:
        recoveries: One :class:`FieldRecovery` per scalar string
            visited in the report.
        joined_label: The join of every recovered label. Useful as a
            single label for the entire report when the downstream
            consumer treats the report opaquely.
        any_overtaint: True when at least one field fell back to the
            over-taint label.
    """

    recoveries: tuple[FieldRecovery, ...]
    joined_label: ProvenanceLabel
    any_overtaint: bool

    def by_path(self) -> dict[str, FieldRecovery]:
        """Return a dict keyed by field_path for easy lookup."""
        return {r.field_path: r for r in self.recoveries}


def _walk_strings(value: Any, prefix: str) -> Iterable[tuple[str, str]]:
    """Yield ``(field_path, string_value)`` for every str leaf in
    ``value``. Recurses into Pydantic models, dicts, lists, and
    tuples. Bool / int / float / None are skipped (they carry no
    free text the worker could have copied from a segment)."""
    if isinstance(value, str):
        yield prefix, value
        return
    if isinstance(value, BaseModel):
        for name, sub in value.model_dump().items():
            child = f"{prefix}.{name}" if prefix else name
            yield from _walk_strings(sub, child)
        return
    if isinstance(value, dict):
        for key, sub in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_strings(sub, child)
        return
    if isinstance(value, (list, tuple)):
        for idx, sub in enumerate(value):
            child = f"{prefix}.{idx}" if prefix else str(idx)
            yield from _walk_strings(sub, child)
        return
    # Skip other primitives.


def _segment_label(segment: Any) -> ProvenanceLabel:
    """Return the :class:`ProvenanceLabel` for a context segment.

    v0.12 Tessera segments still carry the legacy
    :class:`tessera.labels.TrustLabel`; we synthesize a
    :class:`ProvenanceLabel` from the segment's index + trust level
    until Phase 4 wave 4B moves the canonical representation to the
    new label. The synthesized label uses the segment's index as the
    :class:`SegmentRef` source identifier so deduplication still
    works inside :func:`join_labels`.
    """
    # If segment already carries a ProvenanceLabel (post-Phase 4),
    # use it directly.
    plabel = getattr(segment, "provenance_label", None)
    if isinstance(plabel, ProvenanceLabel):
        return plabel
    # Build from legacy fields.
    legacy = getattr(segment, "label", None)
    seg_id = (
        getattr(legacy, "id", None)
        or getattr(segment, "segment_id", None)
        or getattr(legacy, "nonce", None)
        or "unknown"
    )
    origin = getattr(legacy, "origin", None)
    # ``Origin`` is an enum on legacy labels; ``ProvenanceLabel`` only
    # needs a stable URI string for telemetry.
    origin_uri = (
        f"legacy://{origin.value}" if hasattr(origin, "value") else str(origin or "")
    )
    # Heuristic: USER and SYSTEM segments are trusted; TOOL is
    # endorsed (vetted by an authenticated tool); UNTRUSTED is
    # untrusted.
    from tessera.labels import TrustLevel  # local import to avoid cycle

    trust = getattr(legacy, "trust_level", None)
    if trust is None:
        return ProvenanceLabel.untrusted_tool_output(
            segment_id=str(seg_id), origin_uri=origin_uri
        )
    if trust >= TrustLevel.USER:
        principal = getattr(legacy, "principal", None) or "unknown"
        return ProvenanceLabel.trusted_user(principal)
    if trust >= TrustLevel.TOOL:
        return ProvenanceLabel.endorsed_tool(
            segment_id=str(seg_id), origin_uri=origin_uri
        )
    return ProvenanceLabel.untrusted_tool_output(
        segment_id=str(seg_id), origin_uri=origin_uri
    )


def field_provenance_recovery(
    report: BaseModel | dict[str, Any],
    untrusted_context: Context,
    *,
    overtaint_label: ProvenanceLabel | None = None,
    principal: str | None = None,
    correlation_id: str | None = None,
    min_match_length: int = 4,
) -> RecoveryResult:
    """Re-attach provenance labels to fields of a Worker report.

    Walks every string-valued field of ``report`` (recursively into
    nested models, dicts, lists). For each, looks up the segment in
    ``untrusted_context`` whose text contains the field value as a
    contiguous substring. The field's label is the join of all
    matching segments' labels; if no match is found, the label is the
    join of *every* untrusted segment's label (over-taint fallback).

    Args:
        report: The validated Worker report (either a Pydantic model
            instance or a plain dict from ``model_dump()``).
        untrusted_context: The context the worker actually saw. Only
            untrusted segments contribute labels; trusted segments
            (USER / SYSTEM) are skipped because they cannot have
            been the source of an unbounded leak.
        overtaint_label: The label to use when no segment matches a
            field. Defaults to the join of every untrusted segment's
            label, which is the safest choice (the worker may have
            fabricated the field). Pass an explicit label to override
            for tests or custom domains.
        principal: Subject of the recovery events; defaults to the
            context's principal.
        correlation_id: Forwarded into emitted security events for
            cross-component tracing.
        min_match_length: Field values shorter than this are
            *always* over-tainted. Short values trivially appear in
            many segments and would taint everything, defeating the
            purpose. Default 4 covers entity names like ``IBAN``
            without flooding from ``a`` / ``of`` / ``the``.

    Returns:
        A :class:`RecoveryResult` with one :class:`FieldRecovery`
        per scalar string in the report and a joined label suitable
        for downstream policy evaluation.
    """
    untrusted_segments = list(getattr(untrusted_context, "segments", ()))
    untrusted_only = [
        seg
        for seg in untrusted_segments
        if _segment_label(seg).integrity.value > 0
    ]

    # Pre-extract (segment, text, label) tuples once.
    seg_texts: list[tuple[Any, str, ProvenanceLabel]] = []
    for seg in untrusted_only:
        text = getattr(seg, "content", None)
        if not isinstance(text, str):
            continue
        seg_texts.append((seg, text, _segment_label(seg)))

    # Build the over-taint fallback once.
    if overtaint_label is None and seg_texts:
        overtaint_label = join_labels(*[lbl for _, _, lbl in seg_texts])
    elif overtaint_label is None:
        # No untrusted segments at all: nothing to recover from.
        # Use the trusted-user identity so callers do not blow up;
        # the report is implicitly trusted because the worker had
        # no untrusted input.
        overtaint_label = ProvenanceLabel.trusted_user(principal or "unknown")

    recoveries: list[FieldRecovery] = []
    principal_resolved = principal or getattr(untrusted_context, "principal", None)
    overtaint_seen = False

    for path, value in _walk_strings(report, prefix=""):
        if len(value) < min_match_length:
            recoveries.append(
                FieldRecovery(
                    field_path=path,
                    value=value,
                    label=overtaint_label,
                    match_count=0,
                    fallback_overtaint=True,
                )
            )
            overtaint_seen = True
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.LABEL_RECOVERY_FALLBACK_OVERTAINT,
                    principal=principal_resolved,
                    detail={
                        "field_path": path,
                        "reason": "below_min_match_length",
                        "value_length": len(value),
                        "min_match_length": min_match_length,
                    },
                    correlation_id=correlation_id,
                )
            )
            continue

        matches: list[ProvenanceLabel] = []
        match_seg_ids: list[str] = []
        for seg, text, lbl in seg_texts:
            if value in text:
                matches.append(lbl)
                seg_id = getattr(seg, "segment_id", None) or getattr(
                    getattr(seg, "label", None), "id", None
                )
                match_seg_ids.append(str(seg_id) if seg_id is not None else "")

        if matches:
            recovered = join_labels(*matches)
            recoveries.append(
                FieldRecovery(
                    field_path=path,
                    value=value,
                    label=recovered,
                    match_count=len(matches),
                    fallback_overtaint=False,
                )
            )
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.LABEL_RECOVERY_MATCH,
                    principal=principal_resolved,
                    detail={
                        "field_path": path,
                        "match_count": len(matches),
                        "segment_ids": match_seg_ids,
                    },
                    correlation_id=correlation_id,
                )
            )
        else:
            recoveries.append(
                FieldRecovery(
                    field_path=path,
                    value=value,
                    label=overtaint_label,
                    match_count=0,
                    fallback_overtaint=True,
                )
            )
            overtaint_seen = True
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.LABEL_RECOVERY_FALLBACK_OVERTAINT,
                    principal=principal_resolved,
                    detail={
                        "field_path": path,
                        "reason": "no_segment_match",
                        "value_length": len(value),
                    },
                    correlation_id=correlation_id,
                )
            )

    if recoveries:
        joined = join_labels(*[r.label for r in recoveries])
    else:
        joined = overtaint_label

    return RecoveryResult(
        recoveries=tuple(recoveries),
        joined_label=joined,
        any_overtaint=overtaint_seen,
    )


# ---------------------------------------------------------------------------
# Response-grounding (formerly tessera.claim_provenance, absorbed in 2L)
# ---------------------------------------------------------------------------
#
# The legacy tessera.claim_provenance.verify_response_provenance grounded
# model-response sentences in context segments by token overlap. The
# implementation moved here as part of Wave 2L; the legacy module is
# deleted.

import re
from dataclasses import dataclass

from tessera.labels import TrustLevel


@dataclass(frozen=True)
class ClaimGrounding:
    """Provenance of one claim in the model response."""

    claim: str
    segment_indices: tuple[int, ...]
    min_trust: TrustLevel
    overlap_score: float
    from_directive_segment: bool


@dataclass(frozen=True)
class ProvenanceVerificationResult:
    """Result of verifying provenance of all claims in a model response."""

    tainted_claims: tuple[ClaimGrounding, ...]
    clean_claims: tuple[ClaimGrounding, ...]
    tainted: bool
    score: float


_STOP_WORDS = frozenset(
    {
        "a", "an", "the", "is", "are", "was", "were", "be", "been",
        "to", "of", "in", "for", "on", "with", "and", "or", "at",
        "by", "from", "as", "that", "this", "it", "its", "i", "you",
        "we", "they", "he", "she", "my", "your", "our", "their",
    }
)


def _tokenize_for_grounding(text: str) -> set[str]:
    """Extract normalized word tokens, excluding stop words."""
    tokens = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    return {t for t in tokens if t not in _STOP_WORDS}


def _overlap_ratio(tokens_a: set[str], tokens_b: set[str]) -> float:
    """Jaccard-like overlap: intersection / min(|a|, |b|)."""
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    return len(intersection) / min(len(tokens_a), len(tokens_b))


def verify_response_provenance(
    model_response: str,
    context: Context,
    directive_segment_indices: frozenset[int] = frozenset(),
    untrusted_threshold: TrustLevel = TrustLevel.TOOL,
    overlap_threshold: float = 0.3,
) -> ProvenanceVerificationResult:
    """Verify that model response claims are grounded in trusted context.

    Token-overlap grounding: each response sentence is mapped to its
    most likely source segment, and claims grounded in untrusted
    segments that were also flagged as directive content are tainted.

    This function moved here from the deleted
    ``tessera.claim_provenance`` module in Wave 2L. The behavior is
    unchanged; only the import path moved. Callers should switch to
    ``tessera.worker.recovery.verify_response_provenance``.
    """
    segment_tokens = [
        _tokenize_for_grounding(seg.content) for seg in context.segments
    ]
    raw_sentences = re.split(r"[.!?]+", model_response)
    sentences = [s.strip() for s in raw_sentences if len(s.split()) >= 4]

    tainted: list[ClaimGrounding] = []
    clean: list[ClaimGrounding] = []

    for sentence in sentences:
        claim_tokens = _tokenize_for_grounding(sentence)
        if not claim_tokens:
            continue
        grounding_indices: list[int] = []
        best_overlap = 0.0
        for i, seg_tokens in enumerate(segment_tokens):
            ov = _overlap_ratio(claim_tokens, seg_tokens)
            if ov >= overlap_threshold:
                grounding_indices.append(i)
                best_overlap = max(best_overlap, ov)
        if not grounding_indices:
            clean.append(
                ClaimGrounding(
                    claim=sentence,
                    segment_indices=(),
                    min_trust=TrustLevel.SYSTEM,
                    overlap_score=0.0,
                    from_directive_segment=False,
                )
            )
            continue
        dominant_idx = max(
            grounding_indices,
            key=lambda i: _overlap_ratio(claim_tokens, segment_tokens[i]),
        )
        dominant_trust = context.segments[dominant_idx].label.trust_level
        dominant_is_directive = dominant_idx in directive_segment_indices
        min_trust = min(
            context.segments[i].label.trust_level for i in grounding_indices
        )
        from_directive = any(
            i in directive_segment_indices for i in grounding_indices
        )
        is_tainted = (
            dominant_trust < untrusted_threshold and dominant_is_directive
        )
        grounding = ClaimGrounding(
            claim=sentence,
            segment_indices=tuple(grounding_indices),
            min_trust=min_trust,
            overlap_score=best_overlap,
            from_directive_segment=from_directive,
        )
        if is_tainted:
            tainted.append(grounding)
        else:
            clean.append(grounding)

    total = len(tainted) + len(clean)
    score = len(tainted) / total if total > 0 else 0.0
    return ProvenanceVerificationResult(
        tainted_claims=tuple(tainted),
        clean_claims=tuple(clean),
        tainted=bool(tainted),
        score=score,
    )


def from_claim_provenance(
    model_response: str,
    context: Context,
    **kwargs: Any,
) -> ProvenanceVerificationResult:
    """Stable alias for :func:`verify_response_provenance`.

    Wave 2L absorbed the legacy ``tessera.claim_provenance`` module
    into this one. This alias keeps any caller that grepped for the
    historic name working without a deprecation warning, since the
    name now lives at a permanent address.
    """
    return verify_response_provenance(model_response, context, **kwargs)


__all__ = [
    "ClaimGrounding",
    "FieldRecovery",
    "ProvenanceVerificationResult",
    "RecoveryResult",
    "field_provenance_recovery",
    "from_claim_provenance",
    "verify_response_provenance",
]
