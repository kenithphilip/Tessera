"""Provenance-grounded response verification.

When the model recommends Riverside View Hotel, which context segment
grounded that recommendation? If the only grounding is an untrusted
segment that was also flagged as containing directive language, the
model was manipulated.

This module extends taint tracking from tool-call arguments (the
DependencyAccumulator pattern) to model-output text. It treats the
model's response as a "tool call" whose arguments (claims, recommendations,
cited facts) need provenance. Each claim in the response is mapped to its
source segments via token overlap, and claims grounded only in flagged
untrusted content are marked as tainted.

This is complementary to output_monitor.py:
- output_monitor detects high-entropy token echoes (URLs, IBANs, emails)
- claim_provenance detects semantic grounding of claims in directive content

The grounding method is deterministic: token overlap between response
sentences and context segments. No LLM call required for the grounding
itself -- only the model response being analyzed needs to have been
produced by a model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tessera.context import Context
from tessera.labels import TrustLevel


@dataclass(frozen=True)
class ClaimGrounding:
    """Provenance of one claim in the model response."""

    claim: str               # the response sentence being analyzed
    segment_indices: tuple[int, ...]  # context segments that overlap this claim
    min_trust: TrustLevel    # minimum trust across grounding segments
    overlap_score: float     # max token overlap ratio (0.0-1.0) with any segment
    from_directive_segment: bool  # grounding segment was flagged as directive


@dataclass(frozen=True)
class ProvenanceVerificationResult:
    """Result of verifying provenance of all claims in a model response."""

    tainted_claims: tuple[ClaimGrounding, ...]  # claims grounded in directive content
    clean_claims: tuple[ClaimGrounding, ...]
    tainted: bool
    score: float  # 0.0-1.0: fraction of claims that are tainted


def _tokenize(text: str) -> set[str]:
    """Extract normalized word tokens, excluding stop words."""
    _STOP = frozenset({
        "a", "an", "the", "is", "are", "was", "were", "be", "been",
        "to", "of", "in", "for", "on", "with", "and", "or", "at",
        "by", "from", "as", "that", "this", "it", "its", "i", "you",
        "we", "they", "he", "she", "my", "your", "our", "their",
    })
    tokens = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    return {t for t in tokens if t not in _STOP}


def _overlap(tokens_a: set[str], tokens_b: set[str]) -> float:
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

    Extracts sentences from the model response, maps each to its most
    likely source context segment via token overlap, and flags claims
    whose grounding traces to untrusted segments that were also identified
    as containing directive language.

    Args:
        model_response: The model's text response.
        context: The context used for the model call.
        directive_segment_indices: Indices of segments flagged as containing
            directive language (from scan_directive or similar).
        untrusted_threshold: Segments below this level are untrusted.
        overlap_threshold: Minimum overlap ratio to consider a segment as
            a grounding source for a claim.

    Returns:
        ProvenanceVerificationResult with tainted/clean claim breakdown.
    """
    # Pre-tokenize all context segments
    segment_tokens = [
        _tokenize(seg.content) for seg in context.segments
    ]

    # Split model response into claim-sized chunks (sentences)
    raw_sentences = re.split(r"[.!?]+", model_response)
    sentences = [s.strip() for s in raw_sentences if len(s.split()) >= 4]

    tainted: list[ClaimGrounding] = []
    clean: list[ClaimGrounding] = []

    for sentence in sentences:
        claim_tokens = _tokenize(sentence)
        if not claim_tokens:
            continue

        grounding_indices: list[int] = []
        best_overlap = 0.0

        for i, seg_tokens in enumerate(segment_tokens):
            ov = _overlap(claim_tokens, seg_tokens)
            if ov >= overlap_threshold:
                grounding_indices.append(i)
                best_overlap = max(best_overlap, ov)

        if not grounding_indices:
            # No grounding found: treat as clean (may be model's own knowledge)
            clean.append(ClaimGrounding(
                claim=sentence,
                segment_indices=(),
                min_trust=TrustLevel.SYSTEM,
                overlap_score=0.0,
                from_directive_segment=False,
            ))
            continue

        # Taint is driven by the DOMINANT grounding: the segment with the
        # highest token overlap. A claim that shares a few tokens with an
        # untrusted segment but is primarily grounded in a USER segment is
        # not tainted -- the user already mentioned that entity.
        dominant_idx = max(
            grounding_indices,
            key=lambda i: _overlap(claim_tokens, segment_tokens[i]),
        )
        dominant_trust = context.segments[dominant_idx].label.trust_level
        dominant_is_directive = dominant_idx in directive_segment_indices

        # Also compute aggregate stats for reporting.
        min_trust = min(
            context.segments[i].label.trust_level
            for i in grounding_indices
        )
        from_directive = any(i in directive_segment_indices for i in grounding_indices)

        is_tainted = (
            dominant_trust < untrusted_threshold
            and dominant_is_directive
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
