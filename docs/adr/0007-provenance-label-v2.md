# ADR 0007: ProvenanceLabel v2 migration plan locked at end of Phase 3

- **Status:** Proposed
- **Date:** 2026-04-24

## Context

ADR 0006 establishes argument-level provenance as the v1.0
enforcement primary. The substrate types (`ProvenanceLabel`,
`SegmentRef`, `IntegrityLevel`, `SecrecyLevel`,
`InformationCapacity`) ship in Phase 1 wave 1A. The Phase 4
wave 4B GA freezes the shape of these types in the Rust
`tessera-core::label` crate, which is consumed via PyO3 by every
downstream user of the `tessera-rs` wheel.

The forecasted shape changes between v0.12 and v1.0:

- Phase 2 wave 2I (WIMSE / draft-klrc-aiagent-auth alignment)
  may extend `SegmentRef` with WIMSE ID claims.
- Phase 2 wave 2B-i (Sigstore manifest signing) may extend
  `SegmentRef.manifest_digest` to a structured signature
  reference.
- Phase 3 wave 3G (principles library v2 with GCG-resistance
  testing) is the most likely source of unforeseen shape
  changes; adversarial testing will surface field gaps the
  initial Phase 1 design did not anticipate.

## Decision

ProvenanceLabel v2 migration is captured in this ADR (status
flips to **Accepted** when Phase 3 wave 3J completes). The Rust
crate freeze in Phase 4 cannot happen until this ADR documents
every shape change discovered through Phase 3.

The migration plan covers:

1. **Inventory** of every `ProvenanceLabel` field added,
   removed, or re-typed between v0.12 and the end of v0.14.
2. **Wire-format compatibility** decision for each change:
   either backward-compatible (additive) or breaking
   (requires a Tessera v2 wheel).
3. **Python-side compatibility shim** path: how Python code
   that imports `ProvenanceLabel` from v0.12 keeps working
   against the v1.0 Rust crate.
4. **Migration timeline**: explicit opt-out env var
   (`TESSERA_LABEL_PYTHON_ONLY=1`) lets users fall back to
   Python-only labels for one minor version after v1.0 if the
   Rust crate freeze surfaces unforeseen issues.

## Consequences

Positive:
- The Rust crate freeze in Phase 4 wave 4B is informed by
  every shape change discovered during Phases 1-3, reducing
  the probability of a breaking v2 wheel within the v1.x line.
- The opt-out env var preserves user agency if the Rust
  representation surfaces issues post-v1.0.

Negative:
- Phase 3 wave 3J adds work that cannot start until 3G
  completes (serial dependency).
- The freeze date shifts if Phase 3 surfaces a shape change
  large enough to require redesign.

Neutral:
- The existing pattern of `ProvenanceLabel` being a Python
  dataclass with serde-compatible field names makes the
  migration mostly mechanical.

## Alternatives considered

- **Freeze the Rust crate at end of Phase 1.** Rejected
  because Phase 2 + Phase 3 are guaranteed to surface
  changes; freezing too early just guarantees a breaking
  v2 wheel.
- **Defer the Rust crate to v1.1.** Rejected because the
  performance argument (ADR 0005) requires Rust to be the
  canonical representation by v1.0.
- **Skip the opt-out env var.** Rejected because v1.0 is the
  API freeze; users need an escape hatch.

## Implementation

- Phase 3 wave 3J: write the actual ADR 0007 content (this
  document captures the placeholder and acceptance criteria).
- Phase 4 wave 4B: Rust crate GA, conditional on this ADR
  reaching `Accepted` status.

## References

- ADR 0005 (Rust workspace stays the production data plane)
- ADR 0006 (argument-level provenance is the v1.0 primary)
- `docs/strategy/2026-04-engineering-brief.md` Section 1.9
  (performance budget and Rust path)
- Risk register row in the v0.12 to v1.0 plan: "ProvenanceLabel
  field shape changes between v0.12 and v1.0"
