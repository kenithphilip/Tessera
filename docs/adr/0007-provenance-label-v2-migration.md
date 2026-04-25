# ADR 0007: ProvenanceLabel v2 migration

**Status**: Accepted
**Date**: 2026-04-25
**Deciders**: Kenith Philip
**Supersedes**: none
**Superseded by**: none

## Context

Wave 1A froze :class:`tessera.taint.label.ProvenanceLabel` for the
v0.12 to v0.14 line. Phase 3 wave 3G expanded the Action Critic
principles library from 6 to 20 principles. Several v2 principles
(SECRECY_DONT_EXPORT, READERS_AUDIENCE_MATCH,
UNSAFE_TEMPLATE_RENDER) push on label fields the v1 schema does
not carry richly enough:

- **secrecy** is currently a single :class:`SecrecyLevel` enum
  (PUBLIC / INTERNAL / PRIVATE / RESTRICTED). The new principles
  benefit from a structured object that carries both the level AND
  a per-classification policy ("PRIVATE values cannot reach
  recipients outside the readers set" is currently inferred; v2
  makes it explicit).
- **readers** is a frozenset of principal strings or the Public
  marker. v2 principles want to express more granular reader
  policies (e.g. "only readers in this audit-allowed list" with
  expiry).
- **deps** is a frozenset of `SegmentRef` ids. This is already
  rich enough; no v2 change planned here.

Phase 4 wave 4B will GA the canonical
``tessera-core::label`` Rust crate. The Rust freeze cannot land
until the v2 shape is settled, otherwise the wheel produced in 4B
will need another ABI break in v1.1.

## Decision

ProvenanceLabel v2 is a **superset** of v1 with three additions
and zero subtractions. Existing v0.12-v0.14 callers continue to
work without code changes.

### v2 additions

1. **Structured `secrecy` object**. The bare
   :class:`SecrecyLevel` enum becomes the `level` field of a new
   :class:`SecrecyPolicy` dataclass. Backwards-compatibility via a
   `__getattr__` shim: `label.secrecy` continues to return a
   thing comparable to a SecrecyLevel; `label.secrecy.level`
   returns the same value via the new dataclass.
2. **Structured `readers` object**. The bare frozenset becomes the
   `principals` field of a new :class:`ReaderPolicy` dataclass
   that adds optional `expiry: datetime | None` and
   `audit_allowed: frozenset[str]`. Back-compat: iteration over
   `label.readers` still yields the principal strings.
3. **`capacity_bits` constraint**. The existing
   `InformationCapacity` enum (BOOL / ENUM / NUMBER / STRING)
   gains an optional companion `capacity_bits: int | None` that
   pins the maximum bit count the value's representation may
   carry. Defaults to None (no cap, current behavior).

### Migration path

- v0.13 (current): label v1.
- v0.14 (this release): label v1; ADR captures the v2 plan.
- v0.15: label v2 lands behind opt-in env var
  `TESSERA_LABEL_VERSION=2`. v1 readers continue to work; the new
  v2 fields default to None / Public when absent.
- v1.0: default flips to v2. v1 envelopes still verify.
- v1.1+: v1 envelopes warn at decode; v1.2 removes v1 emission.

### Wire format

The JSON encoder (:mod:`tessera.taint.json_encoder`) gains a
`schema_version: int` sidecar entry. v1 envelopes have no version
entry and decode under v1 rules; v2 envelopes set `schema_version=2`
and decode under v2 rules.

The MCP manifest schema is unchanged: the SEP-1913 annotations
already give the per-tool data class hint that drives the new
secrecy policy; no new field is required at the manifest layer.

## Consequences

### Positive

- The Rust crate freeze in Phase 4 wave 4B has a settled target.
- v2 principles can be enforced precisely.
- Wire format stays stable for v0.x consumers.

### Negative

- One additional code path to maintain (v1 vs v2) until v1.2.
- Operators wanting v2 enforcement must opt in via env var until
  v1.0 flips the default.

### Neutral

- The changes are additive; nobody is forced to migrate at v1.0.
- The Rust crate exposes both v1 and v2 Python wrappers via
  PyO3 feature flags.

## Compliance taxonomies impacted

The eight taxonomies the SARIF mapper already enriches with v1
events keep mapping; the v2-only events that surface from the new
fields will be:

- `LABEL_SECRECY_POLICY_APPLIED` (LABEL_DECLASSIFY descendant; same
  taxonomy mappings)
- `LABEL_READER_POLICY_DENY` (existing CRITICAL_ARGS_DENY taxonomy)
- `LABEL_CAPACITY_BITS_OVERRUN` (existing CRITICAL_ARGS_DENY
  taxonomy)

These are tracked in the Phase 4 wave 4B engineering brief; not in
scope for v0.14.

## Out of scope

- ProvenanceLabel **v3**: the engineering brief proposes a label
  algebra rewrite for v2.0; that is outside this ADR.
- Cross-language wire compatibility with non-Tessera consumers
  beyond what SEP-1913 already covers.
- Any change to the lattice algebra (join semantics, declassify
  rules); those are pinned by Wave 1A and stay.

## References

- ADR-0001 License split (Tessera = Apache-2.0)
- ADR-0006 Argument-level provenance is the v1.0 enforcement
  primary
- :mod:`tessera.taint.label`
- :mod:`tessera.action_critic.principles`
  (`v1.yaml` and `v2.yaml`)
- SEP-1913 (MCP attribution)
- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.4
- Phase 4 wave 4B (Rust ``tessera-core::label`` crate GA)
