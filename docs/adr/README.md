# Architecture Decision Records

ADRs capture the "why" behind significant project decisions so
future maintainers (and auditors) can reconstruct the reasoning.

Format: one Markdown file per decision, numbered sequentially,
named `NNNN-short-title.md`. Status values are `Proposed`,
`Accepted`, `Superseded by NNNN`, or `Deprecated`.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-license-split.md) | License split: Tessera Apache, AgentMesh AGPL | Accepted (2026-04-24) |
| [0002](0002-no-hosted-services.md) | No Tessera-hosted commercial services | Accepted (2026-04-24) |
| [0003](0003-foundation-governance-deferred.md) | Foundation governance proposal at v1.1, not v1.0 | Accepted (2026-04-24) |
| [0004](0004-nccoe-via-channels.md) | NCCoE reference impl is contributed through NCCoE channels | Accepted (2026-04-24) |
| [0005](0005-rust-data-plane.md) | Rust workspace stays the production data plane | Accepted (2026-04-24) |
| [0006](0006-arg-level-provenance-primary.md) | Argument-level provenance is the v1.0 enforcement primary | Accepted (2026-04-24) |
| [0007](0007-provenance-label-v2.md) | ProvenanceLabel v2 migration plan locked at end of Phase 3 | Proposed |

## When to write a new ADR

- A change touches a load-bearing invariant (license, security
  primitive, wire format, governance).
- A change has external consequences (downstream consumers,
  partners, regulators).
- A change is reversible only at high cost (re-license,
  foundation transition, API freeze).

Routine engineering decisions live in commit messages, PR
descriptions, or the rolling roadmap, not in ADRs.
