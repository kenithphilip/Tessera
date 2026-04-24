# ADR 0006: Argument-level provenance is the v1.0 enforcement primary

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

Tessera v0.7.1's load-bearing invariant is context-level:

```
allow(tool, ctx) iff required_trust(tool) <= min_{s in ctx.segments} s.trust_level
```

This is sound but coarse. Once any untrusted segment enters the
context, every downstream tool call inherits the worst-case
label. The engineering brief
(`docs/strategy/2026-04-engineering-brief.md` Section 1.1) cites
three converging research results that argue for argument-level
enforcement:

- **CaMeL** (Debenedetti et al., arXiv:2503.18813): per-value
  wrapper + dependency DAG + per-tool Python policy functions
  reduces AgentDojo ASR to 0 on three frontier models at 77%
  utility.
- **FIDES** (Costa et al., arXiv:2505.23643): lattice-based
  label model with information-capacity declassification proves
  non-interference for integrity.
- **PCAS** (arXiv:2602.16708): Datalog reference monitor over
  transitive dependency DAG improves compliance from 48% to
  93% on tau-2 bench.

Tessera already has `tessera.taint.TaintedValue` with
`frozenset[int]` sources plus `DependencyAccumulator`, but they
are secondary to `min_trust`. The v1.0 target is to make
argument-level provenance the **primary** enforcement path
while preserving `min_trust` as the compatibility floor.

## Decision

Argument-level provenance becomes the primary enforcement path
in v1.0. The deterministic policy engine evaluates per-argument
labels (via `CRITICAL_ARGS` spec table from Phase 1 wave 1B-iii)
before falling back to `min_trust`. The `TESSERA_ENFORCEMENT_MODE`
env var controls behavior:

- `scalar`: legacy v0.7 behavior (min_trust only).
- `args`: v1.0 default (argument-level + critical_args).
- `both`: parallel evaluation, both checks must pass (used as
  v0.12 default to gather telemetry on disagreement before
  flipping to `args`).

The flag ships in v0.12 (Phase 1 wave 1B-iii). Default flips to
`args` in v1.0 (Phase 4 wave 4A). `min_trust` becomes a
deprecated compat shim for one minor version after v1.0.

## Consequences

Positive:
- Tessera moves from "respectable mid-tier APR" to plausibly
  best-in-class utility-weighted security per the strategic
  review's #1 highest-leverage technical improvement.
- Argument-level enforcement gives per-reader and per-source
  expressiveness without abandoning the HMAC integrity property
  on labels.
- The CaMeL Sources / Readers + FIDES integrity / secrecy /
  capacity lattice formalizes Tessera's existing schema-enforced
  Worker pattern as a bounded-information-capacity declassification
  rule, enabling formal-security claims.

Negative:
- Performance budget tightens. Per-operation label join must
  stay under 50us; the Rust `tessera-core::label` crate
  (Phase 4 wave 4B) is the long-term home.
- Two enforcement paths through Phase 1-3 (`both` mode).
- Migration cost for users with custom `Policy.evaluate` calls;
  mitigated by the `scalar` mode opt-out.

Neutral:
- The `min_trust` invariant remains computed and emitted
  (SecurityEvent payload, OTel attribute) for backward
  compatibility, even when not the primary enforcement path.

## Alternatives considered

- **Keep `min_trust` as primary; add argument-level as opt-in.**
  Rejected because the GAP_ANALYSIS_AGENTDOJO already shows the
  Travel suite at 30% APR with the current scalar floor;
  argument-level enforcement is the documented mitigation.
- **Adopt CaMeL wholesale** (constrained Python dialect with
  AST interpreter). Rejected because it conflicts with
  Tessera's adapter-first posture (LangChain, CrewAI, ADK,
  LangGraph agents generate arbitrary Python).
- **Adopt FIDES wholesale** (per-variable label propagation).
  Rejected because it requires whole-program label propagation;
  Tessera's at-tool-call-boundary scope is more compatible with
  the adapter ecosystem.

## Implementation

- Phase 1 wave 1A: `ProvenanceLabel` substrate types.
- Phase 1 wave 1B-iii: `CRITICAL_ARGS` spec table +
  `TESSERA_ENFORCEMENT_MODE` env var, default `both`.
- Phase 4 wave 4A: default flips to `args`; `min_trust`
  deprecated to compat shim.
- ADR 0007 captures the related migration risk for the Rust
  crate freeze.

## References

- `docs/strategy/2026-04-engineering-brief.md` Sections 1.1-1.6
- `docs/GAP_ANALYSIS_AGENTDOJO.md`
- arXiv:2503.18813 (CaMeL)
- arXiv:2505.23643 (FIDES)
- arXiv:2602.16708 (PCAS)
