# ADR 0005: Rust workspace stays the production data plane

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

Tessera ships two implementations of the load-bearing primitives:
- **Python** at `src/tessera/`: the canonical reference, where
  every primitive is first prototyped and tested.
- **Rust** at `rust/crates/tessera-*`: workspace at v0.11.0 (per
  `rust/README.md`) with seven crates plus the
  `tessera-rs` PyO3 wheel published to PyPI.

The strategic review notes Microsoft's Agent Governance Toolkit
ships sub-millisecond p99 policy evaluation in Rust. Tessera's
FastAPI proxy at ~1.4ms p50 is in the same ballpark for one
endpoint but cannot match Microsoft's Rust-native overall
profile. The reference proxy in Python is where most of the
overhead concentrates.

## Decision

The Rust workspace is the production data plane for Tessera
deployments where performance matters. The FastAPI proxy stays
as a reference SDK / dev surface and as the test harness for
the Python primitives.

Concretely:
- Operators running Tessera + AgentMesh in production with
  >1000 RPS use the Rust gateway (`tessera-gateway` crate) as
  the data plane.
- The PyPI wheel `tessera-rs` (currently 0.11.0) provides
  Python adapters access to the same Rust primitives via
  PyO3 bindings, so AgentMesh's `MeshProxy(use_rust_primitives=True)`
  swaps the hot path.
- The FastAPI proxy in `src/tessera/proxy.py` remains the
  canonical reference for the wire surface (every endpoint
  documented and tested) but is not the recommended production
  deployment.

## Consequences

Positive:
- Performance ceiling matches Microsoft's toolkit.
- Operators who don't need raw performance can still use the
  FastAPI proxy with no code changes.
- Each new primitive added in Phase 1-4 is mirrored in the Rust
  workspace through the cross-cutting Rust workspace
  continuation track.

Negative:
- Two implementations to keep in sync. Cross-language interop
  tests (e.g., `tests/python_canary_interop.rs`) are the
  contract that prevents drift.
- Rust workspace adds compilation time and toolchain complexity
  for Python-only contributors. Mitigated by the fact that
  Rust changes go through PRs that include both implementations
  + the interop test.

Neutral:
- The PyO3 wheel (`tessera-rs`) is the bridge for Python-side
  consumers who want Rust performance without leaving Python.

## Alternatives considered

- **Python-only data plane.** Rejected per the strategic
  context; Microsoft's Rust performance baseline is the new
  standard.
- **Rust-only data plane.** Rejected because the Python
  primitives ship faster (no compilation) and remain the
  reference for the wire surface; cutting Python would force
  every contributor to write Rust.
- **Drop the FastAPI proxy entirely.** Rejected because it
  serves as the dev surface and the test harness; production
  deployments using the Rust gateway depend on the Python
  primitives existing as the canonical reference.

## Implementation

- Cross-cutting Rust workspace continuation track in the v0.12
  to v1.0 plan: each Phase contributes to workspace crates.
- Phase 4 wave 4B: `tessera-core::label` crate GA. Move
  `ProvenanceLabel` from Python to Rust as the canonical
  representation; Python becomes a thin wrapper.

## References

- `rust/README.md` (Rust workspace overview)
- `docs/strategy/2026-04-mesh-review.md` Section "Microsoft's
  Agent Governance Toolkit"
- `docs/strategy/2026-04-engineering-brief.md` Section 1.9
  (performance budget and Rust path)
