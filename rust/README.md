# Tessera Rust workspace

Cargo workspace that hosts the Rust data-plane implementation of the
Tessera primitives. The workspace lands in v0.8.0-alpha.1 as the
foundation for the multi-phase Rust port plan; v0.7.x shipped a
single `tessera-gateway` crate with all primitives inlined.

The long-term goal is the same as v0.7.x: prove the Tessera
primitives port cleanly to a production-grade Rust data plane, then
contribute the load-bearing pieces upstream to
[agentgateway](https://agentgateway.dev/). The workspace split makes
that contribution path easier (smaller, focused crates) and unlocks
the `tessera_rs` PyO3 wheel so Python adapter authors get a fast
path without reimplementing primitives.

## Workspace layout

```
rust/
  Cargo.toml                  workspace root, shared release profile and lints
  Cargo.lock
  bench/                      baseline microbench numbers and spike notes
  crates/
    tessera-core/             labels, context, no I/O, no async
    tessera-scanners/         (Phase 2) regex / Aho-Corasick scanners + Scanner trait
    tessera-audit/            hash-chained audit log, sinks, verifier
    tessera-policy/           taint-floor policy, SSRF guard, URL rules
                              (Phase 2 adds sensitivity, ratelimit, evidence,
                              provenance, mcp_baseline, delegation, compliance)
    tessera-runtime/          session_context (Phase 4 adds sessions, approval,
                              guardrail)
    tessera-gateway/          axum app, TLS, SPIFFE, control plane, endpoints
    tessera-bench/            criterion microbenches, (Phase 5) load harness binary
    tessera-py/               (Phase 3) PyO3 bindings, single wheel `tessera-rs`
                              (added in Phase 3)
```

Dependency direction is one-way:

```
tessera-gateway -> tessera-runtime -> tessera-policy -> tessera-core
                                  +-> tessera-audit  -+
                                  +-> tessera-scanners +
tessera-py     -> tessera-runtime (re-exports core / policy / audit / scanners)
tessera-bench  -> tessera-policy / tessera-audit / tessera-runtime (microbench)
                  + reqwest (Phase 5 load harness, out-of-process)
```

`tessera_gateway::*` re-exports every former path (`labels`,
`context`, `policy`, `session_context`, `audit_log`, `ssrf_guard`,
`url_rules`) so existing embedders keep building unchanged. See
`crates/tessera-gateway/src/lib.rs`.

## v0.8.0-alpha.1 (Phase 1 complete)

What landed:

- Workspace split into 7 crates (8th `tessera-py` reserved for
  Phase 3) with one-way dependencies and a single shared release
  profile.
- mimalloc as the global allocator in the gateway binary
  (`#[global_allocator]` in `tessera-gateway/src/main.rs`).
- `arc-swap` on the hot-path policy and URL-rules state
  (`PrimitivesState.policy`, `PrimitivesState.url_rules`). Reads are
  now wait-free; writes go through `update_policy` /
  `update_url_rules` helpers that clone, mutate, and atomically
  swap.
- HTTP/2 ALPN advertised on the native TLS listener
  (`build_native_tls_server_config`). Pinned by a regression test
  (`native_tls_config_advertises_h2_then_http11`).
- Criterion microbench harness in `tessera-bench` with checked-in
  baseline numbers at `bench/baseline.md`.
- simd-json vetted on aarch64; integration deferred to Phase 4
  alongside a custom axum body extractor (see
  `bench/simd-json-spike.md` for why it isn't on the critical path
  yet).

Test status: 176 passing across the workspace
(19 audit + 24 core + 58 policy + 3 interop + 54 gateway + 18
runtime, plus crate-internal totals).

## Running the suite

```bash
cd /Users/kenith.philip/Tessera/rust
cargo test --workspace
cargo bench -p tessera-bench --bench policy_eval -- \
    --warm-up-time 1 --measurement-time 3
```

Numbers from a clean run on Apple M3 Pro (rustc 1.94, release
profile + lto = "thin"):

| Workload                          | Time      | Notes                                                |
|-----------------------------------|-----------|------------------------------------------------------|
| `policy_evaluate_clean_allow`     | 110 ns    | 1-segment context, allow path                        |
| `policy_evaluate_tainted_deny`    | 127 ns    | 2-segment context, web taint forces deny             |
| `policy_evaluate_10_segments`     | 136 ns    | realistic session shape                              |
| `label_sign`                      | 764 ns    | TrustLabel + HMAC-SHA256                             |
| `label_verify`                    | 698 ns    | constant-time compare                                |
| `make_segment`                    | 784 ns    | sign + LabeledSegment wrap                           |
| `session_store_get_warm`          | 73 ns     | hot-path lookup                                      |
| `session_store_get_new`           | 44 us     | format + alloc + LRU bookkeeping                     |
| `audit_append_no_fsync`           | 34 us     | canonical_json + sha256 + file write                 |
| `ssrf_loopback_literal`           | 977 ns    | `http://127.0.0.1/`                                  |
| `ssrf_encoded_loopback`           | 962 ns    | `http://0x7f000001/` (hex IP path)                   |
| `ssrf_cloud_metadata`             | 1057 ns   | `http://169.254.169.254/...`                         |
| `url_rules_allow_hit`             | 78 ns     | prefix match against single allow rule               |
| `url_rules_deny_hit`              | 78 ns     | prefix match where deny wins                         |
| `url_rules_no_match`              | 51 ns     | walk rules, fall through to default                  |

The headline `Policy.evaluate` workload is roughly 450x faster than
the Tessera Python reference (~50 us per call). Numbers carry over
from v0.7.x with mimalloc + ArcSwap shaving a few nanoseconds; the
workspace split is behavior-neutral.

## Plan and phases

The full plan lives at
`~/.claude/plans/buzzing-baking-waterfall.md`. Summary:

| Phase | Target window | Pre-release       | Scope                                                                |
|-------|---------------|-------------------|----------------------------------------------------------------------|
| 1     | week 1        | `0.8.0-alpha.1`   | workspace split + drop-in perf wins (this release)                   |
| 2     | weeks 2-3     | `0.8.0-alpha.2`   | trivial primitives + 9 trivial scanners                              |
| 3     | weeks 4-5     | `0.8.0-alpha.3`   | moderate tier + first PyO3 wheel to TestPyPI                         |
| 4     | week 6        | `0.8.0-beta.1`    | hard tier + medium perf wins + PyO3 callback for ML scanners         |
| 5     | week 7        | `0.8.0-rc.1`      | tessera-bench load harness, Rust vs Python comparison numbers        |
| 6     | week 8        | `0.8.0`           | PyO3 wheel to public PyPI + PGO build                                |
| 7     | weeks 9-10    | `0.9.0-alpha.1`   | OpenTelemetry-native + workspace housekeeping                        |

Each phase ends with green tests and a tagged pre-release, so the
work is shippable at any phase boundary.

## Per-crate documentation

`crates/tessera-gateway/README.md` carries the gateway-specific
endpoint surface, configuration knobs, and legacy chat / A2A surface
documentation; that crate is the only one with an HTTP listener and
an external configuration story. Other crates document themselves
through rustdoc; run `cargo doc --workspace --open` for the rendered
view.
