# Tessera Rust workspace, roadmap

What landed in `v0.8.0`, what is in flight for `v0.9.0`, and what
sits beyond. Items that the original 8-phase plan deliberately
deferred or excluded are here too, so reviewers can see the whole
picture rather than just the in-flight work.

## Shipped (v0.8.0)

The 8-phase port plan from
`~/.claude/plans/buzzing-baking-waterfall.md` is complete:

- 7-crate Cargo workspace with one-way dependencies. tessera-gateway
  re-exports every former path so embedders pinned to the v0.7.x
  flat layout keep working.
- 8 trivial primitives + 9 trivial scanners + 5 moderate-tier
  modules + 4 moderate scanners + 4 hard-tier modules. Every
  wire-format primitive (audit log, evidence, provenance,
  delegation, canary) has byte-for-byte cross-language interop
  tests against the Python reference.
- Perf wins across all phases: mimalloc allocator, ArcSwap on the
  policy hot path, HTTP/2 ALPN on the TLS listener, crossbeam SPSC
  channel for the audit-log writer, dashmap for the session store,
  Cow<'static, str> reasons in Decision, verify_chain_mmap for
  large audit logs, reqwest connection pool tuning, PGO build
  script.
- tessera-bench load harness with 6 subcommands; initial baseline
  numbers checked into rust/bench/results.md.
- tessera-rs PyO3 wheel with the smallest useful surface for
  Python adapter authors plus a migration guide at
  crates/tessera-py/MIGRATION.md.
- 750+ tests passing across the workspace with zero warnings.

## In flight (v0.9.0)

Phase 7 of the original plan:

- **OpenTelemetry-native spans.** Wired up behind the
  `tessera-gateway` `otel` feature. Default build stays
  transport-free (plain `tracing-subscriber` + `RUST_LOG`); enable
  `--features otel` to install the OTLP gRPC exporter. Operators
  use the standard OTel env vars
  (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`).
- **Workspace housekeeping.** [workspace.lints] table normalizes
  rust + clippy lints across crates; every crate has a README;
  every public type has rustdoc. Zero warnings in the default
  build.

## Deferred (post-v0.9.0)

These are tracked but not slated.

- **Cranelift CEL JIT.** The Python reference's
  `tessera.cel_engine` interprets CEL expressions; a Cranelift
  JIT path would compile the policy expressions to native code
  for the few customers that use CEL on the hot frame. Belongs
  here only if profiling shows CEL on the hot frame. Tracked as
  its own RFC; gated on a customer signal.
- **Phase-2 simd-json swap.** simd-json is vetted on aarch64
  (`rust/bench/simd-json-spike.md`); the actual integration
  awaits a custom axum body extractor that owns its own
  buffer. Real-world benchmark needed to justify the change.
- **Comparison rows in rust/bench/results.md.** Phase 5
  carryover. The harness is ready; the rows need both the Python
  AgentMesh proxy and the Rust v0.7.x baseline running on the
  same host.
- **EmbeddingAnomalyChecker baseline statistics.** The Phase 3
  port shipped a stub for the embedding anomaly path because the
  Python implementation pulls in numpy + sklearn. A full Rust
  port would need a BLAS-backed linear-algebra crate; deferred
  until a customer asks.

## Out of scope for the foreseeable future

These were considered and rejected for v0.8.x / v0.9.x:

- **DPDK / io_uring / eBPF.** Kernel-bypass and zero-copy
  networking buy single-digit microsecond wins on top of an
  already-microsecond-grade stack. The complexity cost is two
  orders of magnitude higher than the perf cost it saves on a
  realistic agent workload. Revisit if a customer profiles
  Tessera into the kernel as the bottleneck.
- **Custom HTTP server.** axum + hyper is good enough; the data
  plane gains nothing from rolling our own.
- **Custom JSON parser.** simd-json is the right answer for body
  parsing if and when we decide it pays off (see "deferred"
  above). A fully custom parser is not on the table.
- **Replacing tokio with another async runtime.** The runtime
  choice does not appear in any profile we have run. axum + tokio
  is the assumed substrate for the indefinite future.

## How items move

- `In flight` items move to `Shipped` when their tag lands
  (`v0.9.0` for the current row).
- `Deferred` items get their own RFC document under
  `rust/rfcs/` if and when work begins; they move to `In flight`
  on the same merge.
- `Out of scope` items only move if profiling or a customer
  signal shows the cost / benefit shifted.
