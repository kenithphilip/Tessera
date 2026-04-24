# Tessera Rust workspace, roadmap

What landed in each release line, what is in flight, and what
sits beyond. Items that the original 8-phase plan deliberately
deferred or excluded are here too, so reviewers can see the whole
picture rather than just the in-flight work.

## Shipped (v0.11.0, current)

Five follow-on items from the v0.10.0 retrospective:

- **GitHub Actions wheel matrix.** `.github/workflows/wheels.yml`
  ships cp310/cp311/cp312 abi3 wheels for linux x86_64, linux
  aarch64, macOS x86_64, macOS aarch64, windows x64. Linux aarch64
  cross-build fixed by dropping `tessera-runtime` (and its
  transitive `ring` dep) from `tessera-py`.
- **Rate limiter PyO3 binding.** `tessera_rs.ratelimit.ToolCallRateLimit`
  exposes the existing `tessera-policy::ratelimit::ToolCallRateLimit`
  to Python with byte-equal reason strings. 3 cross-language
  interop tests pin window cap, burst detection, and lifetime cap.
- **Deeper AgentMesh auto-swap.** `MeshProxy(use_rust_primitives=True)`
  now swaps the rate limiter, SSRF guard, and audit sink (when
  `audit_log_path` is set). The Policy / Context / scanner / URL
  rules / CEL adapters remain available for direct construction.
- **PyScanner callback registry.**
  `tessera_rs.scanners.register_scanner` + `scan` provide a
  process-global registry for hard scanners (PromptGuard,
  Perplexity, PDFInspector, ImageInspector, CodeShield) that
  depend on Python ML / PIL / sandboxed-PDF stacks.
- **Single-endpoint bench compare.** `bench-compare.sh` now runs
  both `mixed` and `evaluate` workloads against the dual targets
  and captures both tables to `rust/bench/results.md`.

20 adapter parity tests, 3 rate-limiter interop tests, all green.
Default-features test suite plus the `cel-jit` feature suite both
pass with no regressions.

## Shipped (v0.10.0)

Closes the 8-phase port plan plus the v0.10.0 four-wave plan:

- CEL evaluator port (cel-interpreter, byte-equal Python parity)
- Cranelift CEL JIT codegen (12-80x interpreter speedup on int rules)
- simd-json axum body extractor (4-8% faster on 4-64KB bodies)
- EmbeddingAnomalyChecker `compute_baseline` in both languages
- AgentMesh `tessera_rs` adapter (audit sink auto-swap)
- bench-compare.sh first measured side-by-side numbers

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

## Shipped (v0.9.0-alpha.1)

Phase 7 of the original plan:

- **OpenTelemetry-native spans** behind the `tessera-gateway`
  `otel` feature.
- **Workspace housekeeping**, [workspace.lints] normalization,
  per-crate READMEs, zero warnings in the default build.

## Deferred (post-v0.11.0)

Items tracked but not slated for the next release.

- **SessionContextStore single-shard contention.** The
  v0.11.0 single-endpoint bench surfaced that `/v1/evaluate`
  serializes per session_id on one DashMap shard. A per-key
  hot-path bypass (Arc cache that skips the shard lock when the
  context is unchanged) would unlock realistic single-endpoint
  parity with the Python proxy. Tracked for v0.12.0.
- **Wider AgentMesh auto-swap.** Rate limiter, SSRF, and audit
  are auto-swapped today; Policy + Context + URL rules + CEL +
  scanners require explicit construction. Wider coverage is a
  set of small construction-site edits in `proxy.py.__post_init__`
  that need careful integration testing per surface.
- **Hard-scanner ONNX path.** The PyScanner callback bridge
  ships in v0.11.0; the next step is a Rust-native inference
  path for PromptGuard/Perplexity that drops the Python ML
  dependency. Tracked when a customer asks for the deployment
  simplification.

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
