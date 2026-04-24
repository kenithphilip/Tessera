# Tessera Rust gateway, load harness results

Real numbers from `tessera-bench` against the primitives router in
`tessera-gateway`. Methodology, reproduce recipe, and per-tag rows
below. CSV exports for Grafana ingestion live at
`rust/bench/results/<git-sha>-<rfc3339>.csv` (gitignored).

## Methodology

Single-host loopback. The primitives router is started with the
helper at `crates/tessera-bench/examples/spawn_primitives.rs`,
which binds the same `axum::Router` the production gateway exposes
on `/v1/*`. The harness binary opens up to the configured number of
concurrent in-flight requests via `tokio::sync::Semaphore`;
latencies are recorded into `hdrhistogram` (3 sig figs, 1us..1h
range). Warmup samples are not recorded.

Loopback removes network stack from the timing, so these numbers
report the gateway plus the harness overhead, not realistic
network latency. They are the right numbers for "did a perf change
help" questions; they over-report for "what will my production
p99 be" questions.

## Reproduce

```bash
cd /Users/kenith.philip/Tessera/rust

# Terminal 1: bind the primitives router on 127.0.0.1:18081.
cargo run --release -p tessera-bench --example spawn_primitives

# Terminal 2: drive workloads.
cargo build --release -p tessera-bench
./target/release/tessera-bench evaluate \
    --target http://127.0.0.1:18081 \
    --duration 5s --concurrency 100 --warmup 1s \
    --run-label "rust-0.8.0-beta.1" \
    --report-file rust/bench/results.md \
    --csv-dir rust/bench/results \
    --git-sha "$(git rev-parse --short HEAD)"

./target/release/tessera-bench mixed \
    --target http://127.0.0.1:18081 \
    --duration 5s --concurrency 100 --warmup 1s \
    --run-label "rust-0.8.0-beta.1"

./target/release/tessera-bench audit-verify \
    --target http://127.0.0.1:18081 \
    --duration 5s --concurrency 100 --warmup 1s \
    --run-label "rust-0.8.0-beta.1"
```

Compare against another target (e.g. the Python AgentMesh proxy):

```bash
./target/release/tessera-bench compare \
    --rust-target http://127.0.0.1:18081 \
    --python-target http://127.0.0.1:18082 \
    --workload mixed --duration 60s --concurrency 1000 --warmup 10s \
    --rust-label "rust-0.8.0-beta.1" \
    --python-label "python-0.7.x"
```

## PGO build

Profile-guided-optimization builds use the script at
`rust/scripts/pgo-build.sh`. Two-stage workflow: instrument with
`cargo-pgo`, drive `tessera-bench mixed` for the configured
duration, merge with `llvm-profdata`, recompile. Re-run the
baseline below against the optimized binary to capture the PGO row
in the comparison table.

## v0.8.0-beta.1 baseline (Apple M3 Pro, single-host loopback)

| Workload     | Concurrency | Duration | Successes | Failures | RPS     | p50 ms | p95 ms | p99 ms | p99.9 ms | max ms |
|--------------|-------------|----------|-----------|----------|---------|--------|--------|--------|----------|--------|
| evaluate     | 100         | 5s       | 803,681   | 0        | 160,736 | 0.65   | 1.20   | 1.51   | 2.09     | 5.39   |
| mixed        | 100         | 5s       | 25,848    | 0        | 5,170   | 28.59  | 59.84  | 73.47  | 91.58    | 104.96 |
| audit-verify | 100         | 5s       | 995,727   | 0        | 199,145 | 0.52   | 0.90   | 1.16   | 1.93     | 14.09  |

Reading the numbers:

- `evaluate` and `audit-verify` saturate at ~160k and ~200k RPS
  respectively at concurrency 100. Both are read-heavy: evaluate
  walks the context's `min_trust` over a small in-memory `Vec`,
  and audit-verify walks the chain on disk (empty in this run).
- `mixed` (60% evaluate, 30% label, 10% audit-verify) drops to
  5,170 RPS because every `label` call hashes + signs a new
  segment and writes it through the session context. The DashMap
  shard contention dominates here; raising the concurrency past
  ~32 (the default shard count on an 8-core host) does not help.
  This is the correct shape, not a regression.
- Failures are 0 across the board. The harness successfully
  exhausts the loopback path before the gateway saturates.

## v0.10.0 wave A: SIMD-accelerated body parsing

`SimdJson<T>` axum extractor introduced in
`crates/tessera-gateway/src/simd_extractor.rs` swaps `serde_json`
for `simd_json` on 6 production handlers (4 in `endpoints.rs`, 2
in `lib.rs`). Falls back to `serde_json` on parse error so behavior
on edge bodies stays identical.

Microbench (criterion, Apple M3 Pro, single-host loopback):

| Body size | Parser     | Time      | Throughput   | Delta       |
|-----------|------------|-----------|--------------|-------------|
| 4 KB      | serde_json | 19.06 us  | 183 MiB/s    | baseline    |
| 4 KB      | simd_json  | 17.55 us  | 199 MiB/s    | -8% time    |
| 64 KB     | serde_json | 378.49 us | 145 MiB/s    | baseline    |
| 64 KB     | simd_json  | 362.05 us | 151 MiB/s    | -4% time    |

Delta is small at these sizes because the cost is dominated by
allocator + UTF-8 validation; simd_json's main wins are at larger
nested-object payloads (tens of KB and up). On the loopback bench
the JSON parser is not the bottleneck (allocator + DashMap shard
contention is), so the gateway-level RPS numbers in the v0.8.0
baseline above do not move measurably; the per-call latency does.

Run with `cargo bench --bench json_extractor -p tessera-bench`.

## v0.10.0 wave B: CEL evaluator (interpreter vs Cranelift JIT)

`crates/tessera-policy/src/cel.rs` ships a parity port of
`tessera.cel_engine` via cel-interpreter. `crates/tessera-policy/src/cel_jit.rs`
adds a `cranelift-jit`-backed `JitCelEvaluator` (gated behind the
`cel-jit` feature) that compiles the supported CEL subset (int
comparison + boolean composition + int ident lookup) to native code.
Anything outside the subset (string ops, args lookup, function
calls) transparently falls back to the interpreter; the engine
exposes `jit_count()` and `fallback_count()` for ops visibility.

Microbench (criterion, Apple M3 Pro, single-host, `cargo bench
--bench cel_eval -p tessera-bench`):

| Workload    | Interpreter | JIT    | Speedup |
|-------------|-------------|--------|---------|
| 1 rule      | 3.21 us     | 40 ns  | ~80x    |
| 5 rules     | 3.36 us     | 53 ns  | ~63x    |
| 50 rules    | 5.32 us     | 460 ns | ~12x    |

Reading the numbers:

- The JIT pays back enormously on int-only rules. Per-call activation
  build is ~3 us in the interpreter (HashMap of CelValue boxes); the
  JIT just loads two i64s from a stack-allocated `JitActivation`.
- The 50-rule pack still runs the JIT through every rule serially
  (no chain optimization), so the 460 ns is dominated by the linear
  walk; even there it is 12x faster than the interpreter.
- Rules with string ops or args lookups fall back to the interpreter
  for that rule. The fallback path is identical in cost to running
  the interpreter directly.

Run with `cargo bench --bench cel_eval -p tessera-bench`. The
`cel-jit` feature is enabled implicitly because tessera-bench's
dev-deps include `tessera-policy = { features = ["cel-jit"] }`.

## Comparison rows

The plan calls for rows comparing:
- Python AgentMesh proxy (current production reference)
- Rust gateway 0.7.x baseline
- Rust gateway 0.8.x with all perf wins (this row, above)

The first two rows are not yet captured: standing up the Python
proxy and the v0.7.x Rust gateway in CI is Phase 6 work. The
harness is ready to absorb both rows as soon as the targets are
running; the `compare` subcommand emits both rows in one report.

## CSV columns

Stable across releases:

```
title, run_label, workload, target, duration_seconds, concurrency,
successes, failures, rps, p50_us, p95_us, p99_us, p999_us, max_us,
success_rate, generated_at
```

Latency columns are microseconds (no decimals); `rps` and
`success_rate` are floats. Grafana datasource queries can pivot on
`run_label` and `workload` for time-series charts across tags.

## v0.10.0 wave D: Rust gateway vs Python AgentMesh proxy

First captured side-by-side comparison, mixed workload, single-host
loopback. Run via `rust/scripts/bench-compare.sh 10s 50` which spins
up both targets, waits for `/healthz`, drives identical workload
mix, and tears down on exit.

| Run | Workload | Target | Duration | Concurrency | Successes | RPS | p50 ms | p95 ms | p99 ms | p99.9 ms | max ms |
|-----|----------|--------|----------|-------------|-----------|-----|--------|--------|--------|----------|--------|
| `rust` (gateway 0.10.0-rc.1) | mixed | :18081 | 10s | 50 | 39,395 | 3,940 | 29.15 | 52.45 | 64.22 | 78.46 | 90.43 |
| `python` (AgentMesh 0.7.1) | mixed | :18082 | 10s | 50 | 29,775 | 2,978 | 29.28 | 40.54 | 47.97 | 52.45 | 60.67 |

Reading the numbers honestly:

- The Rust gateway processes 32% more requests per second (3,940
  vs 2,978 RPS). That is the headline win.
- The Rust gateway's p99 is 34% higher (64 ms vs 48 ms). At the
  same concurrency it is closer to saturation, so each individual
  request waits longer in the queue. Lower concurrency or more
  cores would shift this in Rust's favor.
- The two targets are doing different work for the same workload.
  The Rust gateway runs the simpler primitives router (just
  taint-floor evaluate + label + audit-verify); the AgentMesh proxy
  also runs prompt screening, secret redaction, risk forecasting,
  and identity verification on every request. So this is more
  "Rust gateway with feature subset" vs "AgentMesh full stack" than
  it is "Rust vs Python on identical work".
- A fairer single-endpoint comparison (just `/v1/evaluate`) would
  show the Rust 150x microbench advantage from the policy-eval
  bench. The mixed workload shows what happens at the macro level
  when both stacks are saturated.

Reproduce with:

```bash
cd /Users/kenith.philip/Tessera/rust
./scripts/bench-compare.sh 30s 200
```

The script auto-detects the AgentMesh venv at
`~/AgentMesh/.venv/bin/python` and falls back to a Rust-only run if
that venv is missing.

## Auto-appended runs

The `compare` and single-workload subcommands append their tables
below this line when invoked with `--report-file`. New runs land
here without overwriting the curated sections above.

## compare (mixed)

Generated: `2026-04-24T11:41:14.725869+00:00`

| Run | Workload | Target | Duration | Concurrency | Successes | Failures | RPS | p50 ms | p95 ms | p99 ms | p99.9 ms | max ms | Success rate |
|-----|----------|--------|----------|-------------|-----------|----------|-----|--------|--------|--------|----------|--------|--------------|
| `rust` | mixed | `http://127.0.0.1:18081` | 10.0s | 50 | 39395 | 0 | 3940 | 29.15 | 52.45 | 64.22 | 78.46 | 90.43 | 100.00% |
| `python` | mixed | `http://127.0.0.1:18082` | 10.0s | 50 | 29775 | 0 | 2978 | 29.28 | 40.54 | 47.97 | 52.45 | 60.67 | 100.00% |
