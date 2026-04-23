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
