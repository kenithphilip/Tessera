# tessera-bench

Microbenchmarks (criterion) and the load test harness binary.

## Microbenchmarks

`cargo bench -p tessera-bench --bench policy_eval -- --warm-up-time 1 --measurement-time 3`

Workloads include:

- `label_sign` / `label_verify` / `make_segment` (HMAC-SHA256)
- `policy_evaluate_clean_allow` / `policy_evaluate_tainted_deny` /
  `policy_evaluate_10_segments`
- `session_store_get_warm` / `session_store_get_new`
- `audit_append_no_fsync`
- `ssrf_loopback_literal` / `ssrf_encoded_loopback` /
  `ssrf_cloud_metadata`
- `url_rules_allow_hit` / `url_rules_deny_hit` /
  `url_rules_no_match`

Baseline numbers checked into `rust/bench/baseline.md`.

## Load harness

```bash
cargo build --release -p tessera-bench
./target/release/tessera-bench evaluate \
    --target http://localhost:8081 \
    --duration 30s --concurrency 100 --warmup 5s
```

Subcommands: `evaluate`, `label`, `audit-verify`, `mixed`,
`sustained`, `compare`. Built on tokio + reqwest + hdrhistogram.
Output formats: markdown to stdout, optional append to
`--report-file`, optional CSV under `--csv-dir` for Grafana
ingestion.

`compare` drives the same workload against two targets in
sequence and emits a side-by-side report, used to compare the
Rust gateway against the Python AgentMesh proxy or against
earlier release tags.

The helper `examples/spawn_primitives.rs` binds the primitives
router on `127.0.0.1:18081` so the harness can be driven against
a real tokio listener without standing up the full
`tessera-gateway` binary.

Initial baseline is in `rust/bench/results.md`; reproduce recipe
in the same file.

## Tests

8 unit tests for the runner + report, 5 main.rs tests for
duration parsing, 3 in-process smoke tests against the gateway
router.
