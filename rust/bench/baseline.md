# Baseline microbenchmarks (v0.8.0-alpha.1)

Captured on the workspace split with mimalloc + ArcSwap perf wins
landed (Phase 1.10 + 1.11). These numbers are the floor every later
phase has to beat (or at minimum, not regress).

## Host

- Apple M3 Pro
- macOS 26.2 (build 25C56)
- rustc 1.94.1 (e408947bf 2026-03-25) (Homebrew)
- Profile: `bench` inherits `release` (lto = "thin", codegen-units = 1,
  strip = "debuginfo")
- Allocator: mimalloc (global)

## Reproduce

```bash
cd /Users/kenith.philip/Tessera/rust
cargo bench -p tessera-bench --bench policy_eval -- \
    --warm-up-time 1 --measurement-time 3
```

Numbers below use criterion's `--measurement-time 3` for a 14-bench
run that completes in roughly one minute. The default
`--measurement-time 5` produces lower variance but takes ~80 seconds
end-to-end; both yield the same medians within noise.

## Results (median time per operation)

| Workload                          | Time      | Notes                                                       |
|-----------------------------------|-----------|-------------------------------------------------------------|
| `label_sign`                      | 764 ns    | TrustLabel + HMAC-SHA256 over canonical payload             |
| `label_verify`                    | 698 ns    | HMAC-SHA256 verify, constant-time compare                   |
| `make_segment`                    | 784 ns    | sign + LabeledSegment wrap                                  |
| `policy_evaluate_clean_allow`     | 110 ns    | 1-segment context, allow path                               |
| `policy_evaluate_tainted_deny`    | 127 ns    | 2-segment context, web taint forces deny                    |
| `policy_evaluate_10_segments`     | 136 ns    | 10-segment context (one tainted), realistic session         |
| `session_store_get_warm`          | 73 ns     | DashMap-style hot-path; ArcSwap kept reads wait-free        |
| `session_store_get_new`           | 44 us     | Includes `format!()` + new entry alloc + LRU bookkeeping    |
| `audit_append_no_fsync`           | 34 us     | canonical_json + sha256 + file write, fsync_every=10000     |
| `ssrf_loopback_literal`           | 977 ns    | `http://127.0.0.1/`                                         |
| `ssrf_encoded_loopback`           | 962 ns    | `http://0x7f000001/` (hex IP decoder path)                  |
| `ssrf_cloud_metadata`             | 1057 ns   | `http://169.254.169.254/latest/meta-data/`                  |
| `url_rules_allow_hit`             | 78 ns     | prefix match against single allow rule                      |
| `url_rules_deny_hit`              | 78 ns     | prefix match where deny wins                                |
| `url_rules_no_match`              | 51 ns     | walk the rule list, fall through to default                 |

## Cross-language comparison

For the headline workload (`policy_evaluate_clean_allow`), Tessera's
Python implementation runs at roughly 50 microseconds per call
(measured under `benchmarks/microbenchmarks.md` in the Python repo).
The Rust path at 110 ns gives a ~450x speedup on the same workload.
That is consistent with the plan's claim of "~410x" carried forward
from v0.7.x; the workspace split + mimalloc + ArcSwap nudged it
slightly faster on M3 Pro.

## What this baseline is for

- Phase 2 ports more primitives. None of the workloads above should
  regress; new primitives (sensitivity, ratelimit, evidence, etc.)
  add new rows here, they don't move existing ones.
- Phase 3 ships the PyO3 wheel. Wheel-side benchmarks belong in
  `crates/tessera-py/benches/` (separate file) so the FFI overhead
  is visible without contaminating native numbers.
- Phase 4 lands the medium perf wins (crossbeam SPSC for audit,
  DashMap for session store). Watch `audit_append_no_fsync` and
  `session_store_get_new` for the impact.
- Phase 6 PGO recompile. Re-run this exact suite on the same host
  before/after to quantify.

If a later phase regresses any row by more than 10%, that is a
release blocker for the affected pre-release tag.
