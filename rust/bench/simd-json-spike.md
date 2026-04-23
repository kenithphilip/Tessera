# simd-json spike (Phase 1.13)

## Verdict

simd-json 0.13 builds and runs cleanly on Apple Silicon (M3 Pro,
macOS 26.2, rustc 1.94). No `sonic-rs` fallback is needed.

```bash
cd /tmp/simdjson-spike2 && cargo build --release && \
    ./target/release/simdjson-spike
# Object({"hello": String("world"), "n": Static(I64(42))})
```

## Why no swap landed in Phase 1

The plan's wording targeted "hot paths in `endpoints.rs`", but the
only `serde_json::from_slice` call in `endpoints.rs` is the test
helper `body_json` at `endpoints.rs:432`. The genuine per-request
JSON parses in the gateway are in `lib.rs`, and they fall into three
buckets:

| Pattern                                              | Sites                          | simd-json help?                       |
|------------------------------------------------------|--------------------------------|---------------------------------------|
| `serde_json::from_value(value.clone())`              | 1636, 2265, 2294, 2313, 4103   | None. Already a `Value`, no parse.    |
| `serde_json::from_str(raw_header)` (sub-2KB headers) | 2543, 2749                     | Marginal. Below SIMD profitability.   |
| `axum::Json<T>` extractor (request body)             | every `evaluate` / `label` etc | Real win, but requires custom extractor. |

simd-json's SIMD pipeline pays off above roughly 4 KB of input;
header parses are 200 B to 2 KB, so the setup cost can dominate the
parse cost. The body extractor is the genuine win, and that swap
belongs alongside the audit SPSC writer in Phase 4 when the load
harness can measure end-to-end p99.

## What landed instead

- `simd-json = "0.13"` stays in `[workspace.dependencies]` so the
  dep is pre-vetted and the version is pinned across the workspace.
- This note documents the spike outcome so the next phase doesn't
  re-litigate the question.

## Phase 4 follow-up

Build a custom axum extractor `Json<T>` that:

1. Reads the body into a `BytesMut` (single allocation, owned).
2. Calls `simd_json::serde::from_slice::<T>(&mut bytes)` (mutates,
   so we need owned bytes).
3. Falls back to `serde_json::from_slice` on `simd_json::Error`.

Wire it into `endpoints.rs` and `lib.rs` handlers. Benchmark with
`tessera-bench mixed --duration 60s --concurrency 10000` against a
realistic body distribution (median 1.5 KB, p99 12 KB) and only
keep the swap if p99 latency on `/v1/evaluate` improves by more
than 10%.
