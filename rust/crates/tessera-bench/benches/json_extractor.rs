//! Microbench comparing the SIMD JSON path used by the
//! `SimdJson<T>` axum extractor against the stock `serde_json` path
//! used by axum's built-in `Json<T>`.
//!
//! Run with `cargo bench --bench json_extractor -p tessera-bench`.
//!
//! The extractor itself adds HTTP plumbing (header check, content
//! type sniffing) that swamps the parser delta on tiny bodies. To
//! measure the actual win that simd-json brings to the gateway, this
//! bench targets the underlying parser API directly with realistic
//! request bodies (4 KB and 64 KB).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EvaluateBody {
    tool_name: String,
    session_id: String,
    args: serde_json::Value,
}

fn build_body(payload_bytes: usize) -> Vec<u8> {
    // Realistic-shape body: matches the EvaluateBody used at
    // /v1/evaluate. The `args` field carries arbitrary JSON, sized
    // up to `payload_bytes` worth of nested map entries so the
    // parser actually has work to do.
    let mut args = serde_json::Map::new();
    let entries_needed = payload_bytes / 32; // ~32 bytes per entry
    for i in 0..entries_needed {
        args.insert(
            format!("k{i:06}"),
            serde_json::Value::String(format!("v{i:06}-padding")),
        );
    }
    let body = serde_json::json!({
        "tool_name": "send_email",
        "session_id": "bench-session-id-12345",
        "args": args,
    });
    serde_json::to_vec(&body).unwrap()
}

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_extractor_parse");
    for size_label in &[("4kb", 4 * 1024usize), ("64kb", 64 * 1024)] {
        let (name, target_bytes) = *size_label;
        let body = build_body(target_bytes);
        group.throughput(Throughput::Bytes(body.len() as u64));

        group.bench_with_input(BenchmarkId::new("serde_json", name), &body, |b, input| {
            b.iter(|| {
                let parsed: EvaluateBody = serde_json::from_slice(input).unwrap();
                black_box(parsed);
            });
        });

        group.bench_with_input(BenchmarkId::new("simd_json", name), &body, |b, input| {
            b.iter(|| {
                // simd_json mutates the buffer; clone per iteration
                // to mirror the real extractor (Bytes::to_vec) cost.
                let mut buf = input.clone();
                let parsed: EvaluateBody = simd_json::serde::from_slice(&mut buf).unwrap();
                black_box(parsed);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse);
criterion_main!(benches);
