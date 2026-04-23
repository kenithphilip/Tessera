//! Cross-implementation interop test for the embedding-anomaly
//! baseline computation.
//!
//! `tessera_scanners::rag::compute_baseline` and Python's
//! `tessera.rag_guard.compute_baseline` must agree byte-for-byte on
//! the same fixed-seed corpus, so that a baseline trained in either
//! language can be fed into either implementation's
//! `EmbeddingAnomalyChecker.set_baseline` without drift.

use std::process::Command;

use tessera_scanners::rag::{compute_baseline, Baseline};

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.rag_guard"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

/// Deterministic xorshift64 so both languages can reproduce the
/// same corpus without depending on each other's RNG. The constants
/// are the ones from Marsaglia's original 2003 paper.
fn deterministic_corpus(n: usize, dim: usize, seed: u64) -> Vec<Vec<f64>> {
    let mut state: u64 = if seed == 0 { 0xDEAD_BEEF } else { seed };
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // Map u64 into [0.0, 1.0) deterministically.
        (state as f64) / (u64::MAX as f64)
    };
    (0..n)
        .map(|_| (0..dim).map(|_| next()).collect())
        .collect()
}

const SCRIPT_HEAD: &str = r#"
import json, sys
def xs(state):
    while True:
        state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 7
        state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
        yield state / 0xFFFFFFFFFFFFFFFF, state
def make_corpus(n, dim, seed):
    state = 0xDEADBEEF if seed == 0 else seed
    g = xs(state)
    rows = []
    for _ in range(n):
        row = []
        for _ in range(dim):
            v, state = next(g)
            row.append(v)
        rows.append(row)
    return rows
from tessera.rag_guard import compute_baseline
"#;

#[test]
fn rust_and_python_agree_on_small_corpus() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }

    let n = 50;
    let dim = 16;
    let seed = 0xCAFEBABE_u64;
    let corpus = deterministic_corpus(n, dim, seed);
    let rust_baseline = compute_baseline(&corpus).expect("rust compute_baseline");

    let script = format!(
        "{SCRIPT_HEAD}\ncorpus = make_corpus({n}, {dim}, {seed})\nb = compute_baseline(corpus)\nprint(json.dumps({{\"centroid\": b.centroid, \"magnitude_p99\": b.magnitude_p99, \"distance_p95\": b.distance_p95}}))\n"
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python compute_baseline failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let py_json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("python json output");

    let py_centroid: Vec<f64> = py_json["centroid"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_f64().unwrap())
        .collect();
    let py_p99 = py_json["magnitude_p99"].as_f64().unwrap();
    let py_p95 = py_json["distance_p95"].as_f64().unwrap();

    // Tight epsilon: both implementations do the same float math in
    // the same order, so we expect bitwise equivalence within a few
    // ULPs even after JSON round-trip.
    assert_eq!(rust_baseline.centroid.len(), py_centroid.len());
    for (i, (r, p)) in rust_baseline
        .centroid
        .iter()
        .zip(py_centroid.iter())
        .enumerate()
    {
        assert!(
            (r - p).abs() < 1e-12,
            "centroid[{i}] diverged: rust={r}, python={p}"
        );
    }
    assert!(
        (rust_baseline.magnitude_p99 - py_p99).abs() < 1e-12,
        "magnitude_p99 diverged: rust={}, python={py_p99}",
        rust_baseline.magnitude_p99
    );
    assert!(
        (rust_baseline.distance_p95 - py_p95).abs() < 1e-12,
        "distance_p95 diverged: rust={}, python={py_p95}",
        rust_baseline.distance_p95
    );
}

#[test]
fn rust_and_python_agree_on_one_hundred_element_corpus() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }

    // Exact 100-element corpus exercises the (n-1)*pct/100 rounding
    // boundary: p99 lands at index 98, p95 at index 94.
    let n = 100;
    let dim = 32;
    let seed = 0xFEEDFACE_u64;
    let corpus = deterministic_corpus(n, dim, seed);
    let rust_baseline = compute_baseline(&corpus).unwrap();

    let script = format!(
        "{SCRIPT_HEAD}\ncorpus = make_corpus({n}, {dim}, {seed})\nb = compute_baseline(corpus)\nprint(json.dumps({{\"centroid\": b.centroid, \"magnitude_p99\": b.magnitude_p99, \"distance_p95\": b.distance_p95}}))\n"
    );
    let out = run_python(&script);
    assert!(out.status.success(), "python invocation failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let py_json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("python json output");

    let py_p99 = py_json["magnitude_p99"].as_f64().unwrap();
    let py_p95 = py_json["distance_p95"].as_f64().unwrap();
    assert!((rust_baseline.magnitude_p99 - py_p99).abs() < 1e-12);
    assert!((rust_baseline.distance_p95 - py_p95).abs() < 1e-12);
}

#[test]
fn type_round_trips_via_serde() {
    // Pin the wire format. Anyone who serializes a Baseline from
    // either side and ships it across a process boundary depends
    // on this shape staying stable.
    let b = Baseline {
        centroid: vec![1.0, 2.0, 3.0],
        magnitude_p99: 4.0,
        distance_p95: 5.0,
    };
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"centroid\""));
    let back: Baseline = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}
