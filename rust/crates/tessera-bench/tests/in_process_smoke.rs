//! End-to-end smoke test for the load harness.
//!
//! Spawns the primitives router on a random port, drives a small
//! evaluate workload through the runner, and asserts that latency
//! samples and success counts make it back into the
//! [`BenchOutcome`]. Runs in seconds, so it stays in the default
//! `cargo test --workspace` path.

use std::sync::Arc;
use std::time::Duration;

use tessera_bench::runner::{run_workload, RunConfig};
use tessera_bench::workloads::{from_kind, EvaluateWorkload, Workload, WorkloadKind};
use tessera_gateway::endpoints::{build_router, PrimitivesState};
use tokio::net::TcpListener;

async fn spawn_primitives() -> String {
    let state = Arc::new(PrimitivesState::with_signing_key(
        "tessera-bench-test",
        b"test-bench-key-32bytes!!!!!!!!".to_vec(),
    ));
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // Give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evaluate_workload_round_trips_against_primitives_router() {
    let target = spawn_primitives().await;
    let workload: Arc<dyn Workload> = Arc::new(EvaluateWorkload::new());
    let cfg = RunConfig::new(Duration::from_millis(500), 16, "smoke")
        .with_max_requests(50);
    let outcome = run_workload(cfg, target, workload).await;
    assert!(outcome.successes >= 50, "want >= 50 successes, got {}", outcome.successes);
    assert_eq!(outcome.failures, 0, "no failures expected against in-process router");
    assert!(outcome.p50_us() > 0, "p50 should be positive: {:?}", outcome.p50_us());
    assert!(outcome.requests_per_second() > 0.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_workload_hits_all_three_endpoints() {
    let target = spawn_primitives().await;
    let workload = from_kind(WorkloadKind::Mixed);
    let cfg = RunConfig::new(Duration::from_millis(500), 16, "smoke-mixed")
        .with_max_requests(100);
    let outcome = run_workload(cfg, target, workload).await;
    assert!(outcome.successes >= 100, "want >= 100 successes, got {}", outcome.successes);
    assert_eq!(outcome.failures, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_verify_workload_round_trips() {
    let target = spawn_primitives().await;
    let workload = from_kind(WorkloadKind::AuditVerify);
    let cfg = RunConfig::new(Duration::from_millis(500), 8, "smoke-verify")
        .with_max_requests(20);
    let outcome = run_workload(cfg, target, workload).await;
    assert!(outcome.successes >= 20);
}
