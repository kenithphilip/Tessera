//! Tiny helper: spawn the primitives router on `127.0.0.1:8081`
//! and block. Useful for running the bench harness against a real
//! tokio listener without standing up the full `tessera-gateway`
//! binary (which needs config, TLS, control-plane env vars, etc.).
//!
//! Build and run:
//!
//! ```text
//! cargo run --release -p tessera-bench --example spawn_primitives
//! ```
//!
//! Then in another shell:
//!
//! ```text
//! ./target/release/tessera-bench evaluate \
//!     --target http://127.0.0.1:8081 \
//!     --duration 10s --concurrency 100 --warmup 2s
//! ```

use std::sync::Arc;

use tessera_gateway::endpoints::{build_router, PrimitivesState};
use tokio::net::TcpListener;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let state = Arc::new(PrimitivesState::with_signing_key(
        "tessera-bench-target",
        b"bench-key-32bytes!!!!!!!!!!!!!!".to_vec(),
    ));
    let app = build_router(state);
    let addr = std::env::var("TESSERA_BENCH_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let listener = TcpListener::bind(&addr)
        .await
        .expect("bind primitives router");
    let bound = listener.local_addr().unwrap();
    eprintln!("primitives router listening on http://{bound}");
    eprintln!("Ctrl+C to stop.");
    axum::serve(listener, app).await.expect("axum::serve");
}
