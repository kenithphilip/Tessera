//! Tessera bench harness library surface.
//!
//! The binary entry point is [`main`] in `src/main.rs`; this module
//! exposes the runner, workloads, and report builders so they can
//! be invoked from integration tests and from external tooling that
//! wants to drive the harness in-process.
//!
//! # Subcommands (binary)
//!
//! - `evaluate`: hammer `POST /v1/evaluate` only.
//! - `label`: hammer `POST /v1/label`.
//! - `audit-verify`: hammer `GET /v1/audit/verify`.
//! - `mixed`: 60% evaluate, 30% label, 10% audit-verify.
//! - `sustained`: long-duration soak at a fixed RPS or concurrency.
//! - `compare`: run the same workload against two targets and emit
//!   a side-by-side report. Used to compare the Rust gateway with
//!   the Python AgentMesh proxy and successive Rust-gateway tags.
//!
//! # Output
//!
//! Every run prints a markdown summary to stdout. The harness can
//! also append the same row to `rust/bench/results.md` and drop a
//! CSV at `rust/bench/results/<git-sha>-<timestamp>.csv` for
//! Grafana ingestion. CSV columns are stable across releases.

pub mod report;
pub mod runner;
pub mod workloads;

pub use report::{format_markdown_table, write_csv, write_markdown_append, BenchReport};
pub use runner::{run_workload, BenchOutcome, RunConfig};
pub use workloads::{Workload, WorkloadKind};
