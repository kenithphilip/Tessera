//! HTTP workloads against the Tessera primitives router. Each
//! workload owns the `reqwest::Client` it uses and the request body
//! template; the runner drives many concurrent calls.
//!
//! Adding a workload: implement the [`Workload`] trait. `execute`
//! must return `Ok(())` on a successful round-trip (any 2xx that
//! the workload deems "valid"). Anything else returns `Err(String)`
//! with a brief reason that flows into the failure counter.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

pub mod evaluate;
pub mod label;
pub mod mixed;
pub mod sustained;
pub mod verify;

pub use evaluate::EvaluateWorkload;
pub use label::LabelWorkload;
pub use mixed::MixedWorkload;
pub use sustained::SustainedWorkload;
pub use verify::AuditVerifyWorkload;

/// Workload kind selected by the CLI. Maps to a concrete impl.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadKind {
    Evaluate,
    Label,
    AuditVerify,
    Mixed,
    Sustained,
}

impl WorkloadKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "evaluate" => Ok(Self::Evaluate),
            "label" => Ok(Self::Label),
            "audit-verify" | "verify" => Ok(Self::AuditVerify),
            "mixed" => Ok(Self::Mixed),
            "sustained" => Ok(Self::Sustained),
            other => Err(format!("unknown workload: {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::Label => "label",
            Self::AuditVerify => "audit-verify",
            Self::Mixed => "mixed",
            Self::Sustained => "sustained",
        }
    }
}

/// One round-trip's worth of work against a target. Implementations
/// own their own `reqwest::Client` so the connection pool is reused
/// across the run.
#[async_trait]
pub trait Workload: Send + Sync {
    fn name(&self) -> &'static str;
    async fn execute(&self, target: &str) -> Result<(), String>;
}

/// Build a `reqwest::Client` tuned for high-concurrency benchmark
/// traffic. 1000 idle conns per host, 30s connect, 30s overall
/// timeout, HTTP/2 over ALPN where supported.
pub fn build_client() -> Client {
    Client::builder()
        .pool_max_idle_per_host(1000)
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client builds with default features")
}

/// Construct a workload from a [`WorkloadKind`]. Wraps in `Arc` so
/// the runner can clone cheaply across worker tasks.
pub fn from_kind(kind: WorkloadKind) -> Arc<dyn Workload> {
    match kind {
        WorkloadKind::Evaluate => Arc::new(EvaluateWorkload::new()),
        WorkloadKind::Label => Arc::new(LabelWorkload::new()),
        WorkloadKind::AuditVerify => Arc::new(AuditVerifyWorkload::new()),
        WorkloadKind::Mixed => Arc::new(MixedWorkload::new()),
        WorkloadKind::Sustained => Arc::new(SustainedWorkload::new()),
    }
}

/// Helper: standard request body for `/v1/evaluate`. Lifted to
/// module scope so workloads can reuse it.
pub(crate) fn evaluate_body(tool: &str, session_id: &str) -> serde_json::Value {
    json!({"tool_name": tool, "session_id": session_id})
}

pub(crate) fn label_body(text: &str, tool: &str, session_id: &str) -> serde_json::Value {
    json!({"text": text, "tool_name": tool, "session_id": session_id})
}
