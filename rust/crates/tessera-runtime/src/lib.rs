//! Tessera runtime: per-session [`Context`] store, approval gate, LLM
//! guardrail, and SARIF event sink.
//!
//! [`Context`]: tessera_core::context::Context

pub mod approval;
pub mod builder_llm;
pub mod guardrail;
pub mod llm_client;
pub mod sarif_sink;
pub mod session_context;
pub mod sessions;

pub use approval::{
    ApprovalDecision, ApprovalGate, ApprovalOutcome, ApprovalRequest, GateError, WebhookSigner,
};
pub use guardrail::{
    BreakerConfig, BreakerSnapshot, BreakerState, GuardrailCache, GuardrailDecision,
    GuardrailStats, InjectionCategory, LlmGuardrail, LlmGuardrailBuilder, OpenMode,
    ReqwestLlmClient,
};
pub use llm_client::{CannedLlmClient, LlmClient, LlmError, LlmRequest};
pub use sarif_sink::{SarifEventBuilder, SarifSink};
pub use session_context::{
    Builder as SessionContextStoreBuilder, EvictCallback, MonotonicClock, SessionContextStore,
    StoreError, SystemClock,
};
pub use builder_llm::{LlmPolicyProposer, LlmProposal, LlmProposalBatch};
pub use sessions::{make_session_id, PendingApproval, ResolveError, SessionStore};
