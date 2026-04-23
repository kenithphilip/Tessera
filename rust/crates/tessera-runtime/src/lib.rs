//! Tessera runtime: per-session [`Context`] store today; Phase 4 adds
//! sessions, approval gate, LLM guardrail, and SARIF event sink.
//!
//! [`Context`]: tessera_core::context::Context

pub mod sarif_sink;
pub mod session_context;

pub use sarif_sink::{SarifEventBuilder, SarifSink};
pub use session_context::{
    Builder as SessionContextStoreBuilder, EvictCallback, MonotonicClock, SessionContextStore,
    StoreError, SystemClock,
};
