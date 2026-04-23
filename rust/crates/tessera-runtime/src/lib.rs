//! Tessera runtime: per-session [`Context`] store today; Phase 4 adds
//! sessions, approval gate, LLM guardrail, and SARIF event sink.
//!
//! [`Context`]: tessera_core::context::Context

pub mod session_context;

pub use session_context::{
    Builder as SessionContextStoreBuilder, EvictCallback, MonotonicClock, SessionContextStore,
    StoreError, SystemClock,
};
