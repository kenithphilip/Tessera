//! Tessera audit log: append-only JSONL hash chain.
//!
//! See [`audit_log`] for the full module. Re-exports the most-used
//! types at the crate root for ergonomic `use tessera_audit::X`
//! consumers.

pub mod audit_log;

pub use audit_log::{
    canonical_json, iter_records, verify_chain, AppendEntry, AuditError, ChainedRecord,
    JsonlHashchainSink, VerificationResult, GENESIS_HASH,
};
