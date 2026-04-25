//! Hash-chained audit event sink plugin shaped for upstream
//! agentgateway. In-tree under the Tessera repo until the upstream
//! PR to ``solo-io/agentgateway`` merges.
//!
//! The sink mirrors the contract of
//! :class:`tessera.compliance.ChainedAuditLog` in the Python tree:
//! every appended event carries the SHA-256 of the prior entry,
//! producing a tamper-evident chain that ``verify_chain`` walks.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors returned by the sink.
#[derive(Debug, Error)]
pub enum SinkError {
    /// JSON serialization failed for an entry.
    #[error("entry serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// One audit event the sink chains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    /// Monotonic timestamp; the sink does not enforce ordering but
    /// surfaces violations via :meth:`verify_chain`.
    pub timestamp_unix_ms: u64,
    /// Stable event-kind identifier (e.g. ``"policy_deny"``).
    pub kind: String,
    /// Authenticated principal that triggered the event.
    pub principal: String,
    /// Free-form detail blob serialized as JSON.
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainedEntry {
    sequence: u64,
    previous_hash: [u8; 32],
    entry_hash: [u8; 32],
    event: AuditEvent,
}

/// Hash-chained audit sink instance.
#[derive(Debug, Default)]
pub struct HashChainedAuditSink {
    entries: Vec<ChainedEntry>,
    sequence: u64,
    last_hash: [u8; 32],
}

impl HashChainedAuditSink {
    /// Build an empty sink with the genesis hash zeroed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event and return the resulting entry hash.
    pub fn append(&mut self, event: AuditEvent) -> Result<[u8; 32], SinkError> {
        self.sequence += 1;
        let canonical = serde_json::to_vec(&serde_json::json!({
            "sequence": self.sequence,
            "previous_hash": hex::encode_lower(self.last_hash),
            "event": &event,
        }))?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let digest = hasher.finalize();
        let mut entry_hash = [0u8; 32];
        entry_hash.copy_from_slice(&digest);
        let entry = ChainedEntry {
            sequence: self.sequence,
            previous_hash: self.last_hash,
            entry_hash,
            event,
        };
        self.entries.push(entry);
        self.last_hash = entry_hash;
        Ok(entry_hash)
    }

    /// Re-derive every entry's hash and confirm the chain.
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for entry in &self.entries {
            if entry.previous_hash != expected_prev {
                return false;
            }
            let canonical = match serde_json::to_vec(&serde_json::json!({
                "sequence": entry.sequence,
                "previous_hash": hex::encode_lower(entry.previous_hash),
                "event": &entry.event,
            })) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let mut hasher = Sha256::new();
            hasher.update(&canonical);
            let digest = hasher.finalize();
            let mut computed = [0u8; 32];
            computed.copy_from_slice(&digest);
            if computed != entry.entry_hash {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }

    /// Return the current chain head; ``[0; 32]`` when empty.
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }

    /// Return how many events were appended.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no events have been appended.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

mod hex {
    pub(crate) fn encode_lower(bytes: [u8; 32]) -> String {
        bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: &str, t: u64) -> AuditEvent {
        AuditEvent {
            timestamp_unix_ms: t,
            kind: kind.to_string(),
            principal: "alice".to_string(),
            detail: serde_json::json!({}),
        }
    }

    #[test]
    fn round_trip_append_and_verify() {
        let mut sink = HashChainedAuditSink::new();
        sink.append(ev("policy_deny", 1)).unwrap();
        sink.append(ev("policy_deny", 2)).unwrap();
        sink.append(ev("policy_deny", 3)).unwrap();
        assert!(sink.verify_chain());
        assert_eq!(sink.len(), 3);
    }

    #[test]
    fn tamper_breaks_chain() {
        let mut sink = HashChainedAuditSink::new();
        sink.append(ev("a", 1)).unwrap();
        sink.append(ev("b", 2)).unwrap();
        sink.append(ev("c", 3)).unwrap();
        // Mutate one entry's event payload.
        sink.entries[1].event.principal = "TAMPERED".into();
        assert!(!sink.verify_chain());
    }

    #[test]
    fn sequence_ordering_preserved() {
        let mut sink = HashChainedAuditSink::new();
        sink.append(ev("a", 10)).unwrap();
        sink.append(ev("b", 20)).unwrap();
        for (i, entry) in sink.entries.iter().enumerate() {
            assert_eq!(entry.sequence, (i as u64) + 1);
        }
    }
}
