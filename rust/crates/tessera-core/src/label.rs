//! v1.0 Phase 4 wave 4B: canonical Rust ProvenanceLabel (GA).
//!
//! This module pins the Rust shape that mirrors the Python
//! :class:`tessera.taint.label.ProvenanceLabel` byte-for-byte at
//! the wire level. The Python class remains the source of truth
//! for in-process callers; the Rust shape ensures cross-language
//! serializers (the PyO3 wheel + the agentgateway plugins +
//! future non-Python consumers) all read and write the same JSON
//! sidecar (``__tessera_labels__``).
//!
//! v1.0 freeze: the field set, the JSON-Schema, and the canonical
//! ordering of `sources` are pinned for the v1.x line. Additive
//! v2 changes are documented in
//! `docs/adr/0007-provenance-label-v2-migration.md` and land via
//! a `schema_version` sidecar bump (NOT an in-place edit).

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// IntegrityLevel: lower numeric value is more trusted.
///
/// The numeric ordering (TRUSTED=0, ENDORSED=1, UNTRUSTED=2) is
/// load-bearing: comparisons in the policy engine use
/// `observed.value <= required.value` to mean "observed is at
/// least as trusted as required".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityLevel {
    /// Highest trust. Reserved for initial labels (user input,
    /// system prompts).
    Trusted,
    /// Lower trust. Worker output that has crossed a critic
    /// boundary and been declassified.
    Endorsed,
    /// Lowest trust. Untrusted tool output, web content, etc.
    Untrusted,
}

impl IntegrityLevel {
    /// Numeric value used by the policy engine.
    pub fn numeric(self) -> u8 {
        match self {
            IntegrityLevel::Trusted => 0,
            IntegrityLevel::Endorsed => 1,
            IntegrityLevel::Untrusted => 2,
        }
    }
}

/// SecrecyLevel: higher numeric value is more secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecrecyLevel {
    /// May be shared with anyone.
    Public,
    /// Internal use only.
    Internal,
    /// Restricted to specific readers.
    Private,
    /// Highest classification; PII / credentials.
    Restricted,
}

impl SecrecyLevel {
    /// Numeric value matching the Python enum's storage.
    pub fn numeric(self) -> u8 {
        match self {
            SecrecyLevel::Public => 0,
            SecrecyLevel::Internal => 1,
            SecrecyLevel::Private => 2,
            SecrecyLevel::Restricted => 3,
        }
    }
}

/// InformationCapacity: how much information the value can carry.
///
/// Used by the critic to reject implausible argument shapes
/// (e.g., a STRING-capacity value as a `transfer_funds.amount`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum InformationCapacity {
    /// Single-bit value (true/false).
    Bool,
    /// Bounded enum.
    Enum,
    /// Numeric value.
    Number,
    /// Free-form string (largest capacity).
    String,
}

impl InformationCapacity {
    /// Numeric value matching the Python enum's storage.
    pub fn numeric(self) -> u8 {
        match self {
            InformationCapacity::Bool => 1,
            InformationCapacity::Enum => 2,
            InformationCapacity::Number => 3,
            InformationCapacity::String => 4,
        }
    }
}

/// One source segment a label depends on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SegmentRef {
    /// Stable identifier for the segment.
    pub segment_id: String,
    /// Optional URI describing where the segment came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_uri: Option<String>,
    /// Optional MCP manifest digest the segment was bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    /// Trust level numeric (matches the legacy TrustLevel
    /// constants in :mod:`tessera_core::labels`).
    pub trust_level: i64,
}

/// Reader policy for a label.
///
/// `Public` means any principal may read. A specific set of
/// principal strings restricts visibility to those readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Readers {
    /// Public marker; any principal may read.
    Public(PublicMarker),
    /// Restricted to a specific set of principals.
    Set(BTreeSet<String>),
}

/// Tag for the `Public` reader policy. Serializes as the literal
/// string `"PUBLIC"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PublicMarker {
    /// The Public marker value.
    Public,
}

/// v1.0-frozen ProvenanceLabel.
///
/// Mirrors the Python :class:`tessera.taint.label.ProvenanceLabel`
/// at the wire level. Field ordering, enum spelling, and JSON
/// shape are pinned for the v1.x line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceLabel {
    /// Sources the value depends on. Ordered set so canonical
    /// JSON encoding is deterministic across runs.
    pub sources: BTreeSet<SegmentRef>,
    /// Reader policy.
    pub readers: Readers,
    /// Integrity level.
    pub integrity: IntegrityLevel,
    /// Secrecy classification.
    pub secrecy: SecrecyLevel,
    /// Information capacity.
    pub capacity: InformationCapacity,
}

impl ProvenanceLabel {
    /// Build a label for trusted-user content.
    pub fn trusted_user(principal: impl Into<String>) -> Self {
        let principal = principal.into();
        let mut sources = BTreeSet::new();
        sources.insert(SegmentRef {
            segment_id: format!("user:{}", principal),
            origin_uri: Some(format!("user://{}", principal)),
            manifest_digest: None,
            trust_level: 100,
        });
        Self {
            sources,
            readers: Readers::Public(PublicMarker::Public),
            integrity: IntegrityLevel::Trusted,
            secrecy: SecrecyLevel::Public,
            capacity: InformationCapacity::String,
        }
    }

    /// Build a label for untrusted tool output.
    pub fn untrusted_tool_output(
        segment_id: impl Into<String>,
        origin_uri: Option<String>,
    ) -> Self {
        let mut sources = BTreeSet::new();
        sources.insert(SegmentRef {
            segment_id: segment_id.into(),
            origin_uri,
            manifest_digest: None,
            trust_level: 0,
        });
        Self {
            sources,
            readers: Readers::Public(PublicMarker::Public),
            integrity: IntegrityLevel::Untrusted,
            secrecy: SecrecyLevel::Public,
            capacity: InformationCapacity::String,
        }
    }

    /// Lattice join: integrity is max (worst), secrecy is max
    /// (most secret), capacity is max (largest), readers is
    /// intersection (intersect when both restricted; remain
    /// Public when either is Public).
    pub fn join(&self, other: &Self) -> Self {
        let mut sources = self.sources.clone();
        sources.extend(other.sources.iter().cloned());
        let readers = match (&self.readers, &other.readers) {
            (Readers::Public(_), r) | (r, Readers::Public(_)) => r.clone(),
            (Readers::Set(a), Readers::Set(b)) => {
                Readers::Set(a.intersection(b).cloned().collect())
            }
        };
        Self {
            sources,
            readers,
            integrity: std::cmp::max(self.integrity, other.integrity),
            secrecy: std::cmp::max(self.secrecy, other.secrecy),
            capacity: std::cmp::max(self.capacity, other.capacity),
        }
    }

    /// Stable canonical-JSON encoding for hashing / signing.
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).expect("ProvenanceLabel always serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_ordering() {
        assert!(IntegrityLevel::Trusted < IntegrityLevel::Endorsed);
        assert!(IntegrityLevel::Endorsed < IntegrityLevel::Untrusted);
        assert_eq!(IntegrityLevel::Trusted.numeric(), 0);
        assert_eq!(IntegrityLevel::Untrusted.numeric(), 2);
    }

    #[test]
    fn trusted_user_round_trip() {
        let label = ProvenanceLabel::trusted_user("alice");
        let wire = label.to_canonical_json();
        let revived: ProvenanceLabel = serde_json::from_str(&wire).unwrap();
        assert_eq!(label, revived);
        assert_eq!(label.integrity, IntegrityLevel::Trusted);
    }

    #[test]
    fn untrusted_tool_round_trip() {
        let label = ProvenanceLabel::untrusted_tool_output(
            "seg-1",
            Some("web://evil.example".into()),
        );
        let wire = label.to_canonical_json();
        let revived: ProvenanceLabel = serde_json::from_str(&wire).unwrap();
        assert_eq!(label, revived);
        assert_eq!(label.integrity, IntegrityLevel::Untrusted);
    }

    #[test]
    fn join_takes_max_integrity() {
        let user = ProvenanceLabel::trusted_user("alice");
        let untrusted = ProvenanceLabel::untrusted_tool_output("seg-1", None);
        let joined = user.join(&untrusted);
        assert_eq!(joined.integrity, IntegrityLevel::Untrusted);
    }

    #[test]
    fn join_intersects_restricted_readers() {
        let mut a = ProvenanceLabel::trusted_user("alice");
        let mut b = ProvenanceLabel::trusted_user("bob");
        a.readers = Readers::Set(vec!["alice".into(), "shared".into()].into_iter().collect());
        b.readers = Readers::Set(vec!["bob".into(), "shared".into()].into_iter().collect());
        let joined = a.join(&b);
        match joined.readers {
            Readers::Set(s) => {
                assert!(s.contains("shared"));
                assert!(!s.contains("alice"));
                assert!(!s.contains("bob"));
            }
            _ => panic!("expected intersected reader set"),
        }
    }

    #[test]
    fn join_with_public_keeps_other_side() {
        let user = ProvenanceLabel::trusted_user("alice");
        let mut restricted = ProvenanceLabel::trusted_user("bob");
        restricted.readers =
            Readers::Set(vec!["bob".into()].into_iter().collect());
        let joined = user.join(&restricted);
        match joined.readers {
            Readers::Set(s) => assert!(s.contains("bob")),
            _ => panic!("expected restricted reader set"),
        }
    }

    #[test]
    fn capacity_numeric_matches_python() {
        assert_eq!(InformationCapacity::Bool.numeric(), 1);
        assert_eq!(InformationCapacity::Enum.numeric(), 2);
        assert_eq!(InformationCapacity::Number.numeric(), 3);
        assert_eq!(InformationCapacity::String.numeric(), 4);
    }

    #[test]
    fn secrecy_ordering() {
        assert!(SecrecyLevel::Public < SecrecyLevel::Restricted);
    }
}
