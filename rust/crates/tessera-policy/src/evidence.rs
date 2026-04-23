//! Signed evidence bundles for audit and incident workflows.
//!
//! Wire format mirrors `tessera.evidence` byte-for-byte: an
//! [`EvidenceBundle`] serializes to canonical JSON (sorted keys,
//! no whitespace, ASCII-escaped non-ASCII) and signs with detached
//! HMAC-SHA256 over those exact bytes. The hex signature an Rust
//! [`HmacEvidenceSigner`] produces verifies in Python's
//! `tessera.evidence.HMACEvidenceVerifier` and vice versa; pinned by
//! the cross-language interop test in
//! `crates/tessera-gateway/tests/python_evidence_interop.rs`.
//!
//! JWT-based signing (Python `JWTEvidenceSigner` /
//! `JWTEvidenceVerifier`) is intentionally not ported here. The
//! gateway's existing JWT machinery covers RS256/ES256 signing for
//! workload identity; layering another JWT path on the policy crate
//! adds weight without unblocking the data plane. Operators that
//! need JWT-signed evidence can use the Python verifier against
//! Rust-produced HMAC bundles or re-sign on the gateway side.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tessera_audit::canonical_json;

type HmacSha256 = Hmac<Sha256>;

/// Default schema version emitted by `EvidenceBuffer.export()` in
/// the Python reference. Matched exactly so Python verifiers do not
/// reject Rust-produced bundles on schema-version drift.
pub const EVIDENCE_SCHEMA_VERSION: &str = "tessera.evidence.v1";

/// Portable event bundle for audit and incident workflows.
///
/// Mirrors `tessera.evidence.EvidenceBundle`. `BTreeMap` is used
/// for `counts_by_kind` so JSON serialization key order is
/// deterministic and matches Python's `sort_keys=True`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub generated_at: String,
    pub event_count: usize,
    pub dropped_events: usize,
    pub counts_by_kind: BTreeMap<String, usize>,
    pub events: Vec<Value>,
}

impl EvidenceBundle {
    pub fn new(generated_at: impl Into<String>) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            generated_at: generated_at.into(),
            event_count: 0,
            dropped_events: 0,
            counts_by_kind: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Canonical JSON serialization, matching Python's
    /// `_canonical_json(self.to_dict())`. The bytes returned here are
    /// what the HMAC and digest are computed over.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(&self.to_value()).into_bytes()
    }

    /// SHA-256 of the canonical bytes, lowercase hex. Matches Python's
    /// `bundle.digest`.
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    /// Convenience: rebuild a `Value` with the field order Python uses
    /// when serializing via `to_dict`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        map.insert(
            "generated_at".into(),
            Value::String(self.generated_at.clone()),
        );
        map.insert("event_count".into(), Value::from(self.event_count));
        map.insert("dropped_events".into(), Value::from(self.dropped_events));
        let mut counts = Map::new();
        for (k, v) in &self.counts_by_kind {
            counts.insert(k.clone(), Value::from(*v));
        }
        map.insert("counts_by_kind".into(), Value::Object(counts));
        map.insert("events".into(), Value::Array(self.events.clone()));
        Value::Object(map)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("malformed evidence bundle: {e}"))
    }
}

/// Evidence bundle plus detached signature metadata. The wire shape
/// mirrors Python: nested `bundle`, sibling `algorithm`, `signature`,
/// `issuer`, and `key_id` fields with `null` allowed for the latter
/// two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvidenceBundle {
    pub bundle: EvidenceBundle,
    pub algorithm: String,
    pub signature: String,
    pub issuer: Option<String>,
    pub key_id: Option<String>,
}

/// Detached HMAC-SHA256 signer.
///
/// `algorithm` defaults to `"HMAC-SHA256"`, matching Python's
/// `HMACEvidenceSigner.algorithm`. Hex-encoded signature, lowercase.
#[derive(Clone, Debug)]
pub struct HmacEvidenceSigner {
    key: Vec<u8>,
    pub algorithm: String,
    pub issuer: Option<String>,
    pub key_id: Option<String>,
}

impl HmacEvidenceSigner {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            algorithm: "HMAC-SHA256".to_string(),
            issuer: None,
            key_id: None,
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn sign(&self, bundle: EvidenceBundle) -> SignedEvidenceBundle {
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&bundle.canonical_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        SignedEvidenceBundle {
            bundle,
            algorithm: self.algorithm.clone(),
            signature,
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
        }
    }
}

/// Detached HMAC-SHA256 verifier. Constant-time comparison via
/// `Mac::verify_slice`.
#[derive(Clone, Debug)]
pub struct HmacEvidenceVerifier {
    key: Vec<u8>,
    pub algorithm: String,
}

impl HmacEvidenceVerifier {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            algorithm: "HMAC-SHA256".to_string(),
        }
    }

    pub fn verify(&self, signed: &SignedEvidenceBundle) -> bool {
        if signed.algorithm != self.algorithm {
            return false;
        }
        let signature_bytes = match hex::decode(&signed.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&signed.bundle.canonical_bytes());
        mac.verify_slice(&signature_bytes).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_bundle() -> EvidenceBundle {
        let mut counts = BTreeMap::new();
        counts.insert("policy_deny".to_string(), 2);
        counts.insert("label_verify_failure".to_string(), 1);
        EvidenceBundle {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
            generated_at: "2026-04-23T00:00:00+00:00".to_string(),
            event_count: 3,
            dropped_events: 0,
            counts_by_kind: counts,
            events: vec![
                json!({"kind": "policy_deny", "principal": "alice", "detail": {"tool": "send_email"}, "timestamp": "2026-04-23T00:00:00+00:00"}),
                json!({"kind": "policy_deny", "principal": "alice", "detail": {"tool": "delete_file"}, "timestamp": "2026-04-23T00:00:01+00:00"}),
                json!({"kind": "label_verify_failure", "principal": "unknown", "detail": {}, "timestamp": "2026-04-23T00:00:02+00:00"}),
            ],
        }
    }

    #[test]
    fn canonical_bytes_are_sorted_no_whitespace() {
        let b = sample_bundle();
        let s = String::from_utf8(b.canonical_bytes()).unwrap();
        assert!(!s.contains(' '));
        assert!(!s.contains('\n'));
        // counts_by_kind keys sort lexicographically.
        let kinds_idx = s.find("counts_by_kind").unwrap();
        let lvf_idx = s[kinds_idx..].find("label_verify_failure").unwrap();
        let pd_idx = s[kinds_idx..].find("policy_deny").unwrap();
        assert!(lvf_idx < pd_idx);
    }

    #[test]
    fn digest_is_sha256_hex_64_chars() {
        let b = sample_bundle();
        let d = b.digest();
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digest_is_deterministic() {
        let b1 = sample_bundle();
        let b2 = sample_bundle();
        assert_eq!(b1.digest(), b2.digest());
    }

    #[test]
    fn round_trip_through_serde() {
        let b = sample_bundle();
        let v = b.to_value();
        let back = EvidenceBundle::from_value(&v).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn hmac_signer_produces_64_char_hex_signature() {
        let signer = HmacEvidenceSigner::new(b"test-key-32bytes!!!!!!!!!!!!!!!!");
        let signed = signer.sign(sample_bundle());
        assert_eq!(signed.signature.len(), 64);
        assert!(signed.signature.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(signed.algorithm, "HMAC-SHA256");
    }

    #[test]
    fn hmac_round_trip_verifies() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let verifier = HmacEvidenceVerifier::new(b"key-A".to_vec());
        let signed = signer.sign(sample_bundle());
        assert!(verifier.verify(&signed));
    }

    #[test]
    fn hmac_wrong_key_fails_verification() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let verifier = HmacEvidenceVerifier::new(b"key-B".to_vec());
        let signed = signer.sign(sample_bundle());
        assert!(!verifier.verify(&signed));
    }

    #[test]
    fn hmac_wrong_algorithm_fails_verification() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let verifier = HmacEvidenceVerifier::new(b"key-A".to_vec());
        let mut signed = signer.sign(sample_bundle());
        signed.algorithm = "HS256".to_string();
        assert!(!verifier.verify(&signed));
    }

    #[test]
    fn hmac_tampered_bundle_fails_verification() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let verifier = HmacEvidenceVerifier::new(b"key-A".to_vec());
        let mut signed = signer.sign(sample_bundle());
        signed.bundle.event_count = 999;
        assert!(!verifier.verify(&signed));
    }

    #[test]
    fn signer_with_issuer_and_key_id_propagates_to_signed_bundle() {
        let signer = HmacEvidenceSigner::new(b"key-A")
            .with_issuer("agent-mesh-test")
            .with_key_id("k-2026-04");
        let signed = signer.sign(sample_bundle());
        assert_eq!(signed.issuer.as_deref(), Some("agent-mesh-test"));
        assert_eq!(signed.key_id.as_deref(), Some("k-2026-04"));
    }

    #[test]
    fn signed_bundle_round_trips_via_serde() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let signed = signer.sign(sample_bundle());
        let v = serde_json::to_value(&signed).unwrap();
        let back: SignedEvidenceBundle = serde_json::from_value(v).unwrap();
        assert_eq!(signed, back);
    }

    #[test]
    fn hex_decode_failure_does_not_panic() {
        let signer = HmacEvidenceSigner::new(b"key-A");
        let verifier = HmacEvidenceVerifier::new(b"key-A".to_vec());
        let mut signed = signer.sign(sample_bundle());
        signed.signature = "not-hex-zzz!".to_string();
        assert!(!verifier.verify(&signed));
    }
}
