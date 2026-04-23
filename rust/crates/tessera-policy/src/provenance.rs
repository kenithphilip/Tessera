//! Signed prompt provenance primitives.
//!
//! Two content-bound metadata objects:
//!
//! - [`ContextSegmentEnvelope`]: signed metadata for one prompt segment
//! - [`PromptProvenanceManifest`]: signed ordered references for one prompt
//!
//! v0 uses HMAC-SHA256 so the primitives compose with Tessera's
//! existing symmetric trust-label path. The signature covers the
//! canonical-JSON serialization of every metadata field; content is
//! bound by SHA-256 digest so a caller cannot swap in different
//! content while keeping the same envelope.
//!
//! Mirrors `tessera.provenance` in the Python reference. The wire
//! format (canonical JSON keys + hex HMAC) is byte-for-byte
//! interoperable with Python; pinned by
//! `tests/python_provenance_interop.rs`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tessera_audit::canonical_json;
use tessera_core::labels::{Origin, TrustLevel};

type HmacSha256 = Hmac<Sha256>;

fn content_digest(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))
}

fn sign_payload(payload: &[u8], key: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn first_seen(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for v in values {
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    out
}

/// Signed provenance for one prompt segment.
///
/// Content is bound by [`content_sha256`]. Verification requires the
/// original content bytes so a caller cannot swap in a different
/// string while keeping the same envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSegmentEnvelope {
    pub schema_version: u32,
    pub segment_id: String,
    pub origin: Origin,
    pub issuer: String,
    pub principal: String,
    pub trust_level: TrustLevel,
    pub content_sha256: String,
    pub parent_ids: Vec<String>,
    pub delegating_user: Option<String>,
    pub sensitivity: Vec<String>,
    pub created_at: String,
    pub signature: String,
}

impl ContextSegmentEnvelope {
    /// Create and sign an envelope for raw content. `segment_id`
    /// defaults to a 32-char hex random when `None`.
    pub fn create(
        content: &str,
        origin: Origin,
        issuer: impl Into<String>,
        principal: impl Into<String>,
        trust_level: TrustLevel,
        key: &[u8],
        segment_id: Option<String>,
        parent_ids: Vec<String>,
        delegating_user: Option<String>,
        sensitivity: Vec<String>,
        created_at: String,
    ) -> Self {
        let envelope = Self {
            schema_version: 1,
            segment_id: segment_id.unwrap_or_else(random_segment_id),
            origin,
            issuer: issuer.into(),
            principal: principal.into(),
            trust_level,
            content_sha256: content_digest(content),
            parent_ids,
            delegating_user,
            sensitivity,
            created_at,
            signature: String::new(),
        };
        envelope.signed(key)
    }

    /// Canonical JSON of every field except `signature`. The
    /// signature covers exactly these bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = json!({
            "schema_version": self.schema_version,
            "segment_id": self.segment_id,
            "origin": origin_to_str(self.origin),
            "issuer": self.issuer,
            "principal": self.principal,
            "trust_level": trust_level_to_int(self.trust_level),
            "content_sha256": self.content_sha256,
            "parent_ids": self.parent_ids,
            "delegating_user": self.delegating_user,
            "sensitivity": self.sensitivity,
            "created_at": self.created_at,
        });
        canonical_json(&value).into_bytes()
    }

    /// Return a signed copy. Replaces any existing signature.
    pub fn signed(mut self, key: &[u8]) -> Self {
        self.signature = sign_payload(&self.canonical_bytes(), key);
        self
    }

    /// Verify the signature and the content binding against the
    /// original bytes. Constant-time HMAC comparison.
    pub fn verify(&self, content: &str, key: &[u8]) -> bool {
        if self.signature.is_empty() || self.content_sha256 != content_digest(content) {
            return false;
        }
        let signature_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&self.canonical_bytes());
        mac.verify_slice(&signature_bytes).is_ok()
    }
}

/// One ordered segment reference inside a provenance manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSegmentRef {
    pub segment_id: String,
    pub position: usize,
    pub content_sha256: String,
}

impl ManifestSegmentRef {
    pub fn from_envelope(envelope: &ContextSegmentEnvelope, position: usize) -> Self {
        Self {
            segment_id: envelope.segment_id.clone(),
            position,
            content_sha256: envelope.content_sha256.clone(),
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "segment_id": self.segment_id,
            "position": self.position,
            "content_sha256": self.content_sha256,
        })
    }
}

/// Signed ordered references for one assembled prompt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptProvenanceManifest {
    pub schema_version: u32,
    pub manifest_id: String,
    pub session_id: String,
    pub principal_set: Vec<String>,
    pub segments: Vec<ManifestSegmentRef>,
    pub assembled_by: String,
    pub assembled_at: String,
    pub signature: String,
}

impl PromptProvenanceManifest {
    /// Build and sign a manifest preserving the given segment order.
    /// `principal_set` defaults to the de-duplicated principals from
    /// the envelopes (in first-seen order, matching Python's
    /// `dict.fromkeys`).
    pub fn assemble(
        envelopes: &[ContextSegmentEnvelope],
        assembled_by: impl Into<String>,
        key: &[u8],
        session_id: Option<String>,
        manifest_id: Option<String>,
        principal_set: Option<Vec<String>>,
        assembled_at: String,
    ) -> Self {
        let segments: Vec<ManifestSegmentRef> = envelopes
            .iter()
            .enumerate()
            .map(|(i, e)| ManifestSegmentRef::from_envelope(e, i))
            .collect();
        let principals = principal_set.unwrap_or_else(|| {
            let raw: Vec<String> = envelopes.iter().map(|e| e.principal.clone()).collect();
            first_seen(&raw)
        });
        let manifest = Self {
            schema_version: 1,
            manifest_id: manifest_id.unwrap_or_else(random_segment_id),
            session_id: session_id.unwrap_or_else(random_segment_id),
            principal_set: principals,
            segments,
            assembled_by: assembled_by.into(),
            assembled_at,
            signature: String::new(),
        };
        manifest.signed(key)
    }

    /// Canonical JSON of every field except `signature`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = json!({
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "session_id": self.session_id,
            "principal_set": self.principal_set,
            "segments": self.segments.iter().map(|s| s.to_value()).collect::<Vec<_>>(),
            "assembled_by": self.assembled_by,
            "assembled_at": self.assembled_at,
        });
        canonical_json(&value).into_bytes()
    }

    /// Return a signed copy. Replaces any existing signature.
    pub fn signed(mut self, key: &[u8]) -> Self {
        self.signature = sign_payload(&self.canonical_bytes(), key);
        self
    }

    /// Verify the manifest signature and that the provided envelopes
    /// match the recorded order and content digests. Callers should
    /// verify each envelope's own signature separately.
    pub fn verify(&self, envelopes: &[ContextSegmentEnvelope], key: &[u8]) -> bool {
        if self.signature.is_empty() || envelopes.len() != self.segments.len() {
            return false;
        }
        let expected_refs: Vec<ManifestSegmentRef> = envelopes
            .iter()
            .enumerate()
            .map(|(i, e)| ManifestSegmentRef::from_envelope(e, i))
            .collect();
        if self.segments != expected_refs {
            return false;
        }
        let signature_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&self.canonical_bytes());
        mac.verify_slice(&signature_bytes).is_ok()
    }
}

fn origin_to_str(origin: Origin) -> &'static str {
    match origin {
        Origin::User => "user",
        Origin::System => "system",
        Origin::Tool => "tool",
        Origin::Memory => "memory",
        Origin::Web => "web",
    }
}

fn trust_level_to_int(level: TrustLevel) -> i64 {
    match level {
        TrustLevel::Untrusted => 0,
        TrustLevel::Tool => 50,
        TrustLevel::User => 100,
        TrustLevel::System => 200,
    }
}

fn random_segment_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_envelope(content: &str, key: &[u8]) -> ContextSegmentEnvelope {
        ContextSegmentEnvelope::create(
            content,
            Origin::User,
            "tessera-test",
            "alice",
            TrustLevel::User,
            key,
            Some("seg-fixed-id".to_string()),
            Vec::new(),
            None,
            Vec::new(),
            "2026-04-23T00:00:00+00:00".to_string(),
        )
    }

    #[test]
    fn envelope_signs_and_verifies() {
        let env = fixed_envelope("hello world", b"key-A");
        assert!(!env.signature.is_empty());
        assert!(env.verify("hello world", b"key-A"));
    }

    #[test]
    fn envelope_wrong_key_fails() {
        let env = fixed_envelope("hello world", b"key-A");
        assert!(!env.verify("hello world", b"key-B"));
    }

    #[test]
    fn envelope_wrong_content_fails() {
        let env = fixed_envelope("hello world", b"key-A");
        assert!(!env.verify("HELLO world", b"key-A"));
    }

    #[test]
    fn envelope_tampered_metadata_fails() {
        let mut env = fixed_envelope("hello world", b"key-A");
        env.principal = "bob".to_string();
        assert!(!env.verify("hello world", b"key-A"));
    }

    #[test]
    fn envelope_canonical_bytes_are_deterministic() {
        let a = fixed_envelope("hello", b"k");
        let b = fixed_envelope("hello", b"k");
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn envelope_content_digest_is_sha256_hex() {
        let env = fixed_envelope("hello world", b"k");
        // Independently computed: sha256("hello world") = b94d27b9...
        assert_eq!(
            env.content_sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn envelope_serializes_origin_as_string() {
        let env = fixed_envelope("hi", b"k");
        let s = String::from_utf8(env.canonical_bytes()).unwrap();
        assert!(s.contains("\"origin\":\"user\""));
    }

    #[test]
    fn manifest_assembles_and_verifies() {
        let key = b"manifest-key";
        let env_a = fixed_envelope("first", key);
        let env_b = fixed_envelope("second", key);
        let manifest = PromptProvenanceManifest::assemble(
            &[env_a.clone(), env_b.clone()],
            "tessera-proxy",
            key,
            Some("session-1".to_string()),
            Some("manifest-1".to_string()),
            None,
            "2026-04-23T00:00:00+00:00".to_string(),
        );
        assert!(!manifest.signature.is_empty());
        assert!(manifest.verify(&[env_a, env_b], key));
    }

    #[test]
    fn manifest_wrong_envelope_order_fails() {
        let key = b"manifest-key";
        let env_a = ContextSegmentEnvelope::create(
            "a", Origin::User, "iss", "alice", TrustLevel::User, key,
            Some("a".into()), Vec::new(), None, Vec::new(),
            "2026-04-23T00:00:00+00:00".into(),
        );
        let env_b = ContextSegmentEnvelope::create(
            "b", Origin::User, "iss", "bob", TrustLevel::User, key,
            Some("b".into()), Vec::new(), None, Vec::new(),
            "2026-04-23T00:00:00+00:00".into(),
        );
        let manifest = PromptProvenanceManifest::assemble(
            &[env_a.clone(), env_b.clone()],
            "tessera-proxy",
            key,
            Some("s".into()),
            Some("m".into()),
            None,
            "2026-04-23T00:00:00+00:00".into(),
        );
        // Reverse order: should fail.
        assert!(!manifest.verify(&[env_b, env_a], key));
    }

    #[test]
    fn manifest_wrong_envelope_count_fails() {
        let key = b"manifest-key";
        let env_a = fixed_envelope("a", key);
        let env_b = fixed_envelope("b", key);
        let manifest = PromptProvenanceManifest::assemble(
            &[env_a.clone(), env_b.clone()],
            "tessera-proxy",
            key,
            Some("s".into()),
            Some("m".into()),
            None,
            "2026-04-23T00:00:00+00:00".into(),
        );
        assert!(!manifest.verify(&[env_a], key));
    }

    #[test]
    fn manifest_wrong_key_fails() {
        let key_a: &[u8] = b"key-A";
        let key_b: &[u8] = b"key-B";
        let env = fixed_envelope("x", key_a);
        let manifest = PromptProvenanceManifest::assemble(
            &[env.clone()],
            "tessera-proxy",
            key_a,
            Some("s".into()),
            Some("m".into()),
            None,
            "2026-04-23T00:00:00+00:00".into(),
        );
        assert!(!manifest.verify(&[env], key_b));
    }

    #[test]
    fn manifest_principal_set_is_first_seen_order() {
        let key = b"k";
        let env_alice_1 = ContextSegmentEnvelope::create(
            "x", Origin::User, "iss", "alice", TrustLevel::User, key,
            Some("1".into()), Vec::new(), None, Vec::new(),
            "2026-04-23T00:00:00+00:00".into(),
        );
        let env_bob = ContextSegmentEnvelope::create(
            "y", Origin::User, "iss", "bob", TrustLevel::User, key,
            Some("2".into()), Vec::new(), None, Vec::new(),
            "2026-04-23T00:00:00+00:00".into(),
        );
        let env_alice_2 = ContextSegmentEnvelope::create(
            "z", Origin::User, "iss", "alice", TrustLevel::User, key,
            Some("3".into()), Vec::new(), None, Vec::new(),
            "2026-04-23T00:00:00+00:00".into(),
        );
        let manifest = PromptProvenanceManifest::assemble(
            &[env_alice_1, env_bob, env_alice_2],
            "tessera-proxy",
            key,
            Some("s".into()),
            Some("m".into()),
            None,
            "2026-04-23T00:00:00+00:00".into(),
        );
        assert_eq!(manifest.principal_set, vec!["alice", "bob"]);
    }

    #[test]
    fn envelope_serde_round_trip() {
        let env = fixed_envelope("hi", b"k");
        let s = serde_json::to_string(&env).unwrap();
        let back: ContextSegmentEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn manifest_serde_round_trip() {
        let env = fixed_envelope("hi", b"k");
        let m = PromptProvenanceManifest::assemble(
            &[env.clone()],
            "tessera-proxy",
            b"k",
            Some("s".into()),
            Some("m".into()),
            None,
            "2026-04-23T00:00:00+00:00".into(),
        );
        let s = serde_json::to_string(&m).unwrap();
        let back: PromptProvenanceManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }
}
