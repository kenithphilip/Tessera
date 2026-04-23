//! Encrypted in-memory session store for pending approvals.
//!
//! When a tool call requires human approval, the proxy stores the
//! pending [`Decision`] in a session keyed by a random id. The
//! approval webhook resolves the session; expired sessions
//! auto-resolve as DENY (fail closed).
//!
//! # Wire format vs Python
//!
//! The Python reference uses optional Fernet symmetric encryption.
//! Fernet's wire format is `0x80 || timestamp || iv || ciphertext ||
//! hmac`, using AES-128-CBC + HMAC-SHA256. The Rust port replaces
//! this with **AES-256-GCM with HKDF-SHA256 key derivation**: a
//! tighter primitive (one combined AEAD instead of CBC + MAC), and a
//! stronger 256-bit key. The on-disk shape is:
//!
//! ```text
//! version(1) || nonce(12) || ciphertext || tag(16)
//! ```
//!
//! `version` is `0x01` for this release. **Cross-runtime
//! compatibility is not supported in 0.8.0**: a session written by
//! Python's Fernet path cannot be read by Rust and vice versa.
//! Sessions are short-lived (default TTL 5 minutes), so the
//! migration story is: drain the queue at the cutover boundary, no
//! shared persistence required. Document this in the upgrade note.
//!
//! Mirrors `tessera.sessions` in the Python reference; the public
//! API surface matches except for the encryption-key bytes (AES-256
//! needs 32 bytes; HKDF derives the actual key from the supplied
//! master).

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use tessera_core::labels::TrustLevel;
use tessera_policy::policy::{Decision, DecisionKind};

const ENCRYPTED_VERSION: u8 = 0x01;
const NONCE_LEN: usize = 12;
const KDF_INFO: &[u8] = b"tessera-sessions-v1-aes256gcm";

/// One suspended tool-call decision awaiting human review.
#[derive(Clone, Debug)]
pub struct PendingApproval {
    pub session_id: String,
    pub tool: String,
    pub principal: String,
    pub decision: Decision,
    pub context_summary: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl PendingApproval {
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    fn to_serializable(&self) -> SerializedApproval {
        SerializedApproval {
            session_id: self.session_id.clone(),
            tool: self.tool.clone(),
            principal: self.principal.clone(),
            decision: SerializedDecision {
                kind: match self.decision.kind {
                    DecisionKind::Allow => "allow".to_string(),
                    DecisionKind::Deny => "deny".to_string(),
                    DecisionKind::RequireApproval => "require_approval".to_string(),
                },
                reason: self.decision.reason.clone(),
                tool: self.decision.tool.clone(),
                required_trust: self.decision.required_trust.as_int(),
                observed_trust: self.decision.observed_trust.as_int(),
            },
            context_summary: self.context_summary.clone(),
            created_at: self.created_at.to_rfc3339(),
            expires_at: self.expires_at.to_rfc3339(),
        }
    }

    fn from_serializable(s: SerializedApproval) -> Result<Self, String> {
        let kind = match s.decision.kind.as_str() {
            "allow" => DecisionKind::Allow,
            "deny" => DecisionKind::Deny,
            "require_approval" => DecisionKind::RequireApproval,
            other => return Err(format!("unknown decision kind: {other}")),
        };
        let required = TrustLevel::from_int(s.decision.required_trust)
            .ok_or_else(|| format!("bad required_trust: {}", s.decision.required_trust))?;
        let observed = TrustLevel::from_int(s.decision.observed_trust)
            .ok_or_else(|| format!("bad observed_trust: {}", s.decision.observed_trust))?;
        let decision = Decision {
            kind,
            reason: s.decision.reason,
            tool: s.decision.tool,
            required_trust: required,
            observed_trust: observed,
        };
        let created_at = DateTime::parse_from_rfc3339(&s.created_at)
            .map_err(|e| format!("bad created_at: {e}"))?
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339(&s.expires_at)
            .map_err(|e| format!("bad expires_at: {e}"))?
            .with_timezone(&Utc);
        Ok(Self {
            session_id: s.session_id,
            tool: s.tool,
            principal: s.principal,
            decision,
            context_summary: s.context_summary,
            created_at,
            expires_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct SerializedApproval {
    session_id: String,
    tool: String,
    principal: String,
    decision: SerializedDecision,
    context_summary: String,
    created_at: String,
    expires_at: String,
}

#[derive(Serialize, Deserialize)]
struct SerializedDecision {
    kind: String,
    reason: String,
    tool: String,
    required_trust: i64,
    observed_trust: i64,
}

/// Reason why a session resolution failed. Used to drive
/// observability without leaking session ids in error messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Expired,
}

/// Thread-safe session store. Optionally encrypts session payloads
/// at rest with AES-256-GCM.
pub struct SessionStore {
    ttl: Duration,
    sessions: Mutex<HashMap<String, Vec<u8>>>,
    cipher: Option<Aes256Gcm>,
}

impl SessionStore {
    /// Build a plaintext store. `ttl` defaults to 5 minutes when
    /// `Duration::zero()` is passed.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl: if ttl.is_zero() {
                Duration::minutes(5)
            } else {
                ttl
            },
            sessions: Mutex::new(HashMap::new()),
            cipher: None,
        }
    }

    /// Build an encrypted store. The supplied master key is run
    /// through HKDF-SHA256 to derive the AES-256 key.
    /// Encryption material on disk: `version(1) || nonce(12) ||
    /// ciphertext || tag(16)`. Cross-runtime compatibility with
    /// Python Fernet is NOT supported (see module docstring).
    pub fn with_encryption(ttl: Duration, master_key: &[u8]) -> Self {
        let mut derived = [0u8; 32];
        // HKDF-SHA256 with no salt and the static info string.
        Hkdf::<Sha256>::new(None, master_key)
            .expand(KDF_INFO, &mut derived)
            .expect("AES-256 derived key length is fixed");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
        Self {
            ttl: if ttl.is_zero() {
                Duration::minutes(5)
            } else {
                ttl
            },
            sessions: Mutex::new(HashMap::new()),
            cipher: Some(cipher),
        }
    }

    /// Default TTL used when constructed with `Duration::zero()`.
    pub fn default_ttl() -> Duration {
        Duration::minutes(5)
    }

    fn serialize(&self, approval: &PendingApproval) -> Vec<u8> {
        let json = serde_json::to_vec(&approval.to_serializable())
            .expect("PendingApproval serializes");
        match &self.cipher {
            Some(cipher) => self.encrypt(cipher, &json),
            None => json,
        }
    }

    fn deserialize(&self, raw: &[u8]) -> Result<PendingApproval, String> {
        let plain = match &self.cipher {
            Some(cipher) => self.decrypt(cipher, raw)?,
            None => raw.to_vec(),
        };
        let s: SerializedApproval = serde_json::from_slice(&plain)
            .map_err(|e| format!("malformed session payload: {e}"))?;
        PendingApproval::from_serializable(s)
    }

    fn encrypt(&self, cipher: &Aes256Gcm, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("AES-GCM encryption never fails for valid keys");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(ENCRYPTED_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn decrypt(&self, cipher: &Aes256Gcm, raw: &[u8]) -> Result<Vec<u8>, String> {
        if raw.len() < 1 + NONCE_LEN {
            return Err("ciphertext too short".to_string());
        }
        if raw[0] != ENCRYPTED_VERSION {
            return Err(format!("unknown session payload version: {:#x}", raw[0]));
        }
        let nonce = &raw[1..1 + NONCE_LEN];
        let ciphertext = &raw[1 + NONCE_LEN..];
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| "session payload decryption failed".to_string())
    }

    /// Store a pending approval. Returns the session id (a copy of
    /// `approval.session_id` for ergonomics).
    pub fn store(&self, approval: PendingApproval) -> String {
        let session_id = approval.session_id.clone();
        let raw = self.serialize(&approval);
        self.sessions.lock().insert(session_id.clone(), raw);
        session_id
    }

    /// Retrieve a session if it exists, has not expired, and decrypts
    /// successfully. Returns `None` for any failure (the caller
    /// cannot distinguish among them by design: avoids leaking
    /// session-existence to webhook callers).
    pub fn retrieve(&self, session_id: &str) -> Option<PendingApproval> {
        let raw = self.sessions.lock().get(session_id).cloned()?;
        let approval = self.deserialize(&raw).ok()?;
        if approval.is_expired() {
            return None;
        }
        Some(approval)
    }

    /// Resolve a pending approval and return the final decision. The
    /// session is removed from the store regardless of outcome.
    pub fn resolve(
        &self,
        session_id: &str,
        approved: bool,
        approver: &str,
        reason: &str,
    ) -> Result<Decision, ResolveError> {
        let raw = self.sessions.lock().remove(session_id);
        let raw = raw.ok_or(ResolveError::NotFound)?;
        let approval = self
            .deserialize(&raw)
            .map_err(|_| ResolveError::Expired)?;
        if approval.is_expired() {
            return Err(ResolveError::Expired);
        }
        let kind = if approved {
            DecisionKind::Allow
        } else {
            DecisionKind::Deny
        };
        let resolved_reason = if approved {
            format!("approved by {approver}: {reason}")
        } else {
            format!("denied by {approver}: {reason}")
        };
        Ok(Decision {
            kind,
            reason: resolved_reason,
            tool: approval.tool,
            required_trust: approval.decision.required_trust,
            observed_trust: approval.decision.observed_trust,
        })
    }

    /// Remove every expired session in one pass. Returns the count.
    pub fn expire_stale(&self) -> usize {
        let now = Utc::now();
        let mut expired: Vec<String> = Vec::new();
        let mut g = self.sessions.lock();
        for (sid, raw) in g.iter() {
            if let Ok(approval) = self.deserialize(raw) {
                if now >= approval.expires_at {
                    expired.push(sid.clone());
                }
            }
        }
        for sid in &expired {
            g.remove(sid);
        }
        expired.len()
    }

    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Generate a cryptographically random session identifier (43 chars
/// of urlsafe base64). Mirrors Python `secrets.token_urlsafe(32)`.
pub fn make_session_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64_urlsafe_no_pad(&bytes)
}

fn base64_urlsafe_no_pad(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_decision() -> Decision {
        Decision {
            kind: DecisionKind::Deny,
            reason: "needs human approval".into(),
            tool: "send_email".into(),
            required_trust: TrustLevel::User,
            observed_trust: TrustLevel::Tool,
        }
    }

    fn approval(ttl: Duration) -> PendingApproval {
        let now = Utc::now();
        PendingApproval {
            session_id: make_session_id(),
            tool: "send_email".into(),
            principal: "alice".into(),
            decision: fixed_decision(),
            context_summary: "alice asked to send invoice to bob".into(),
            created_at: now,
            expires_at: now + ttl,
        }
    }

    #[test]
    fn store_then_retrieve_round_trip() {
        let store = SessionStore::new(Duration::minutes(5));
        let pending = approval(Duration::minutes(5));
        let sid = store.store(pending.clone());
        let r = store.retrieve(&sid).unwrap();
        assert_eq!(r.tool, "send_email");
        assert_eq!(r.principal, "alice");
        assert_eq!(r.decision.required_trust, TrustLevel::User);
    }

    #[test]
    fn retrieve_returns_none_for_unknown_id() {
        let store = SessionStore::new(Duration::minutes(5));
        assert!(store.retrieve("not-a-session").is_none());
    }

    #[test]
    fn retrieve_returns_none_for_expired() {
        let store = SessionStore::new(Duration::minutes(5));
        let mut p = approval(Duration::minutes(5));
        p.expires_at = Utc::now() - Duration::seconds(1);
        let sid = store.store(p);
        assert!(store.retrieve(&sid).is_none());
    }

    #[test]
    fn resolve_approved_returns_allow_decision() {
        let store = SessionStore::new(Duration::minutes(5));
        let p = approval(Duration::minutes(5));
        let sid = store.store(p);
        let d = store.resolve(&sid, true, "carol", "looks legit").unwrap();
        assert_eq!(d.kind, DecisionKind::Allow);
        assert!(d.reason.contains("approved by carol"));
    }

    #[test]
    fn resolve_rejected_returns_deny_decision() {
        let store = SessionStore::new(Duration::minutes(5));
        let p = approval(Duration::minutes(5));
        let sid = store.store(p);
        let d = store.resolve(&sid, false, "carol", "phishing").unwrap();
        assert_eq!(d.kind, DecisionKind::Deny);
        assert!(d.reason.contains("denied by carol"));
    }

    #[test]
    fn resolve_unknown_session_returns_not_found() {
        let store = SessionStore::new(Duration::minutes(5));
        let r = store.resolve("missing", true, "carol", "");
        assert_eq!(r.unwrap_err(), ResolveError::NotFound);
    }

    #[test]
    fn resolve_expired_session_returns_expired() {
        let store = SessionStore::new(Duration::minutes(5));
        let mut p = approval(Duration::minutes(5));
        p.expires_at = Utc::now() - Duration::seconds(1);
        let sid = store.store(p);
        let r = store.resolve(&sid, true, "carol", "");
        assert_eq!(r.unwrap_err(), ResolveError::Expired);
    }

    #[test]
    fn resolve_consumes_session() {
        let store = SessionStore::new(Duration::minutes(5));
        let p = approval(Duration::minutes(5));
        let sid = store.store(p);
        let _ = store.resolve(&sid, true, "carol", "ok");
        assert!(store.retrieve(&sid).is_none());
    }

    #[test]
    fn expire_stale_drops_expired_only() {
        let store = SessionStore::new(Duration::minutes(5));
        let live = approval(Duration::minutes(5));
        let mut dead = approval(Duration::minutes(5));
        dead.expires_at = Utc::now() - Duration::seconds(1);
        let _ = store.store(live);
        let _ = store.store(dead);
        let n = store.expire_stale();
        assert_eq!(n, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn make_session_id_returns_43_char_urlsafe_string() {
        let id = make_session_id();
        // 32 bytes -> 43 chars of urlsafe base64 (no padding).
        assert_eq!(id.len(), 43);
        // Ensure character set is urlsafe.
        for c in id.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_');
        }
    }

    #[test]
    fn encrypted_store_round_trips_through_aes_gcm() {
        let store = SessionStore::with_encryption(Duration::minutes(5), b"master-key-bytes");
        let p = approval(Duration::minutes(5));
        let sid = store.store(p.clone());
        let r = store.retrieve(&sid).unwrap();
        assert_eq!(r.session_id, p.session_id);
        assert_eq!(r.tool, p.tool);
    }

    #[test]
    fn encrypted_store_payload_is_not_plaintext_json() {
        let store = SessionStore::with_encryption(Duration::minutes(5), b"master-key");
        let p = approval(Duration::minutes(5));
        let _sid = store.store(p);
        // Inspect the raw bytes; they should NOT contain plaintext
        // field names from the SerializedApproval JSON.
        let g = store.sessions.lock();
        let raw = g.values().next().unwrap();
        let raw_str = String::from_utf8_lossy(raw);
        assert!(!raw_str.contains("session_id"));
        assert!(!raw_str.contains("send_email"));
        // First byte is the version sentinel.
        assert_eq!(raw[0], ENCRYPTED_VERSION);
    }

    #[test]
    fn encrypted_store_wrong_master_key_fails_decrypt() {
        let s_a = SessionStore::with_encryption(Duration::minutes(5), b"key-A");
        let s_b = SessionStore::with_encryption(Duration::minutes(5), b"key-B");
        let p = approval(Duration::minutes(5));
        let sid = s_a.store(p);
        // Steal the ciphertext from store A, plant it in store B.
        let raw = s_a.sessions.lock().get(&sid).cloned().unwrap();
        s_b.sessions.lock().insert(sid.clone(), raw);
        // Retrieve under the wrong key fails (silently returns None).
        assert!(s_b.retrieve(&sid).is_none());
    }

    #[test]
    fn encrypted_store_tampered_ciphertext_fails_decrypt() {
        let store = SessionStore::with_encryption(Duration::minutes(5), b"key-A");
        let p = approval(Duration::minutes(5));
        let sid = store.store(p);
        // Flip one byte of ciphertext.
        {
            let mut g = store.sessions.lock();
            let raw = g.get_mut(&sid).unwrap();
            let last = raw.len() - 1;
            raw[last] ^= 0xFF;
        }
        assert!(store.retrieve(&sid).is_none());
    }

    #[test]
    fn store_with_zero_ttl_uses_default() {
        let store = SessionStore::new(Duration::zero());
        assert_eq!(store.ttl(), Duration::minutes(5));
    }

    #[test]
    fn len_tracks_active_sessions() {
        let store = SessionStore::new(Duration::minutes(5));
        assert_eq!(store.len(), 0);
        for _ in 0..3 {
            let _ = store.store(approval(Duration::minutes(5)));
        }
        assert_eq!(store.len(), 3);
    }
}
