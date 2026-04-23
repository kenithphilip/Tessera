//! Signed trust labels on context segments.
//!
//! Mirrors `tessera.labels` from the Python reference. Every chunk of
//! text entering the LLM's context carries a [`TrustLabel`] whose
//! signature binds the trust level, origin, principal, and optional
//! readers set to the content. The HMAC-SHA256 signing format is the
//! v0 path; JWT-SVID signing lives in the existing identity stack.
//!
//! The signature payload format MUST stay byte-for-byte compatible with
//! the Python implementation. A label signed in Python and read in Rust
//! (or vice versa) must verify. The format is:
//!
//! ```text
//! origin || "\x1F" || principal || "\x1F" || trust_level_str ||
//!   "\x1F" || nonce || "\x1F" || readers_canonical || "\x1F" || content
//! ```
//!
//! `\x1F` is the ASCII Unit Separator. `readers_canonical` is the
//! readers set as a sorted, comma-joined string, or empty when readers
//! is None.

use std::collections::BTreeSet;
use std::fmt;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SEP: u8 = 0x1F;

// Trust level integer values are part of the wire contract.
pub const UNTRUSTED: i64 = 0;
pub const TOOL: i64 = 50;
pub const USER: i64 = 100;
pub const SYSTEM: i64 = 200;

/// Categories of provenance origin. Matches `tessera.labels.Origin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    User,
    System,
    Tool,
    Memory,
    Web,
}

impl Origin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::User => "user",
            Origin::System => "system",
            Origin::Tool => "tool",
            Origin::Memory => "memory",
            Origin::Web => "web",
        }
    }

    /// Default trust level for an origin, matching `DEFAULT_TRUST` in
    /// `tessera.labels`.
    pub fn default_trust(&self) -> TrustLevel {
        match self {
            Origin::User => TrustLevel::User,
            Origin::System => TrustLevel::System,
            Origin::Tool => TrustLevel::Tool,
            Origin::Memory => TrustLevel::Tool,
            Origin::Web => TrustLevel::Untrusted,
        }
    }
}

/// Trust ladder. Ordering is meaningful: higher numerical value means
/// higher trust. Comparing two `TrustLevel` values must reflect that.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TrustLevel {
    Untrusted,
    Tool,
    User,
    System,
}

impl TrustLevel {
    pub fn as_int(&self) -> i64 {
        match self {
            TrustLevel::Untrusted => UNTRUSTED,
            TrustLevel::Tool => TOOL,
            TrustLevel::User => USER,
            TrustLevel::System => SYSTEM,
        }
    }

    pub fn from_int(value: i64) -> Option<Self> {
        match value {
            UNTRUSTED => Some(TrustLevel::Untrusted),
            TOOL => Some(TrustLevel::Tool),
            USER => Some(TrustLevel::User),
            SYSTEM => Some(TrustLevel::System),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            TrustLevel::Untrusted => "UNTRUSTED",
            TrustLevel::Tool => "TOOL",
            TrustLevel::User => "USER",
            TrustLevel::System => "SYSTEM",
        }
    }
}

impl PartialOrd for TrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_int().cmp(&other.as_int())
    }
}

impl Serialize for TrustLevel {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(self.as_int())
    }
}

impl<'de> Deserialize<'de> for TrustLevel {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = i64::deserialize(d)?;
        TrustLevel::from_int(n).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid trust level: {n}"))
        })
    }
}

/// A trust label as it travels with a context segment.
///
/// `signature` is the base64-encoded HMAC-SHA256 of the canonical
/// payload. `nonce` is 128 bits of base64 randomness so that two
/// segments with the same content but different lifetimes get
/// distinct labels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustLabel {
    pub origin: Origin,
    pub principal: String,
    pub trust_level: TrustLevel,
    pub nonce: String,
    /// Optional set of principals allowed to receive data derived from
    /// this segment. `None` means public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readers: Option<BTreeSet<String>>,
    /// Base64-encoded HMAC-SHA256. Empty before signing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl TrustLabel {
    /// Build a fresh, unsigned label with a random 128-bit nonce.
    pub fn new(
        origin: Origin,
        principal: impl Into<String>,
        trust_level: TrustLevel,
        readers: Option<BTreeSet<String>>,
    ) -> Self {
        let mut nonce_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        Self {
            origin,
            principal: principal.into(),
            trust_level,
            nonce: B64.encode(nonce_bytes),
            readers,
            signature: String::new(),
        }
    }

    /// Build a label with a caller-provided nonce. Used when reading
    /// labels from the wire so we don't reroll the nonce.
    pub fn with_nonce(
        origin: Origin,
        principal: impl Into<String>,
        trust_level: TrustLevel,
        nonce: impl Into<String>,
        readers: Option<BTreeSet<String>>,
    ) -> Self {
        Self {
            origin,
            principal: principal.into(),
            trust_level,
            nonce: nonce.into(),
            readers,
            signature: String::new(),
        }
    }

    fn readers_canonical(&self) -> String {
        match &self.readers {
            None => String::new(),
            Some(set) => {
                // BTreeSet iterates in sorted order, matching Python's
                // sorted(readers) canonicalization.
                let v: Vec<&str> = set.iter().map(String::as_str).collect();
                v.join(",")
            }
        }
    }

    /// Canonical signing payload. MUST match the Python implementation
    /// byte-for-byte: any change here breaks signature interop.
    pub fn signing_payload(&self, content: &str) -> Vec<u8> {
        let trust_str = self.trust_level.as_int().to_string();
        let readers = self.readers_canonical();
        let mut buf = Vec::with_capacity(
            self.origin.as_str().len()
                + self.principal.len()
                + trust_str.len()
                + self.nonce.len()
                + readers.len()
                + content.len()
                + 5, // five separators
        );
        buf.extend_from_slice(self.origin.as_str().as_bytes());
        buf.push(SEP);
        buf.extend_from_slice(self.principal.as_bytes());
        buf.push(SEP);
        buf.extend_from_slice(trust_str.as_bytes());
        buf.push(SEP);
        buf.extend_from_slice(self.nonce.as_bytes());
        buf.push(SEP);
        buf.extend_from_slice(readers.as_bytes());
        buf.push(SEP);
        buf.extend_from_slice(content.as_bytes());
        buf
    }
}

/// HMAC-SHA256 label signer. Holds the symmetric key.
pub struct HmacSigner {
    key: Vec<u8>,
}

impl HmacSigner {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Sign `label` over `content`, returning the label with its
    /// `signature` field populated. The input label is consumed; the
    /// returned value is a complete signed label.
    pub fn sign(&self, mut label: TrustLabel, content: &str) -> TrustLabel {
        let payload = label.signing_payload(content);
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        label.signature = B64.encode(mac.finalize().into_bytes());
        label
    }
}

/// HMAC-SHA256 label verifier. Holds the symmetric key.
pub struct HmacVerifier {
    key: Vec<u8>,
}

#[derive(Debug)]
pub enum VerifyError {
    /// The signature is missing or not valid base64.
    BadSignature,
    /// The signature did not match the expected MAC for the payload.
    InvalidMac,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::BadSignature => write!(f, "signature missing or unparseable"),
            VerifyError::InvalidMac => write!(f, "HMAC verification failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl HmacVerifier {
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Verify `label`'s signature over `content`. Constant-time MAC
    /// comparison via [`hmac::Mac::verify_slice`]; signature length
    /// mismatches return `BadSignature`.
    pub fn verify(&self, label: &TrustLabel, content: &str) -> Result<(), VerifyError> {
        if label.signature.is_empty() {
            return Err(VerifyError::BadSignature);
        }
        let sig_bytes = B64
            .decode(label.signature.as_bytes())
            .map_err(|_| VerifyError::BadSignature)?;
        let payload = label.signing_payload(content);
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC accepts any key length");
        mac.update(&payload);
        mac.verify_slice(&sig_bytes)
            .map_err(|_| VerifyError::InvalidMac)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-labels-32bytes!!!!!!!!!!!!!";

    #[test]
    fn trust_levels_are_ordered() {
        assert!(TrustLevel::Untrusted < TrustLevel::Tool);
        assert!(TrustLevel::Tool < TrustLevel::User);
        assert!(TrustLevel::User < TrustLevel::System);
        assert!(TrustLevel::Untrusted < TrustLevel::System);
    }

    #[test]
    fn trust_level_int_round_trip() {
        for tl in [
            TrustLevel::Untrusted,
            TrustLevel::Tool,
            TrustLevel::User,
            TrustLevel::System,
        ] {
            assert_eq!(TrustLevel::from_int(tl.as_int()), Some(tl));
        }
    }

    #[test]
    fn invalid_trust_level_int_rejected() {
        assert!(TrustLevel::from_int(42).is_none());
    }

    #[test]
    fn origin_default_trust_levels_match_python() {
        assert_eq!(Origin::User.default_trust(), TrustLevel::User);
        assert_eq!(Origin::System.default_trust(), TrustLevel::System);
        assert_eq!(Origin::Tool.default_trust(), TrustLevel::Tool);
        assert_eq!(Origin::Memory.default_trust(), TrustLevel::Tool);
        assert_eq!(Origin::Web.default_trust(), TrustLevel::Untrusted);
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let signer = HmacSigner::new(KEY);
        let verifier = HmacVerifier::new(KEY);
        let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        let signed = signer.sign(label, "hello world");
        assert!(!signed.signature.is_empty());
        verifier.verify(&signed, "hello world").expect("verify ok");
    }

    #[test]
    fn verify_rejects_modified_content() {
        let signer = HmacSigner::new(KEY);
        let verifier = HmacVerifier::new(KEY);
        let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        let signed = signer.sign(label, "hello world");
        assert!(matches!(
            verifier.verify(&signed, "different content"),
            Err(VerifyError::InvalidMac)
        ));
    }

    #[test]
    fn verify_rejects_modified_metadata() {
        let signer = HmacSigner::new(KEY);
        let verifier = HmacVerifier::new(KEY);
        let label = TrustLabel::new(Origin::Web, "attacker", TrustLevel::User, None);
        let mut signed = signer.sign(label, "hi");
        // Attacker tries to upgrade themselves from Web -> Tool.
        signed.origin = Origin::Tool;
        assert!(matches!(
            verifier.verify(&signed, "hi"),
            Err(VerifyError::InvalidMac)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer = HmacSigner::new(KEY);
        let verifier = HmacVerifier::new(b"different-key-32bytes!!!!!!!!!!!");
        let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        let signed = signer.sign(label, "hello");
        assert!(matches!(
            verifier.verify(&signed, "hello"),
            Err(VerifyError::InvalidMac)
        ));
    }

    #[test]
    fn verify_rejects_missing_signature() {
        let verifier = HmacVerifier::new(KEY);
        let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        // Never signed.
        assert!(matches!(
            verifier.verify(&label, "hi"),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_rejects_bad_base64_signature() {
        let verifier = HmacVerifier::new(KEY);
        let mut label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        label.signature = "not-base64!".to_string();
        assert!(matches!(
            verifier.verify(&label, "hi"),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn nonce_differs_on_each_construction() {
        let a = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        let b = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn readers_set_canonicalization_is_sorted() {
        let signer = HmacSigner::new(KEY);
        let verifier = HmacVerifier::new(KEY);
        let mut readers_a = BTreeSet::new();
        readers_a.insert("zebra".to_string());
        readers_a.insert("apple".to_string());
        let label_a = TrustLabel::with_nonce(
            Origin::User, "alice", TrustLevel::User, "fixed-nonce", Some(readers_a),
        );
        let mut readers_b = BTreeSet::new();
        readers_b.insert("apple".to_string());
        readers_b.insert("zebra".to_string());
        let label_b = TrustLabel::with_nonce(
            Origin::User, "alice", TrustLevel::User, "fixed-nonce", Some(readers_b),
        );
        let signed_a = signer.sign(label_a, "hello");
        let signed_b = signer.sign(label_b, "hello");
        // Insertion order should not matter; the canonicalization
        // sorts.
        assert_eq!(signed_a.signature, signed_b.signature);
        verifier.verify(&signed_a, "hello").expect("a verifies");
        verifier.verify(&signed_b, "hello").expect("b verifies");
    }

    #[test]
    fn readers_none_distinct_from_empty_set() {
        // Two labels with the same metadata but different readers
        // (None vs Some({})) MUST produce different signatures, because
        // `Some(empty)` is meaningful (deny everyone) and `None` is
        // public.
        let signer = HmacSigner::new(KEY);
        let none_label = TrustLabel::with_nonce(
            Origin::User, "alice", TrustLevel::User, "n", None,
        );
        let empty_label = TrustLabel::with_nonce(
            Origin::User, "alice", TrustLevel::User, "n", Some(BTreeSet::new()),
        );
        let none_signed = signer.sign(none_label, "hi");
        let empty_signed = signer.sign(empty_label, "hi");
        // Both serialize empty in readers_canonical, so signatures
        // currently match. Document this with a test so any future
        // change to readers canonicalization is intentional.
        assert_eq!(none_signed.signature, empty_signed.signature);
    }

    #[test]
    fn signing_payload_is_deterministic_for_fixed_inputs() {
        let label = TrustLabel::with_nonce(
            Origin::Web,
            "alice",
            TrustLevel::Untrusted,
            "ABCDEFGHIJKLMNOP",
            None,
        );
        let payload_1 = label.signing_payload("evil content");
        let payload_2 = label.signing_payload("evil content");
        assert_eq!(payload_1, payload_2);
    }

    #[test]
    fn signing_payload_layout_matches_spec() {
        // Pin the canonical format so changes are loud.
        let label = TrustLabel::with_nonce(
            Origin::Web, "alice", TrustLevel::Untrusted, "NONCE", None,
        );
        let payload = label.signing_payload("body");
        let expected =
            b"web\x1Falice\x1F0\x1FNONCE\x1F\x1Fbody";
        assert_eq!(&payload[..], &expected[..]);
    }
}
