//! Delegation tokens for binding user intent to an agent session.
//!
//! A [`DelegationToken`] is a small, content-bound credential that
//! says one principal delegated a bounded set of actions to one
//! agent for one audience and session until a specific expiry time.
//! v0 uses HMAC-SHA256 so the proxy and policy layer can fail
//! closed before richer OAuth or JWT-based profiles land.
//!
//! Mirrors `tessera.delegation` in the Python reference. The wire
//! format (canonical JSON of the same fields, hex HMAC-SHA256
//! signature) is byte-for-byte interoperable with Python; pinned by
//! `tests/python_delegation_interop.rs`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use tessera_audit::canonical_json;

type HmacSha256 = Hmac<Sha256>;

/// A signed delegation from one principal to one agent.
///
/// The signature covers the delegating subject, delegated agent,
/// target audience, authorized actions, constraints, session
/// identifier, and expiry. Verification also enforces expiry and,
/// when supplied, the expected audience.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegationToken {
    pub subject: String,
    pub delegate: String,
    pub audience: String,
    pub authorized_actions: Vec<String>,
    /// Free-form constraints. Keys ordered lexicographically inside
    /// the canonical bytes (BTreeMap-backed `Value::Object`).
    pub constraints: Value,
    pub session_id: String,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl DelegationToken {
    pub fn new(
        subject: impl Into<String>,
        delegate: impl Into<String>,
        audience: impl Into<String>,
        authorized_actions: Vec<String>,
        constraints: Value,
        session_id: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            subject: subject.into(),
            delegate: delegate.into(),
            audience: audience.into(),
            authorized_actions,
            constraints,
            session_id: session_id.into(),
            expires_at,
            signature: String::new(),
        }
    }

    /// Deterministic bytes covered by [`signature`]. Matches Python's
    /// `_canonical_json` output: sorted keys, no whitespace,
    /// ISO-8601 UTC timestamp, sorted authorized_actions array.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_actions = self.authorized_actions.clone();
        sorted_actions.sort();
        let payload = json!({
            "subject": self.subject,
            "delegate": self.delegate,
            "audience": self.audience,
            "authorized_actions": sorted_actions,
            "constraints": self.constraints,
            "session_id": self.session_id,
            // Python uses isoformat(); chrono's to_rfc3339() matches the
            // shape "2026-04-23T00:00:00+00:00" when the time has UTC tz.
            "expires_at": self.expires_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true).replace('Z', "+00:00"),
        });
        canonical_json(&payload).into_bytes()
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Sign a delegation token and return the signed copy.
pub fn sign_delegation(mut token: DelegationToken, key: &[u8]) -> DelegationToken {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&token.canonical_bytes());
    token.signature = hex::encode(mac.finalize().into_bytes());
    token
}

/// Verify a token. Returns `true` only for a valid, unexpired token
/// with a matching audience (when an audience is supplied). Fails
/// closed for missing signatures, wrong keys, expired tokens,
/// tampered fields, or audience mismatches.
pub fn verify_delegation(
    token: &DelegationToken,
    key: &[u8],
    audience: Option<&str>,
    now: DateTime<Utc>,
) -> bool {
    if token.signature.is_empty() {
        return false;
    }
    if token.is_expired(now) {
        return false;
    }
    if let Some(expected_audience) = audience {
        if token.audience != expected_audience {
            return false;
        }
    }
    let signature_bytes = match hex::decode(&token.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&token.canonical_bytes());
    mac.verify_slice(&signature_bytes).is_ok()
}

/// Raised by [`narrow_delegation`] when a child attempts to widen
/// the parent's scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationNarrowingViolation(pub String);

impl std::fmt::Display for DelegationNarrowingViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "delegation narrowing violation: {}", self.0)
    }
}

impl std::error::Error for DelegationNarrowingViolation {}

/// Create a child delegation that narrows the parent's scope.
///
/// Enforces monotonic narrowing:
/// - Child `authorized_actions` must be a subset of parent's.
/// - Child `max_cost_usd` constraint (if set) must not exceed parent's.
/// - Child `expires_at` must not be later than parent's.
/// - Parent's `read_only` constraint is sticky and propagates.
///
/// Returns an unsigned child token. Sign with [`sign_delegation`].
pub fn narrow_delegation(
    parent: &DelegationToken,
    delegate: impl Into<String>,
    authorized_actions: Option<Vec<String>>,
    constraints: Option<Value>,
    expires_at: Option<DateTime<Utc>>,
    session_id: impl Into<String>,
) -> Result<DelegationToken, DelegationNarrowingViolation> {
    let mut child_actions =
        authorized_actions.unwrap_or_else(|| parent.authorized_actions.clone());
    let mut child_constraints: BTreeMap<String, Value> = match constraints {
        Some(Value::Object(map)) => map.into_iter().collect(),
        Some(_) => {
            return Err(DelegationNarrowingViolation(
                "constraints must be a JSON object".into(),
            ))
        }
        None => match &parent.constraints {
            Value::Object(map) => map.clone().into_iter().collect(),
            _ => BTreeMap::new(),
        },
    };
    let child_expires = expires_at.unwrap_or(parent.expires_at);

    // Subset check on actions.
    if !parent.authorized_actions.is_empty() {
        for a in &child_actions {
            if !parent.authorized_actions.contains(a) {
                return Err(DelegationNarrowingViolation(format!(
                    "child action {a:?} not in parent's authorized_actions"
                )));
            }
        }
    }

    // Expiry must not extend parent's.
    if child_expires > parent.expires_at {
        return Err(DelegationNarrowingViolation(
            "child expires_at cannot be later than parent's".into(),
        ));
    }

    // max_cost_usd ceiling.
    let parent_cost = parent
        .constraints
        .get("max_cost_usd")
        .and_then(|v| v.as_f64());
    let child_cost = child_constraints.get("max_cost_usd").and_then(|v| v.as_f64());
    if let (Some(pc), Some(cc)) = (parent_cost, child_cost) {
        if cc > pc {
            return Err(DelegationNarrowingViolation(format!(
                "child max_cost_usd ({cc}) exceeds parent's ({pc})"
            )));
        }
    }

    // read_only is sticky: if parent has it set, the child inherits it.
    if parent
        .constraints
        .get("read_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        child_constraints.insert("read_only".into(), Value::Bool(true));
    }

    child_actions.sort();
    let constraints_value = Value::Object(child_constraints.into_iter().collect());
    Ok(DelegationToken {
        subject: parent.subject.clone(),
        delegate: delegate.into(),
        audience: parent.audience.clone(),
        authorized_actions: child_actions,
        constraints: constraints_value,
        session_id: session_id.into(),
        expires_at: child_expires,
        signature: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_token() -> DelegationToken {
        DelegationToken::new(
            "alice",
            "agent-A",
            "tessera-proxy",
            vec!["send_email".to_string(), "list_files".to_string()],
            json!({"max_cost_usd": 10.0}),
            "sess-1",
            Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
        )
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = b"k";
        let token = sign_delegation(fixed_token(), key);
        assert!(!token.signature.is_empty());
        assert!(verify_delegation(&token, key, None, Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()));
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let token = sign_delegation(fixed_token(), b"k1");
        assert!(!verify_delegation(&token, b"k2", None, Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()));
    }

    #[test]
    fn verify_fails_when_expired() {
        let token = sign_delegation(fixed_token(), b"k");
        // 2031 is past the 2030 expiry.
        let now = Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap();
        assert!(!verify_delegation(&token, b"k", None, now));
    }

    #[test]
    fn verify_fails_with_audience_mismatch() {
        let token = sign_delegation(fixed_token(), b"k");
        assert!(!verify_delegation(
            &token,
            b"k",
            Some("other-aud"),
            Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()
        ));
    }

    #[test]
    fn verify_fails_when_unsigned() {
        let token = fixed_token();
        assert!(!verify_delegation(&token, b"k", None, Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()));
    }

    #[test]
    fn verify_fails_when_field_tampered() {
        let mut token = sign_delegation(fixed_token(), b"k");
        token.subject = "bob".to_string();
        assert!(!verify_delegation(&token, b"k", None, Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()));
    }

    #[test]
    fn canonical_action_ordering_independent_of_input() {
        let mut t1 = fixed_token();
        let mut t2 = fixed_token();
        t1.authorized_actions = vec!["a".into(), "b".into()];
        t2.authorized_actions = vec!["b".into(), "a".into()];
        assert_eq!(t1.canonical_bytes(), t2.canonical_bytes());
    }

    #[test]
    fn narrow_subset_of_actions_succeeds() {
        let parent = sign_delegation(fixed_token(), b"k");
        let child = narrow_delegation(
            &parent,
            "agent-B",
            Some(vec!["list_files".to_string()]),
            None,
            None,
            "sess-2",
        )
        .unwrap();
        assert_eq!(child.authorized_actions, vec!["list_files"]);
        assert_eq!(child.delegate, "agent-B");
    }

    #[test]
    fn narrow_action_outside_parent_fails() {
        let parent = sign_delegation(fixed_token(), b"k");
        let err = narrow_delegation(
            &parent,
            "agent-B",
            Some(vec!["wipe_disk".to_string()]),
            None,
            None,
            "sess-2",
        );
        assert!(err.is_err());
    }

    #[test]
    fn narrow_expires_later_fails() {
        let parent = sign_delegation(fixed_token(), b"k");
        let later = Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap();
        let err = narrow_delegation(
            &parent,
            "agent-B",
            None,
            None,
            Some(later),
            "sess-2",
        );
        assert!(err.is_err());
    }

    #[test]
    fn narrow_max_cost_above_parent_fails() {
        let parent = sign_delegation(fixed_token(), b"k");
        let err = narrow_delegation(
            &parent,
            "agent-B",
            None,
            Some(json!({"max_cost_usd": 100.0})),
            None,
            "sess-2",
        );
        assert!(err.is_err());
    }

    #[test]
    fn narrow_read_only_propagates() {
        let mut parent = fixed_token();
        parent.constraints = json!({"read_only": true});
        let parent = sign_delegation(parent, b"k");
        let child = narrow_delegation(
            &parent,
            "agent-B",
            None,
            Some(json!({})),
            None,
            "sess-2",
        )
        .unwrap();
        assert_eq!(child.constraints["read_only"], Value::Bool(true));
    }

    #[test]
    fn narrow_signs_independently() {
        let parent = sign_delegation(fixed_token(), b"k");
        let child = narrow_delegation(&parent, "agent-B", None, None, None, "sess-2").unwrap();
        assert!(child.signature.is_empty());
        let signed = sign_delegation(child, b"k");
        assert!(!signed.signature.is_empty());
        assert!(verify_delegation(&signed, b"k", None, Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()));
    }
}
