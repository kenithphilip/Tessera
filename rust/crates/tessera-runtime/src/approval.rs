//! Human-in-the-loop approval gate for tool calls.
//!
//! When a policy engine returns a REQUIRE_APPROVAL outcome, the caller
//! can use [`ApprovalGate`] to park the decision and wait for a human
//! to respond via an out-of-band callback. This module deliberately
//! avoids HTTP and process-specific I/O: the caller owns the webhook
//! transport and posts the resolved [`ApprovalDecision`] back via
//! [`ApprovalGate::resolve`].
//!
//! [`WebhookSigner`] provides HMAC-SHA256 request signing so the
//! receiving endpoint can verify the payload has not been tampered with
//! in transit.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::oneshot;

// ---- ApprovalRequest -------------------------------------------------------

/// Payload that describes a pending tool-call approval request.
///
/// Callers serialize this to JSON and POST it to their approval
/// webhook. The `request_id` ties the later [`ApprovalGate::resolve`]
/// call back to the suspended task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique id for this approval request. Must be echoed in the
    /// matching [`ApprovalDecision`].
    pub request_id: String,
    /// Name of the tool awaiting approval.
    pub tool: String,
    /// Principal who issued the original request.
    pub principal: String,
    /// Human-readable reason why approval is needed.
    pub reason: String,
    /// Brief summary of the context window at decision time.
    pub context_summary: String,
}

impl ApprovalRequest {
    /// Create a new request with a randomly generated `request_id`.
    pub fn new(
        tool: impl Into<String>,
        principal: impl Into<String>,
        reason: impl Into<String>,
        context_summary: impl Into<String>,
    ) -> Self {
        Self {
            request_id: new_request_id(),
            tool: tool.into(),
            principal: principal.into(),
            reason: reason.into(),
            context_summary: context_summary.into(),
        }
    }
}

// ---- ApprovalOutcome -------------------------------------------------------

/// The verdict carried in an [`ApprovalDecision`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// The human approved the tool call.
    Approved,
    /// The human (or policy) denied the tool call.
    Denied,
    /// No decision arrived before the timeout elapsed.
    Expired,
}

// ---- ApprovalDecision ------------------------------------------------------

/// Resolved verdict for one [`ApprovalRequest`].
///
/// The `request_id` must match the [`ApprovalRequest`] that was sent.
/// Mismatched ids are rejected by [`ApprovalGate::resolve`] with an
/// `Err`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Must match the `request_id` in the original [`ApprovalRequest`].
    pub request_id: String,
    /// Final verdict.
    pub outcome: ApprovalOutcome,
    /// Who or what resolved the decision (e.g. "jane.doe@example.com",
    /// "policy-auto-approve", "timeout").
    pub approver: String,
    /// Free-form reasoning recorded for the audit trail.
    pub reason: String,
}

impl ApprovalDecision {
    /// Convenience constructor for an approved decision.
    pub fn approved(
        request_id: impl Into<String>,
        approver: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            outcome: ApprovalOutcome::Approved,
            approver: approver.into(),
            reason: reason.into(),
        }
    }

    /// Convenience constructor for a denied decision.
    pub fn denied(
        request_id: impl Into<String>,
        approver: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            outcome: ApprovalOutcome::Denied,
            approver: approver.into(),
            reason: reason.into(),
        }
    }

    /// Convenience constructor for an expired decision.
    pub fn expired(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            outcome: ApprovalOutcome::Expired,
            approver: "timeout".to_string(),
            reason: "approval window elapsed with no response".to_string(),
        }
    }

    /// Returns true when the outcome is [`ApprovalOutcome::Approved`].
    pub fn is_approved(&self) -> bool {
        self.outcome == ApprovalOutcome::Approved
    }
}

// ---- GateError -------------------------------------------------------------

/// Error type returned by [`ApprovalGate::resolve`].
#[derive(Debug, PartialEq, Eq)]
pub enum GateError {
    /// No pending request exists with the given `request_id`.
    NotFound(String),
    /// A decision was already delivered for this `request_id`; the
    /// duplicate is discarded. This matches the Python semantics where
    /// subsequent resolution attempts after the first are no-ops.
    AlreadyResolved(String),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::NotFound(id) => write!(f, "no pending approval for request_id={id}"),
            GateError::AlreadyResolved(id) => {
                write!(f, "approval already resolved for request_id={id}")
            }
        }
    }
}

impl std::error::Error for GateError {}

// ---- ApprovalGate ----------------------------------------------------------

type Sender = oneshot::Sender<ApprovalDecision>;

#[derive(Default)]
struct GateInner {
    pending: HashMap<String, Sender>,
}

/// Async approval gate. Suspends the caller via a `tokio::sync::oneshot`
/// channel until a matching [`ApprovalDecision`] is delivered or the
/// configured timeout elapses.
///
/// One `ApprovalGate` is typically shared across the application as an
/// `Arc<ApprovalGate>`. The webhook handler calls [`ApprovalGate::resolve`]
/// on the shared instance; the tool-call path calls
/// [`ApprovalGate::wait`].
///
/// # Timeout semantics
///
/// When `timeout` elapses with no call to [`ApprovalGate::resolve`], the
/// pending entry is dropped and [`wait`] returns
/// `ApprovalDecision::expired(...)`. A subsequent
/// [`ApprovalGate::resolve`] call for the same `request_id` returns
/// [`GateError::NotFound`] (the receiver is gone).
///
/// # Multi-resolve semantics
///
/// Only the first call to [`ApprovalGate::resolve`] for a given
/// `request_id` succeeds. The pending slot is removed atomically, so
/// any concurrent second call receives [`GateError::NotFound`]. This
/// mirrors the Python behaviour where a second call is silently
/// dropped.
///
/// [`wait`]: ApprovalGate::wait
#[derive(Debug)]
pub struct ApprovalGate {
    timeout: Duration,
    inner: Arc<Mutex<GateInner>>,
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

impl ApprovalGate {
    /// Create a new gate with the given decision timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            inner: Arc::new(Mutex::new(GateInner::default())),
        }
    }

    /// Register a pending approval and block until a decision arrives
    /// or the timeout elapses.
    ///
    /// The `request_id` from `request` is the key used by
    /// [`ApprovalGate::resolve`].
    pub async fn wait(&self, request: &ApprovalRequest) -> ApprovalDecision {
        let (tx, rx) = oneshot::channel();
        {
            let mut g = self.inner.lock();
            g.pending.insert(request.request_id.clone(), tx);
        }

        let request_id = request.request_id.clone();
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(decision)) => decision,
            // oneshot sender dropped without sending: treat as expired.
            Ok(Err(_)) => ApprovalDecision::expired(&request_id),
            // tokio timeout elapsed.
            Err(_) => {
                // Remove the stale sender so resolve returns NotFound.
                self.inner.lock().pending.remove(&request_id);
                ApprovalDecision::expired(&request_id)
            }
        }
    }

    /// Deliver a decision for a pending approval.
    ///
    /// Returns `Ok(())` if the sender was found and the decision
    /// delivered. Returns `Err(GateError::NotFound)` when no pending
    /// entry exists for `request_id` (never registered, already
    /// expired, or already resolved).
    pub fn resolve(&self, decision: ApprovalDecision) -> Result<(), GateError> {
        let sender = self
            .inner
            .lock()
            .pending
            .remove(&decision.request_id)
            .ok_or_else(|| GateError::NotFound(decision.request_id.clone()))?;

        // send() fails only if the receiver has been dropped (timeout
        // path). That is a NotFound-equivalent situation.
        sender
            .send(decision.clone())
            .map_err(|_| GateError::NotFound(decision.request_id.clone()))
    }

    /// Return the number of approvals currently awaiting a decision.
    pub fn pending_count(&self) -> usize {
        self.inner.lock().pending.len()
    }
}

impl std::fmt::Debug for GateInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateInner")
            .field("pending_count", &self.pending.len())
            .finish()
    }
}

// ---- WebhookSigner ---------------------------------------------------------

/// HMAC-SHA256 request signer for approval webhook calls.
///
/// Computes `HMAC-SHA256(key, body)` and returns the hex-encoded
/// digest. The receiving endpoint should recompute the same value over
/// the raw POST body and compare with the `X-Tessera-Signature` header
/// (or equivalent) in constant time.
///
/// # Usage
///
/// ```rust
/// use tessera_runtime::approval::WebhookSigner;
///
/// let signer = WebhookSigner::new(b"my-secret");
/// let body = r#"{"request_id":"abc","tool":"deploy"}"#;
/// let sig = signer.sign(body.as_bytes());
/// assert_eq!(sig.len(), 64); // 32-byte digest as 64 hex chars
/// ```
#[derive(Clone)]
pub struct WebhookSigner {
    key: Vec<u8>,
}

impl WebhookSigner {
    /// Create a signer from a raw key.
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self {
            key: key.as_ref().to_vec(),
        }
    }

    /// Compute `HMAC-SHA256(key, body)` and return the lowercase hex string.
    pub fn sign(&self, body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts keys of any length");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify that `signature` matches the HMAC of `body`. Comparison
    /// is done byte-by-byte after hex decoding; callers who need
    /// constant-time comparison should use the `subtle` crate instead.
    pub fn verify(&self, body: &[u8], signature: &str) -> bool {
        let expected = self.sign(body);
        expected == signature
    }
}

impl std::fmt::Debug for WebhookSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSigner")
            .field("key_len", &self.key.len())
            .finish()
    }
}

// ---- helpers ---------------------------------------------------------------

/// Generate a random request id. Uses thread-local entropy; does not
/// require a CSPRNG or tokio runtime.
fn new_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Combine a timestamp and a small counter for ordering + uniqueness.
    // This is sufficient for test-and-reference use. Production deployments
    // should substitute a UUID crate.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{ts:016x}{n:08x}")
}

// ---- tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    fn req(tool: &str) -> ApprovalRequest {
        ApprovalRequest::new(tool, "alice", "tool requires human approval", "1 segment, min_trust=100")
    }

    // 1. ApprovalRequest serializes to JSON and round-trips.
    #[test]
    fn approval_request_round_trips_json() {
        let r = req("deploy");
        let json = serde_json::to_string(&r).unwrap();
        let back: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // 2. ApprovalDecision serializes and round-trips.
    #[test]
    fn approval_decision_round_trips_json() {
        let d = ApprovalDecision::approved("req-1", "jane", "looks good");
        let json = serde_json::to_string(&d).unwrap();
        let back: ApprovalDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // 3. is_approved returns true only for Approved outcome.
    #[test]
    fn is_approved_semantics() {
        assert!(ApprovalDecision::approved("r", "a", "ok").is_approved());
        assert!(!ApprovalDecision::denied("r", "b", "no").is_approved());
        assert!(!ApprovalDecision::expired("r").is_approved());
    }

    // 4. Expired decision carries expected metadata.
    #[test]
    fn expired_decision_metadata() {
        let d = ApprovalDecision::expired("r-42");
        assert_eq!(d.outcome, ApprovalOutcome::Expired);
        assert_eq!(d.approver, "timeout");
        assert!(!d.reason.is_empty());
    }

    // 5. Gate wait resolves to approved when resolve is called.
    #[tokio::test]
    async fn gate_resolves_approved() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_secs(5)));
        let r = req("deploy");
        let rid = r.request_id.clone();

        let gate2 = Arc::clone(&gate);
        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            gate2
                .resolve(ApprovalDecision::approved(&rid, "jane", "looks good"))
                .unwrap();
        });

        let decision = gate.wait(&r).await;
        assert!(decision.is_approved());
        assert_eq!(decision.approver, "jane");
    }

    // 6. Gate wait resolves to denied when resolve sends denied.
    #[tokio::test]
    async fn gate_resolves_denied() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_secs(5)));
        let r = req("deploy");
        let rid = r.request_id.clone();

        let gate2 = Arc::clone(&gate);
        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            gate2
                .resolve(ApprovalDecision::denied(&rid, "bob", "too risky"))
                .unwrap();
        });

        let decision = gate.wait(&r).await;
        assert!(!decision.is_approved());
        assert_eq!(decision.outcome, ApprovalOutcome::Denied);
        assert_eq!(decision.approver, "bob");
    }

    // 7. Gate returns expired decision when timeout elapses.
    #[tokio::test]
    async fn gate_expires_on_timeout() {
        let gate = ApprovalGate::new(Duration::from_millis(30));
        let r = req("deploy");
        let decision = gate.wait(&r).await;
        assert_eq!(decision.outcome, ApprovalOutcome::Expired);
        assert_eq!(decision.approver, "timeout");
    }

    // 8. resolve after timeout returns NotFound (sender is gone).
    #[tokio::test]
    async fn resolve_after_timeout_returns_not_found() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_millis(30)));
        let r = req("deploy");
        let rid = r.request_id.clone();

        // Wait out the timeout.
        gate.wait(&r).await;

        let err = gate
            .resolve(ApprovalDecision::approved(&rid, "late", "too late"))
            .unwrap_err();
        assert!(matches!(err, GateError::NotFound(_)));
    }

    // 9. Second resolve call returns NotFound (slot already consumed).
    #[tokio::test]
    async fn second_resolve_returns_not_found() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_secs(5)));
        let r = req("deploy");
        let rid = r.request_id.clone();

        let gate2 = Arc::clone(&gate);
        let rid2 = rid.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(10)).await;
            gate2
                .resolve(ApprovalDecision::approved(&rid2, "jane", "ok"))
                .unwrap();
        });

        gate.wait(&r).await;

        // Slot is consumed; second resolve must fail.
        let err = gate
            .resolve(ApprovalDecision::approved(&rid, "jane", "duplicate"))
            .unwrap_err();
        assert!(matches!(err, GateError::NotFound(_)));
    }

    // 10. pending_count reflects registered and resolved requests.
    #[tokio::test]
    async fn pending_count_tracks_state() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_secs(5)));
        assert_eq!(gate.pending_count(), 0);

        let r = req("deploy");
        let rid = r.request_id.clone();

        // Register without resolving yet.
        let gate2 = Arc::clone(&gate);
        let handle = tokio::spawn(async move { gate2.wait(&r).await });

        // Give the spawn time to register.
        sleep(Duration::from_millis(20)).await;
        assert_eq!(gate.pending_count(), 1);

        gate.resolve(ApprovalDecision::approved(&rid, "j", "ok"))
            .unwrap();
        let _ = handle.await.unwrap();
        assert_eq!(gate.pending_count(), 0);
    }

    // 11. resolve for unknown request_id returns NotFound.
    #[test]
    fn resolve_unknown_returns_not_found() {
        let gate = ApprovalGate::default();
        let err = gate
            .resolve(ApprovalDecision::approved("nonexistent", "x", "y"))
            .unwrap_err();
        assert!(matches!(err, GateError::NotFound(_)));
        // Verify the id is in the error message.
        assert!(err.to_string().contains("nonexistent"));
    }

    // 12. WebhookSigner produces consistent signature.
    #[test]
    fn webhook_signer_produces_hex_digest() {
        let signer = WebhookSigner::new(b"test-key");
        let body = b"{\"request_id\":\"abc\",\"tool\":\"deploy\"}";
        let sig = signer.sign(body);
        assert_eq!(sig.len(), 64, "HMAC-SHA256 is 32 bytes = 64 hex chars");
        // Deterministic: same inputs yield same output.
        assert_eq!(sig, signer.sign(body));
    }

    // 13. WebhookSigner.verify accepts matching signature.
    #[test]
    fn webhook_signer_verify_accepts_correct_signature() {
        let signer = WebhookSigner::new(b"secret");
        let body = b"hello world";
        let sig = signer.sign(body);
        assert!(signer.verify(body, &sig));
    }

    // 14. WebhookSigner.verify rejects tampered body.
    #[test]
    fn webhook_signer_verify_rejects_tampered_body() {
        let signer = WebhookSigner::new(b"secret");
        let sig = signer.sign(b"original");
        assert!(!signer.verify(b"tampered", &sig));
    }

    // 15. Different keys produce different signatures.
    #[test]
    fn different_keys_produce_different_signatures() {
        let s1 = WebhookSigner::new(b"key-one");
        let s2 = WebhookSigner::new(b"key-two");
        let body = b"same body";
        assert_ne!(s1.sign(body), s2.sign(body));
    }

    // 16. new_request_id produces unique ids across rapid calls.
    #[test]
    fn request_ids_are_unique() {
        let ids: Vec<String> = (0..50).map(|_| new_request_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 50);
    }

    // 17. Multiple concurrent waits on the same gate resolve independently.
    #[tokio::test]
    async fn concurrent_waits_resolve_independently() {
        let gate = Arc::new(ApprovalGate::new(Duration::from_secs(5)));

        let r1 = req("tool-a");
        let r2 = req("tool-b");
        let rid1 = r1.request_id.clone();
        let rid2 = r2.request_id.clone();

        let g1 = Arc::clone(&gate);
        let h1 = tokio::spawn(async move { g1.wait(&r1).await });

        let g2 = Arc::clone(&gate);
        let h2 = tokio::spawn(async move { g2.wait(&r2).await });

        sleep(Duration::from_millis(20)).await;

        gate.resolve(ApprovalDecision::approved(&rid1, "alice", "ok"))
            .unwrap();
        gate.resolve(ApprovalDecision::denied(&rid2, "bob", "no"))
            .unwrap();

        let d1 = h1.await.unwrap();
        let d2 = h2.await.unwrap();

        assert!(d1.is_approved());
        assert!(!d2.is_approved());
    }

    // 18. GateError Display message is human-readable.
    #[test]
    fn gate_error_display_is_readable() {
        let e1 = GateError::NotFound("req-xyz".to_string());
        assert!(e1.to_string().contains("req-xyz"));

        let e2 = GateError::AlreadyResolved("req-abc".to_string());
        assert!(e2.to_string().contains("req-abc"));
    }
}
