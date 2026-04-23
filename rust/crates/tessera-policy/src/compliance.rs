//! NIST SP 800-53, CWE, and OWASP Agentic AI mappings for SecurityEvents.
//!
//! Mirrors `tessera.compliance` in the Python reference. Lookup tables
//! key on the snake_case form of an event kind so this module stays
//! decoupled from any specific `EventKind` enum (the gateway crate has
//! its own; future crates can supply theirs). Callers pass the kind
//! as a `&str` (typically `serde::Serialize` of an `EventKind`).
//!
//! Source attribution: NIST control mappings derived from
//! Compliant-LLM (`strategy_mapping.yaml`). CWE assignments from
//! Superagent (`prompts/guard.py`). OWASP Agentic AI Top 10 taxonomy
//! covers ASI-01..ASI-10 (Agent Audit).

use std::collections::HashSet;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tessera_audit::canonical_json;

/// SHA-256 of zero bytes is not used; the Python reference uses
/// 64 ASCII zeros as the genesis "previous hash" so a fresh chain's
/// first entry has a well-known sentinel. We match that exactly so
/// hash-chain interop works byte-for-byte against the Python output.
pub const GENESIS_PREVIOUS_HASH: &str = concat!(
    "0000000000000000",
    "0000000000000000",
    "0000000000000000",
    "0000000000000000",
);

/// NIST SP 800-53 control IDs for a given event kind.
///
/// Returns an empty slice for unknown kinds so callers do not need to
/// special-case the absence of a mapping.
pub fn nist_controls(kind: &str) -> &'static [&'static str] {
    match kind {
        "policy_deny" => &["AC-4", "SI-10", "SC-7"],
        "worker_schema_violation" => &["SI-10", "SI-15"],
        "label_verify_failure" => &["IA-9", "SC-8"],
        "secret_redacted" => &["SC-28", "SI-12"],
        "identity_verify_failure" => &["IA-9", "IA-5"],
        "proof_verify_failure" => &["IA-9", "IA-5"],
        "provenance_verify_failure" => &["AU-10", "SC-8"],
        "delegation_verify_failure" => &["AC-4", "AC-6"],
        "human_approval_required" => &["AC-6", "AU-12"],
        "human_approval_resolved" => &["AC-6", "AU-12"],
        "session_expired" => &["AC-12"],
        "content_injection_detected" => &["SI-10", "SC-7"],
        "guardrail_decision" => &["SI-10", "SC-7"],
        _ => &[],
    }
}

/// CWE weakness IDs for a given event kind.
pub fn cwe_codes(kind: &str) -> &'static [&'static str] {
    match kind {
        "policy_deny" => &["CWE-20"],
        "worker_schema_violation" => &["CWE-20"],
        "label_verify_failure" => &["CWE-345"],
        "identity_verify_failure" => &["CWE-287"],
        "proof_verify_failure" => &["CWE-287"],
        "provenance_verify_failure" => &["CWE-345"],
        "delegation_verify_failure" => &["CWE-285"],
        "secret_redacted" => &["CWE-200"],
        "content_injection_detected" => &["CWE-77", "CWE-20"],
        "guardrail_decision" => &["CWE-77"],
        _ => &[],
    }
}

/// OWASP Agentic AI Top 10 (ASI-01..ASI-10) categories for a given event kind.
pub fn owasp_asi(kind: &str) -> &'static [&'static str] {
    match kind {
        "policy_deny" => &["ASI-01"],
        "worker_schema_violation" => &["ASI-01"],
        "content_injection_detected" => &["ASI-01", "ASI-07"],
        "guardrail_decision" => &["ASI-01"],
        "label_verify_failure" => &["ASI-01", "ASI-08"],
        "identity_verify_failure" => &["ASI-05"],
        "proof_verify_failure" => &["ASI-05"],
        "provenance_verify_failure" => &["ASI-08"],
        "delegation_verify_failure" => &["ASI-03", "ASI-10"],
        "secret_redacted" => &["ASI-02"],
        "human_approval_required" => &["ASI-03"],
        "human_approval_resolved" => &["ASI-03"],
        "session_expired" => &["ASI-05"],
        _ => &[],
    }
}

/// Every event kind that has at least one mapping in this module.
///
/// Useful for tests that want to assert a new event kind has been
/// wired up; mirrors `test_all_event_kinds_have_nist_mapping` in the
/// Python suite.
pub fn known_event_kinds() -> Vec<&'static str> {
    let mut s: HashSet<&'static str> = HashSet::new();
    for k in [
        "policy_deny",
        "worker_schema_violation",
        "label_verify_failure",
        "secret_redacted",
        "identity_verify_failure",
        "proof_verify_failure",
        "provenance_verify_failure",
        "delegation_verify_failure",
        "human_approval_required",
        "human_approval_resolved",
        "session_expired",
        "content_injection_detected",
        "guardrail_decision",
    ] {
        s.insert(k);
    }
    let mut out: Vec<&'static str> = s.into_iter().collect();
    out.sort();
    out
}

/// Add `nist_controls`, `cwe_codes`, and `owasp_asi` to an event JSON
/// object based on its `kind` field.
///
/// The input object is cloned; the original is not mutated. If `event`
/// is not a JSON object, it is returned unchanged.
pub fn enrich_event(event: &Value) -> Value {
    let Value::Object(map) = event else {
        return event.clone();
    };
    let kind = map.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let mut out = map.clone();
    out.insert(
        "nist_controls".into(),
        json!(nist_controls(kind).to_vec()),
    );
    out.insert("cwe_codes".into(), json!(cwe_codes(kind).to_vec()));
    out.insert("owasp_asi".into(), json!(owasp_asi(kind).to_vec()));
    Value::Object(out)
}

/// In-memory tamper-evident hash-chained audit log. Each entry's
/// `entry_hash` is the SHA-256 of the canonical-JSON serialization of
/// the entry minus the hash itself; each entry references the prior
/// entry's hash via `previous_hash`. The first entry references
/// [`GENESIS_PREVIOUS_HASH`] (64 ASCII zeros).
///
/// This is the in-memory analog of the on-disk JSONL chain in
/// `tessera_audit::audit_log`; the on-disk version is the one you
/// want for production durability. The in-memory version exists for
/// unit tests, eval harnesses, and code paths that need to inspect
/// the chain without touching the filesystem.
///
/// Mirrors `tessera.compliance.ChainedAuditLog`.
#[derive(Debug)]
pub struct ChainedAuditLog {
    enforce_monotonic: bool,
    previous_hash: String,
    entries: Vec<Value>,
    last_timestamp: Option<String>,
    sequence: u64,
}

impl Default for ChainedAuditLog {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ChainedAuditLog {
    pub fn new(enforce_monotonic: bool) -> Self {
        Self {
            enforce_monotonic,
            previous_hash: GENESIS_PREVIOUS_HASH.to_string(),
            entries: Vec::new(),
            last_timestamp: None,
            sequence: 0,
        }
    }

    /// Append an event to the chain. `timestamp` should be RFC 3339;
    /// monotonicity is checked by lexicographic string comparison
    /// (which is the same as chronological order for valid RFC 3339).
    pub fn append(
        &mut self,
        kind: &str,
        principal: &str,
        detail: Value,
        timestamp: &str,
        correlation_id: Option<&str>,
        trace_id: Option<&str>,
    ) {
        let mut event = Map::new();
        event.insert("kind".into(), Value::String(kind.to_string()));
        event.insert("principal".into(), Value::String(principal.to_string()));
        event.insert("detail".into(), detail);
        event.insert("timestamp".into(), Value::String(timestamp.to_string()));
        if let Some(cid) = correlation_id {
            event.insert("correlation_id".into(), Value::String(cid.to_string()));
        }
        if let Some(tid) = trace_id {
            event.insert("trace_id".into(), Value::String(tid.to_string()));
        }
        let value = Value::Object(event);
        self.append_value(value);
    }

    /// Append an already-built event Value to the chain. Useful when
    /// the event is constructed elsewhere (typed `EventKind` adapter,
    /// test fixtures, replay path).
    pub fn append_value(&mut self, event: Value) {
        let mut enriched_map = match enrich_event(&event) {
            Value::Object(m) => m,
            _ => return,
        };

        enriched_map.insert(
            "previous_hash".into(),
            Value::String(self.previous_hash.clone()),
        );

        // Monotonic timestamp check: a clock-rollback or replayed event
        // gets flagged with a `timestamp_violation` field. We do not
        // refuse the append, the violation is recorded so that
        // `verify_timestamps` can surface it later.
        let event_ts = enriched_map
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if self.enforce_monotonic {
            if let Some(last) = &self.last_timestamp {
                if event_ts.as_str() < last.as_str() {
                    enriched_map.insert(
                        "timestamp_violation".into(),
                        json!({
                            "event_timestamp": event_ts,
                            "last_timestamp": last,
                            "violation": "non-monotonic: event arrived before previous",
                        }),
                    );
                }
            }
        }
        self.last_timestamp = Some(event_ts);

        self.sequence += 1;
        enriched_map.insert("sequence".into(), json!(self.sequence));

        let canonical = canonical_json(&Value::Object(enriched_map.clone()));
        let entry_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
        enriched_map.insert("entry_hash".into(), Value::String(entry_hash.clone()));

        self.previous_hash = entry_hash;
        self.entries.push(Value::Object(enriched_map));
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    /// Verify that every entry's `previous_hash` matches the prior
    /// entry's `entry_hash`, and that each entry's stored `entry_hash`
    /// matches the SHA-256 of its canonical JSON minus the hash field.
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = GENESIS_PREVIOUS_HASH.to_string();
        for entry in &self.entries {
            let Value::Object(map) = entry else {
                return false;
            };
            let prev_match = map
                .get("previous_hash")
                .and_then(|v| v.as_str())
                .map(|s| s == expected_prev.as_str())
                .unwrap_or(false);
            if !prev_match {
                return false;
            }
            let stored_hash = match map.get("entry_hash").and_then(|v| v.as_str()) {
                Some(h) => h.to_string(),
                None => return false,
            };
            let mut without_hash = map.clone();
            without_hash.remove("entry_hash");
            let canonical = canonical_json(&Value::Object(without_hash));
            let computed = hex::encode(Sha256::digest(canonical.as_bytes()));
            if computed != stored_hash {
                return false;
            }
            expected_prev = stored_hash;
        }
        true
    }

    /// Return `(all_valid, violation_sequence_numbers)`.
    pub fn verify_timestamps(&self) -> (bool, Vec<u64>) {
        let mut violations = Vec::new();
        for entry in &self.entries {
            let Value::Object(map) = entry else { continue };
            if map.contains_key("timestamp_violation") {
                let seq = map
                    .get("sequence")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                violations.push(seq);
            }
        }
        (violations.is_empty(), violations)
    }

    /// Verify that sequence numbers are 1, 2, 3, ... N with no gaps.
    /// Detects deleted or inserted entries (the hash chain alone
    /// cannot detect a deletion of the very last entry).
    pub fn verify_sequences(&self) -> bool {
        for (i, entry) in self.entries.iter().enumerate() {
            let Value::Object(map) = entry else {
                return false;
            };
            let seq = map.get("sequence").and_then(|v| v.as_u64()).unwrap_or(0);
            if seq != (i as u64) + 1 {
                return false;
            }
        }
        true
    }

    /// Test-only: mutate the entry at `idx` so we can assert that
    /// tampering is detected. Returns false if `idx` is out of bounds.
    #[cfg(test)]
    pub(crate) fn tamper_entry(&mut self, idx: usize, new_detail: Value) -> bool {
        if idx >= self.entries.len() {
            return false;
        }
        if let Value::Object(map) = &mut self.entries[idx] {
            map.insert("detail".into(), new_detail);
            return true;
        }
        false
    }

    /// Test-only: drop the entry at `idx` to simulate an audit-log
    /// deletion attack. The hash chain may still verify (if you also
    /// rewrite the next entry), but `verify_sequences` will catch it.
    #[cfg(test)]
    pub(crate) fn drop_entry(&mut self, idx: usize) -> bool {
        if idx >= self.entries.len() {
            return false;
        }
        self.entries.remove(idx);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_event(kind: &str, principal: &str, detail: Value, ts: &str) -> Value {
        json!({
            "kind": kind,
            "principal": principal,
            "detail": detail,
            "timestamp": ts,
        })
    }

    // ---- NIST / CWE / OWASP enrichment ----

    #[test]
    fn enrich_policy_deny_carries_nist_and_cwe() {
        let event = fixed_event("policy_deny", "alice", json!({"tool": "send_email"}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        let nist = enriched["nist_controls"].as_array().unwrap();
        let cwe = enriched["cwe_codes"].as_array().unwrap();
        assert!(nist.iter().any(|v| v == "AC-4"));
        assert!(nist.iter().any(|v| v == "SI-10"));
        assert!(cwe.iter().any(|v| v == "CWE-20"));
    }

    #[test]
    fn enrich_label_verify_failure() {
        let event = fixed_event("label_verify_failure", "unknown", json!({}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        assert!(enriched["nist_controls"].as_array().unwrap().iter().any(|v| v == "IA-9"));
        assert!(enriched["cwe_codes"].as_array().unwrap().iter().any(|v| v == "CWE-345"));
    }

    #[test]
    fn enrich_delegation_failure() {
        let event = fixed_event("delegation_verify_failure", "bob", json!({}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        assert!(enriched["nist_controls"].as_array().unwrap().iter().any(|v| v == "AC-6"));
        assert!(enriched["cwe_codes"].as_array().unwrap().iter().any(|v| v == "CWE-285"));
    }

    #[test]
    fn enrich_unknown_kind_returns_empty_lists() {
        let event = fixed_event("session_expired", "sys", json!({}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        // session_expired has NIST but no CWE
        assert_eq!(enriched["nist_controls"].as_array().unwrap()[0], "AC-12");
        assert!(enriched["cwe_codes"].as_array().unwrap().is_empty());
    }

    #[test]
    fn enrich_preserves_original_fields() {
        let event = fixed_event("secret_redacted", "alice", json!({"name": "API_KEY"}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        assert_eq!(enriched["kind"], "secret_redacted");
        assert_eq!(enriched["principal"], "alice");
        assert_eq!(enriched["detail"]["name"], "API_KEY");
    }

    #[test]
    fn enrich_non_object_returns_unchanged() {
        let event = json!("just a string");
        let enriched = enrich_event(&event);
        assert_eq!(enriched, json!("just a string"));
    }

    #[test]
    fn enrich_carries_owasp_asi_for_policy_deny() {
        let event = fixed_event("policy_deny", "alice", json!({}), "2026-04-23T00:00:00Z");
        let enriched = enrich_event(&event);
        assert_eq!(enriched["owasp_asi"].as_array().unwrap()[0], "ASI-01");
    }

    #[test]
    fn enrich_owasp_asi_for_content_injection_has_two_entries() {
        let event = fixed_event(
            "content_injection_detected",
            "alice",
            json!({"score": 0.95}),
            "2026-04-23T00:00:00Z",
        );
        let enriched = enrich_event(&event);
        let asi = enriched["owasp_asi"].as_array().unwrap();
        assert!(asi.iter().any(|v| v == "ASI-01"));
        assert!(asi.iter().any(|v| v == "ASI-07"));
    }

    #[test]
    fn known_event_kinds_includes_every_table_key() {
        let kinds = known_event_kinds();
        assert!(kinds.contains(&"policy_deny"));
        assert!(kinds.contains(&"guardrail_decision"));
        // Every Python EventKind value must appear here so a future
        // refactor cannot silently drop a kind.
        assert_eq!(kinds.len(), 13);
    }

    // ---- Hash-chain audit log ----

    #[test]
    fn chain_single_event() {
        let mut chain = ChainedAuditLog::new(true);
        chain.append("policy_deny", "alice", json!({"tool": "x"}), "2026-04-23T00:00:00Z", None, None);
        assert_eq!(chain.entries().len(), 1);
        assert_eq!(chain.entries()[0]["previous_hash"], GENESIS_PREVIOUS_HASH);
        assert_eq!(chain.entries()[0]["entry_hash"].as_str().unwrap().len(), 64);
        assert!(chain.verify_chain());
    }

    #[test]
    fn chain_multiple_events_link_correctly() {
        let mut chain = ChainedAuditLog::new(true);
        for i in 0..5 {
            chain.append(
                "policy_deny",
                "alice",
                json!({"i": i}),
                &format!("2026-04-23T00:00:0{i}Z"),
                None,
                None,
            );
        }
        assert_eq!(chain.entries().len(), 5);
        for i in 1..5 {
            assert_eq!(
                chain.entries()[i]["previous_hash"],
                chain.entries()[i - 1]["entry_hash"]
            );
        }
        assert!(chain.verify_chain());
    }

    #[test]
    fn chain_detects_tamper() {
        let mut chain = ChainedAuditLog::new(true);
        for tag in ["a", "b", "c"] {
            chain.append("policy_deny", "alice", json!({"tool": tag}), "2026-04-23T00:00:00Z", None, None);
        }
        assert!(chain.tamper_entry(1, json!({"tool": "TAMPERED"})));
        assert!(!chain.verify_chain());
    }

    #[test]
    fn chain_empty_verifies_true() {
        let chain = ChainedAuditLog::new(true);
        assert!(chain.verify_chain());
    }

    #[test]
    fn chain_with_correlation_and_trace_ids() {
        let mut chain = ChainedAuditLog::new(true);
        chain.append(
            "policy_deny",
            "alice",
            json!({}),
            "2026-04-23T00:00:00Z",
            Some("req-123"),
            Some("trace-abc"),
        );
        let entry = &chain.entries()[0];
        assert_eq!(entry["correlation_id"], "req-123");
        assert_eq!(entry["trace_id"], "trace-abc");
        assert!(chain.verify_chain());
    }

    // ---- Timestamp + sequence validation ----

    #[test]
    fn monotonic_timestamps_pass() {
        let mut chain = ChainedAuditLog::new(true);
        for i in 0..5 {
            chain.append(
                "policy_deny",
                "alice",
                json!({"i": i}),
                &format!("2026-04-23T00:00:0{i}Z"),
                None,
                None,
            );
        }
        let (valid, violations) = chain.verify_timestamps();
        assert!(valid);
        assert!(violations.is_empty());
    }

    #[test]
    fn non_monotonic_timestamp_detected() {
        let mut chain = ChainedAuditLog::new(true);
        chain.append("policy_deny", "alice", json!({}), "2026-04-15T12:00:00Z", None, None);
        chain.append("policy_deny", "alice", json!({}), "2026-04-15T11:59:00Z", None, None);
        let (valid, violations) = chain.verify_timestamps();
        assert!(!valid);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0], 2);
    }

    #[test]
    fn sequence_numbers_contiguous() {
        let mut chain = ChainedAuditLog::new(true);
        for i in 0..4 {
            chain.append(
                "policy_deny",
                "alice",
                json!({"i": i}),
                &format!("2026-04-23T00:00:0{i}Z"),
                None,
                None,
            );
        }
        assert!(chain.verify_sequences());
        assert_eq!(chain.entries()[0]["sequence"], 1);
        assert_eq!(chain.entries()[3]["sequence"], 4);
    }

    #[test]
    fn sequence_gap_detected() {
        let mut chain = ChainedAuditLog::new(true);
        for i in 0..3 {
            chain.append(
                "policy_deny",
                "alice",
                json!({"i": i}),
                &format!("2026-04-23T00:00:0{i}Z"),
                None,
                None,
            );
        }
        assert!(chain.drop_entry(1));
        assert!(!chain.verify_sequences());
    }

    #[test]
    fn enforce_monotonic_disabled_records_no_violation() {
        let mut chain = ChainedAuditLog::new(false);
        chain.append("policy_deny", "alice", json!({}), "2026-04-15T12:00:00Z", None, None);
        chain.append("policy_deny", "alice", json!({}), "2026-04-15T11:00:00Z", None, None);
        let (valid, violations) = chain.verify_timestamps();
        assert!(valid);
        assert!(violations.is_empty());
    }

    #[test]
    fn chain_enriches_with_compliance_metadata() {
        let mut chain = ChainedAuditLog::new(true);
        chain.append("policy_deny", "alice", json!({}), "2026-04-23T00:00:00Z", None, None);
        let entry = &chain.entries()[0];
        assert!(entry.get("nist_controls").is_some());
        assert!(entry.get("cwe_codes").is_some());
        assert_eq!(entry["nist_controls"][0], "AC-4");
    }

    // ---- Lookup correctness ----

    #[test]
    fn lookups_return_empty_for_unknown_kind() {
        assert!(nist_controls("not_a_kind").is_empty());
        assert!(cwe_codes("not_a_kind").is_empty());
        assert!(owasp_asi("not_a_kind").is_empty());
    }

    #[test]
    fn nist_table_covers_all_known_kinds() {
        for k in known_event_kinds() {
            assert!(
                !nist_controls(k).is_empty(),
                "nist_controls missing for {k}"
            );
        }
    }

    #[test]
    fn append_value_path_matches_append_string_path() {
        let mut a = ChainedAuditLog::new(true);
        let mut b = ChainedAuditLog::new(true);
        let event = fixed_event("policy_deny", "alice", json!({"tool": "send_email"}), "2026-04-23T00:00:00Z");
        a.append_value(event.clone());
        b.append("policy_deny", "alice", json!({"tool": "send_email"}), "2026-04-23T00:00:00Z", None, None);
        assert_eq!(a.entries()[0]["entry_hash"], b.entries()[0]["entry_hash"]);
    }

    #[test]
    fn chain_verify_after_three_kinds_mixed() {
        let mut chain = ChainedAuditLog::new(true);
        chain.append("label_verify_failure", "u", json!({}), "2026-04-23T00:00:00Z", None, None);
        chain.append("delegation_verify_failure", "u", json!({}), "2026-04-23T00:00:01Z", None, None);
        chain.append("secret_redacted", "u", json!({"name": "AWS_SECRET"}), "2026-04-23T00:00:02Z", None, None);
        assert!(chain.verify_chain());
        assert!(chain.verify_sequences());
        let (ok, _) = chain.verify_timestamps();
        assert!(ok);
    }
}
