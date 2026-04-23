//! SARIF 2.1.0 output sink for SecurityEvents.
//!
//! Collects events during an agent run and serializes them to SARIF
//! 2.1.0 JSON, suitable for upload to GitHub Code Scanning,
//! Semgrep App, or any SARIF consumer.
//!
//! Mirrors `tessera.events_sarif` in the Python reference. Events
//! are accepted as `serde_json::Value` rather than a concrete
//! `SecurityEvent` type so the sink stays decoupled from any
//! specific event-emission path. The expected shape is
//! `{ "kind": "...", "principal": "...", ... }`, which is what
//! every gateway / runtime emit path produces.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";

fn kind_to_rule(kind: &str) -> String {
    match kind {
        "policy_deny" => "tessera/policy-deny".to_string(),
        "worker_schema_violation" => "tessera/worker-schema-violation".to_string(),
        "label_verify_failure" => "tessera/label-verify-failure".to_string(),
        "secret_redacted" => "tessera/secret-redacted".to_string(),
        "identity_verify_failure" => "tessera/identity-verify-failure".to_string(),
        "proof_verify_failure" => "tessera/proof-verify-failure".to_string(),
        "provenance_verify_failure" => "tessera/provenance-verify-failure".to_string(),
        "delegation_verify_failure" => "tessera/delegation-verify-failure".to_string(),
        "human_approval_required" => "tessera/human-approval-required".to_string(),
        "human_approval_resolved" => "tessera/human-approval-resolved".to_string(),
        "session_expired" => "tessera/session-expired".to_string(),
        "content_injection_detected" => "tessera/injection-detected".to_string(),
        other => format!("tessera/{other}"),
    }
}

fn kind_to_level(kind: &str) -> &'static str {
    match kind {
        "policy_deny"
        | "worker_schema_violation"
        | "label_verify_failure"
        | "identity_verify_failure"
        | "proof_verify_failure"
        | "provenance_verify_failure"
        | "delegation_verify_failure"
        | "content_injection_detected" => "error",
        "secret_redacted" | "human_approval_required" | "session_expired" => "warning",
        "human_approval_resolved" => "note",
        _ => "warning",
    }
}

/// SARIF event sink. Collects events under a mutex; every method on
/// the sink is `&self`.
#[derive(Debug)]
pub struct SarifSink {
    tool_name: String,
    tool_version: String,
    events: Mutex<Vec<Value>>,
}

impl SarifSink {
    pub fn new(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new("tessera", env!("CARGO_PKG_VERSION"))
    }

    /// Record one event. Cheap: just an append under a mutex.
    pub fn emit(&self, event: Value) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.events.lock() {
            g.clear();
        }
    }

    /// Return the SARIF 2.1.0 JSON for every event collected so far.
    pub fn to_sarif(&self) -> Value {
        let events = match self.events.lock() {
            Ok(g) => g.clone(),
            Err(_) => Vec::new(),
        };
        let mut seen_rules: BTreeMap<String, Value> = BTreeMap::new();
        let mut results: Vec<Value> = Vec::new();
        for event in &events {
            let kind = event.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let principal = event
                .get("principal")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let rule_id = kind_to_rule(kind);
            let level = kind_to_level(kind);
            seen_rules.entry(rule_id.clone()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "shortDescription": {"text": kind},
                })
            });
            let mut result = Map::new();
            result.insert("ruleId".into(), Value::String(rule_id));
            result.insert("level".into(), Value::String(level.to_string()));
            result.insert(
                "message".into(),
                json!({"text": format!("{kind} by {principal}")}),
            );
            result.insert("properties".into(), event.clone());
            results.push(Value::Object(result));
        }
        let rules: Vec<Value> = seen_rules.into_values().collect();
        json!({
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        })
    }

    /// Write SARIF JSON to `path`. Pretty-printed (2-space indent).
    pub fn write(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let body = serde_json::to_string_pretty(&self.to_sarif()).expect("SARIF serializes");
        std::fs::write(path, body)
    }
}

/// Helper: build an event Value with the standard shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SarifEventBuilder {
    pub kind: String,
    pub principal: String,
    pub timestamp: String,
    pub detail: Value,
}

impl SarifEventBuilder {
    pub fn into_value(self) -> Value {
        json!({
            "kind": self.kind,
            "principal": self.principal,
            "timestamp": self.timestamp,
            "detail": self.detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, principal: &str) -> Value {
        json!({
            "kind": kind,
            "principal": principal,
            "timestamp": "2026-04-23T00:00:00+00:00",
            "detail": {}
        })
    }

    #[test]
    fn empty_sink_emits_valid_sarif_skeleton() {
        let s = SarifSink::with_defaults();
        let v = s.to_sarif();
        assert_eq!(v["version"], SARIF_VERSION);
        assert_eq!(v["runs"].as_array().unwrap().len(), 1);
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "tessera");
    }

    #[test]
    fn emit_appends_to_results() {
        let s = SarifSink::new("tessera", "0.8.0-alpha.3");
        s.emit(event("policy_deny", "alice"));
        s.emit(event("policy_deny", "bob"));
        let v = s.to_sarif();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "tessera/policy-deny");
        assert_eq!(results[0]["level"], "error");
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("policy_deny by alice"));
    }

    #[test]
    fn rules_block_contains_each_unique_kind_once() {
        let s = SarifSink::with_defaults();
        s.emit(event("policy_deny", "alice"));
        s.emit(event("policy_deny", "bob"));
        s.emit(event("label_verify_failure", "x"));
        let v = s.to_sarif();
        let rules = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn level_maps_match_python_reference() {
        let cases = [
            ("policy_deny", "error"),
            ("secret_redacted", "warning"),
            ("human_approval_required", "warning"),
            ("human_approval_resolved", "note"),
            ("identity_verify_failure", "error"),
            ("session_expired", "warning"),
            ("unknown_kind", "warning"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind_to_level(kind), expected, "kind={kind}");
        }
    }

    #[test]
    fn unknown_kind_maps_to_tessera_prefix() {
        assert_eq!(kind_to_rule("guardrail_decision"), "tessera/guardrail_decision");
    }

    #[test]
    fn write_produces_readable_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.sarif");
        let s = SarifSink::with_defaults();
        s.emit(event("policy_deny", "alice"));
        s.write(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["version"], SARIF_VERSION);
    }

    #[test]
    fn clear_resets_event_count() {
        let s = SarifSink::with_defaults();
        s.emit(event("policy_deny", "x"));
        s.emit(event("policy_deny", "y"));
        assert_eq!(s.event_count(), 2);
        s.clear();
        assert_eq!(s.event_count(), 0);
    }

    #[test]
    fn event_count_reflects_emitted_events() {
        let s = SarifSink::with_defaults();
        for _ in 0..5 {
            s.emit(event("policy_deny", "x"));
        }
        assert_eq!(s.event_count(), 5);
    }

    #[test]
    fn properties_carry_full_event_payload() {
        let s = SarifSink::with_defaults();
        let e = json!({
            "kind": "policy_deny",
            "principal": "alice",
            "detail": {"tool": "send_email", "extra": 123},
            "timestamp": "2026-04-23T00:00:00+00:00",
        });
        s.emit(e.clone());
        let v = s.to_sarif();
        let props = &v["runs"][0]["results"][0]["properties"];
        assert_eq!(props, &e);
    }

    #[test]
    fn schema_url_matches_oasis_2_1_0() {
        let s = SarifSink::with_defaults();
        let v = s.to_sarif();
        assert_eq!(v["$schema"].as_str().unwrap(), SARIF_SCHEMA);
    }
}
