//! Agent Audit SARIF correlation with Tessera runtime events.
//!
//! Ingests Agent Audit SARIF output (static analysis findings) and
//! correlates them with runtime events by tool name and OWASP
//! category. When a statically flagged tool actually fires at
//! runtime, operators get evidence the theoretical finding has
//! practical impact.
//!
//! Mirrors `tessera.compliance_sarif` in the Python reference.
//! Events are passed in as `serde_json::Value` rather than a
//! concrete `SecurityEvent` type because `tessera-policy` does not
//! own the event-sink abstraction. The expected shape is
//! `{ "kind": "...", "detail": {"tool": "..."}, ... }`, which is
//! what every gateway / runtime emit path produces.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::compliance::owasp_asi;

/// A finding from Agent Audit's static analysis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticFinding {
    pub rule_id: String,
    pub tool_name: String,
    pub owasp_category: String,
    pub message: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub line: Option<u64>,
}

/// A runtime event that matches a static finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedFinding {
    pub runtime_event: Value,
    pub static_finding: StaticFinding,
    /// One of `"tool_match"`, `"owasp_match"`, or `"both"`.
    pub correlation_type: String,
}

/// Correlate Agent Audit static findings with Tessera runtime events.
#[derive(Clone, Debug, Default)]
pub struct SarifCorrelator {
    static_findings: Vec<StaticFinding>,
    correlated: Vec<CorrelatedFinding>,
}

impl SarifCorrelator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load Agent Audit SARIF output from a file. Returns the number
    /// of findings loaded.
    pub fn load_sarif(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let body = std::fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
        let data: Value =
            serde_json::from_str(&body).map_err(|e| format!("malformed SARIF JSON: {e}"))?;
        Ok(self.load_sarif_value(&data))
    }

    /// Load findings from an already-parsed SARIF Value.
    pub fn load_sarif_value(&mut self, data: &Value) -> usize {
        let mut count = 0;
        if let Some(runs) = data.get("runs").and_then(|v| v.as_array()) {
            for run in runs {
                if let Some(results) = run.get("results").and_then(|v| v.as_array()) {
                    for result in results {
                        if let Some(finding) = sarif_result_to_finding(result) {
                            self.static_findings.push(finding);
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }

    /// Add findings directly. Useful for tests and for building a
    /// correlator from a non-SARIF source.
    pub fn load_findings(&mut self, findings: impl IntoIterator<Item = StaticFinding>) {
        self.static_findings.extend(findings);
    }

    /// Check a single event against loaded findings. The `event`
    /// must be a JSON object with at least a `kind` string and a
    /// `detail` object that may contain `tool`. Returns every
    /// match (a single event can match multiple findings).
    pub fn correlate(&self, event: &Value) -> Vec<CorrelatedFinding> {
        let kind = event.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let event_tool = event
            .get("detail")
            .and_then(|d| d.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let event_owasp: Vec<&'static str> = owasp_asi(kind).to_vec();

        let mut results = Vec::new();
        for finding in &self.static_findings {
            let tool_match = !event_tool.is_empty() && event_tool == finding.tool_name;
            let owasp_match = event_owasp
                .iter()
                .any(|c| *c == finding.owasp_category.as_str());
            let correlation_type = match (tool_match, owasp_match) {
                (true, true) => "both",
                (true, false) => "tool_match",
                (false, true) => "owasp_match",
                (false, false) => continue,
            };
            results.push(CorrelatedFinding {
                runtime_event: event.clone(),
                static_finding: finding.clone(),
                correlation_type: correlation_type.to_string(),
            });
        }
        results
    }

    /// Same as [`correlate`] but also records every match in the
    /// internal log. Use this when wiring the correlator as a sink.
    pub fn correlate_and_record(&mut self, event: &Value) -> Vec<CorrelatedFinding> {
        let matches = self.correlate(event);
        self.correlated.extend(matches.iter().cloned());
        matches
    }

    pub fn correlated_findings(&self) -> &[CorrelatedFinding] {
        &self.correlated
    }

    pub fn static_findings(&self) -> &[StaticFinding] {
        &self.static_findings
    }
}

fn sarif_result_to_finding(result: &Value) -> Option<StaticFinding> {
    let rule_id = result
        .get("ruleId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let message = result
        .get("message")
        .and_then(|m| m.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let level = result
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("warning");
    let props = result.get("properties");
    let tool_name = props
        .and_then(|p| p.get("tool_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let owasp_category = props
        .and_then(|p| p.get("owasp_category"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let severity = match level {
        "error" => "BLOCK",
        "warning" => "WARN",
        "note" | "none" => "INFO",
        _ => "WARN",
    }
    .to_string();
    let mut file_path = None;
    let mut line = None;
    if let Some(loc) = result
        .get("locations")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        if let Some(phys) = loc.get("physicalLocation") {
            file_path = phys
                .get("artifactLocation")
                .and_then(|al| al.get("uri"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            line = phys
                .get("region")
                .and_then(|r| r.get("startLine"))
                .and_then(|v| v.as_u64());
        }
    }
    if rule_id.is_empty() && tool_name.is_empty() {
        return None;
    }
    Some(StaticFinding {
        rule_id,
        tool_name,
        owasp_category,
        message,
        severity,
        file_path,
        line,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_finding(tool: &str, owasp: &str) -> StaticFinding {
        StaticFinding {
            rule_id: "AGENT-056".into(),
            tool_name: tool.into(),
            owasp_category: owasp.into(),
            message: "test finding".into(),
            severity: "WARN".into(),
            file_path: Some("agent.py".into()),
            line: Some(42),
        }
    }

    fn sample_event(kind: &str, tool: &str) -> Value {
        json!({
            "kind": kind,
            "principal": "alice",
            "detail": {"tool": tool},
            "timestamp": "2026-04-23T00:00:00+00:00"
        })
    }

    #[test]
    fn correlate_tool_match_when_tool_name_aligns() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("send_email", "ASI-99")]);
        let event = sample_event("policy_deny", "send_email");
        let matches = c.correlate(&event);
        // policy_deny -> ASI-01; finding has ASI-99 -> tool_match only.
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].correlation_type, "tool_match");
    }

    #[test]
    fn correlate_owasp_match_when_category_overlaps() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("other_tool", "ASI-01")]);
        let event = sample_event("policy_deny", "send_email");
        let matches = c.correlate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].correlation_type, "owasp_match");
    }

    #[test]
    fn correlate_both_when_tool_and_owasp_align() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("send_email", "ASI-01")]);
        let event = sample_event("policy_deny", "send_email");
        let matches = c.correlate(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].correlation_type, "both");
    }

    #[test]
    fn correlate_no_match_returns_empty() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("other_tool", "ASI-99")]);
        let event = sample_event("policy_deny", "send_email");
        assert!(c.correlate(&event).is_empty());
    }

    #[test]
    fn load_sarif_value_extracts_findings() {
        let sarif = json!({
            "runs": [{
                "results": [{
                    "ruleId": "AGENT-056",
                    "level": "warning",
                    "message": {"text": "tool may be poisoned"},
                    "properties": {
                        "tool_name": "send_email",
                        "owasp_category": "ASI-01"
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "agent.py"},
                            "region": {"startLine": 10}
                        }
                    }]
                }]
            }]
        });
        let mut c = SarifCorrelator::new();
        let n = c.load_sarif_value(&sarif);
        assert_eq!(n, 1);
        assert_eq!(c.static_findings().len(), 1);
        let f = &c.static_findings()[0];
        assert_eq!(f.rule_id, "AGENT-056");
        assert_eq!(f.severity, "WARN");
        assert_eq!(f.line, Some(10));
        assert_eq!(f.file_path.as_deref(), Some("agent.py"));
    }

    #[test]
    fn level_maps_to_severity_correctly() {
        for (level, expected) in [
            ("error", "BLOCK"),
            ("warning", "WARN"),
            ("note", "INFO"),
            ("none", "INFO"),
            ("garbage", "WARN"),
        ] {
            let r = json!({"ruleId": "X", "level": level, "properties": {"tool_name": "t"}});
            let f = sarif_result_to_finding(&r).unwrap();
            assert_eq!(f.severity, expected);
        }
    }

    #[test]
    fn sarif_result_without_rule_or_tool_returns_none() {
        let r = json!({"level": "warning"});
        assert!(sarif_result_to_finding(&r).is_none());
    }

    #[test]
    fn correlate_and_record_accumulates_state() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("send_email", "ASI-01")]);
        let event = sample_event("policy_deny", "send_email");
        c.correlate_and_record(&event);
        c.correlate_and_record(&event);
        assert_eq!(c.correlated_findings().len(), 2);
    }

    #[test]
    fn load_sarif_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sarif.json");
        let sarif = json!({
            "runs": [{
                "results": [{
                    "ruleId": "AGENT-001",
                    "level": "error",
                    "message": {"text": "x"},
                    "properties": {"tool_name": "t", "owasp_category": "ASI-01"}
                }]
            }]
        });
        std::fs::write(&path, sarif.to_string()).unwrap();
        let mut c = SarifCorrelator::new();
        assert_eq!(c.load_sarif(&path).unwrap(), 1);
    }

    #[test]
    fn empty_event_kind_does_not_match_owasp() {
        let mut c = SarifCorrelator::new();
        c.load_findings([sample_finding("send_email", "ASI-01")]);
        let event = json!({"kind": "", "detail": {"tool": "send_email"}});
        let matches = c.correlate(&event);
        // tool matches, owasp does not (no mapping for "").
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].correlation_type, "tool_match");
    }
}
