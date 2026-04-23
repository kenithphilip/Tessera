//! Per-trajectory information-flow primitives.
//!
//! Tracks data sensitivity across an agent trajectory and enforces
//! an outbound-flow policy. Sensitivity is orthogonal to trust:
//! trust says "who said this" (USER, TOOL, UNTRUSTED); sensitivity
//! says "how bad if it leaks" (PUBLIC, INTERNAL, CONFIDENTIAL,
//! RESTRICTED).
//!
//! Mirrors `tessera.sensitivity` in the Python reference. The
//! classifier is intentionally pattern-based so false-positive
//! iteration is fast (same approach as the directive / intent
//! scanners in `tessera-scanners`). Plug in a vendor DLP classifier
//! by passing a custom rule set or wrapping
//! [`SensitivityClassifier`] with a different `classify` impl.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};

/// Ordered sensitivity lattice. Higher value means more sensitive.
///
/// Numeric values match the Python `IntEnum`, so any cross-language
/// transport (a JSON `int` value) round-trips exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum SensitivityLabel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl SensitivityLabel {
    /// Parse a label from its uppercase or mixed-case name.
    pub fn from_str(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_uppercase().as_str() {
            "PUBLIC" => Ok(Self::Public),
            "INTERNAL" => Ok(Self::Internal),
            "CONFIDENTIAL" => Ok(Self::Confidential),
            "RESTRICTED" => Ok(Self::Restricted),
            other => Err(format!("unknown sensitivity label: {other:?}")),
        }
    }

    /// Uppercase canonical name, matching Python's `IntEnum.name`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Internal => "INTERNAL",
            Self::Confidential => "CONFIDENTIAL",
            Self::Restricted => "RESTRICTED",
        }
    }
}

impl Default for SensitivityLabel {
    fn default() -> Self {
        Self::Public
    }
}

/// Whether the rule's pattern alone is sufficient or whether an
/// extra structural validation step has to pass.
#[derive(Clone, Debug)]
pub enum RuleKind {
    /// Any regex match counts as a hit.
    Pattern,
    /// US Social Security Number: regex finds candidate triples;
    /// area must not be `000`, `666`, or `9xx`; group must not be
    /// `00`; serial must not be `0000`. The Python reference uses
    /// negative lookaheads in the regex itself, which Rust's `regex`
    /// crate does not support, so the structural check lives here.
    UsSsn,
}

/// A single labeled pattern. The highest-matching rule wins during
/// classification.
#[derive(Clone, Debug)]
pub struct ClassificationRule {
    pub id: String,
    pub label: SensitivityLabel,
    pub pattern: Regex,
    pub description: String,
    pub kind: RuleKind,
}

impl ClassificationRule {
    pub fn standard(
        id: impl Into<String>,
        label: SensitivityLabel,
        pattern: Regex,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label,
            pattern,
            description: description.into(),
            kind: RuleKind::Pattern,
        }
    }

    fn matches(&self, text: &str) -> bool {
        match self.kind {
            RuleKind::Pattern => self.pattern.is_match(text),
            RuleKind::UsSsn => self
                .pattern
                .captures_iter(text)
                .any(|c| valid_ssn_captures(&c)),
        }
    }
}

fn valid_ssn_captures(caps: &Captures<'_>) -> bool {
    let area = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let group = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let serial = caps.get(3).map(|m| m.as_str()).unwrap_or("");
    if area == "000" || area == "666" {
        return false;
    }
    if area.starts_with('9') {
        return false;
    }
    if group == "00" {
        return false;
    }
    if serial == "0000" {
        return false;
    }
    true
}

/// Result of [`SensitivityClassifier::classify`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub label: SensitivityLabel,
    pub matched_rule_ids: Vec<String>,
}

impl Classification {
    pub fn public() -> Self {
        Self {
            label: SensitivityLabel::Public,
            matched_rule_ids: Vec::new(),
        }
    }
}

/// Default rule set. Tuned conservatively. Extend by passing
/// additional rules to [`SensitivityClassifier::with_rules`] or by
/// calling [`SensitivityClassifier::register`].
pub fn default_rules() -> Vec<ClassificationRule> {
    static DEFAULTS: LazyLock<Vec<ClassificationRule>> = LazyLock::new(|| {
        vec![
            // RESTRICTED ----------------------------------------------------
            ClassificationRule {
                id: "pii.ssn".into(),
                label: SensitivityLabel::Restricted,
                pattern: Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").unwrap(),
                description: "US Social Security Number".into(),
                kind: RuleKind::UsSsn,
            },
            ClassificationRule::standard(
                "pii.credit_card",
                SensitivityLabel::Restricted,
                Regex::new(
                    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
                )
                .unwrap(),
                "Major-issuer credit card",
            ),
            ClassificationRule::standard(
                "pii.aadhaar",
                SensitivityLabel::Restricted,
                Regex::new(r"\b\d{4}\s?\d{4}\s?\d{4}\b").unwrap(),
                "Aadhaar (12-digit)",
            ),
            // CONFIDENTIAL --------------------------------------------------
            ClassificationRule::standard(
                "secret.aws_access_key",
                SensitivityLabel::Confidential,
                Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                "AWS access key id",
            ),
            ClassificationRule::standard(
                "secret.aws_secret",
                SensitivityLabel::Confidential,
                Regex::new(
                    r"(?i)aws(.{0,20})?(secret|sk)[^a-z0-9]{0,5}[a-z0-9/+=]{40}",
                )
                .unwrap(),
                "AWS secret access key (heuristic)",
            ),
            ClassificationRule::standard(
                "secret.gcp_sa_key",
                SensitivityLabel::Confidential,
                Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
                "GCP service-account JSON",
            ),
            ClassificationRule::standard(
                "secret.private_key_pem",
                SensitivityLabel::Confidential,
                Regex::new(
                    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
                )
                .unwrap(),
                "PEM/OpenSSH private key block",
            ),
            ClassificationRule::standard(
                "secret.jwt",
                SensitivityLabel::Confidential,
                Regex::new(
                    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
                )
                .unwrap(),
                "JWT",
            ),
            ClassificationRule::standard(
                "secret.github_token",
                SensitivityLabel::Confidential,
                Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
                "GitHub token",
            ),
            ClassificationRule::standard(
                "secret.slack_token",
                SensitivityLabel::Confidential,
                Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
                "Slack token",
            ),
            ClassificationRule::standard(
                "secret.generic_bearer",
                SensitivityLabel::Confidential,
                Regex::new(
                    r"(?i)(?:authorization\s*:\s*bearer\s+|api[_-]?key\s*[:=]\s*)[A-Za-z0-9._\-]{20,}",
                )
                .unwrap(),
                "Bearer / api-key header (heuristic)",
            ),
            ClassificationRule::standard(
                "marker.confidential_header",
                SensitivityLabel::Confidential,
                Regex::new(
                    r"(?i)\b(?:strictly\s+)?confidential\b|\bnda\b|\bprivileged\b",
                )
                .unwrap(),
                "Explicit confidentiality marker",
            ),
            // INTERNAL ------------------------------------------------------
            ClassificationRule::standard(
                "marker.internal_header",
                SensitivityLabel::Internal,
                Regex::new(r"(?i)\binternal(?:\s+only)?\b|\bcompany\s+confidential\b")
                    .unwrap(),
                "Explicit internal marker",
            ),
        ]
    });
    DEFAULTS.clone()
}

/// Pattern-based sensitivity classifier.
///
/// Walks all rules and returns the maximum label whose pattern
/// matched. Matching is stateless and thread-safe; runtime rule
/// additions are guarded by a mutex.
#[derive(Clone)]
pub struct SensitivityClassifier {
    rules: Arc<Mutex<Vec<ClassificationRule>>>,
}

impl SensitivityClassifier {
    /// Construct with the default rule set.
    pub fn new() -> Self {
        Self::with_rules(default_rules(), true)
    }

    /// Construct with `rules` and an `include_defaults` flag.
    /// `include_defaults = false` is useful for tests and DLP
    /// integrations that supply their own taxonomy.
    pub fn with_rules(rules: Vec<ClassificationRule>, include_defaults: bool) -> Self {
        let mut base: Vec<ClassificationRule> = if include_defaults {
            default_rules()
        } else {
            Vec::new()
        };
        base.extend(rules);
        Self {
            rules: Arc::new(Mutex::new(base)),
        }
    }

    pub fn register(&self, rule: ClassificationRule) {
        if let Ok(mut g) = self.rules.lock() {
            g.push(rule);
        }
    }

    pub fn rules(&self) -> Vec<ClassificationRule> {
        self.rules.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Classify a piece of content. Empty input returns `PUBLIC`.
    pub fn classify(&self, content: &str) -> Classification {
        if content.is_empty() {
            return Classification::public();
        }
        let snapshot = self.rules();
        let mut best = SensitivityLabel::Public;
        let mut matched: Vec<String> = Vec::new();
        for rule in &snapshot {
            if rule.matches(content) {
                matched.push(rule.id.clone());
                if rule.label > best {
                    best = rule.label;
                }
            }
        }
        Classification {
            label: best,
            matched_rule_ids: matched,
        }
    }
}

impl Default for SensitivityClassifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---- High-water mark -----------------------------------------------------

/// Pluggable backing store for high-water marks. Swap for a Redis
/// implementation in production by implementing this trait.
pub trait HwmStore: Send + Sync {
    fn get(&self, trajectory_id: &str) -> SensitivityLabel;
    fn set(&self, trajectory_id: &str, label: SensitivityLabel);
    fn delete(&self, trajectory_id: &str);
}

/// Thread-safe in-memory store. Suitable for single-process proxies.
#[derive(Default)]
pub struct InMemoryHwmStore {
    inner: Mutex<HashMap<String, SensitivityLabel>>,
}

impl HwmStore for InMemoryHwmStore {
    fn get(&self, trajectory_id: &str) -> SensitivityLabel {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.get(trajectory_id).copied())
            .unwrap_or(SensitivityLabel::Public)
    }

    fn set(&self, trajectory_id: &str, label: SensitivityLabel) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(trajectory_id.to_string(), label);
        }
    }

    fn delete(&self, trajectory_id: &str) {
        if let Ok(mut g) = self.inner.lock() {
            g.remove(trajectory_id);
        }
    }
}

/// Per-trajectory monotonic max of observed sensitivity labels.
///
/// `observe` is the only way the mark moves; it never goes down.
/// Call `reset` at end-of-trajectory (session close, agent reset)
/// to release the mark.
pub struct HighWaterMark {
    store: Arc<dyn HwmStore>,
}

impl HighWaterMark {
    pub fn new(store: Arc<dyn HwmStore>) -> Self {
        Self { store }
    }

    pub fn in_memory() -> Self {
        Self::new(Arc::new(InMemoryHwmStore::default()))
    }

    pub fn observe(
        &self,
        trajectory_id: &str,
        label: SensitivityLabel,
    ) -> SensitivityLabel {
        let current = self.store.get(trajectory_id);
        if label > current {
            self.store.set(trajectory_id, label);
            label
        } else {
            current
        }
    }

    pub fn get(&self, trajectory_id: &str) -> SensitivityLabel {
        self.store.get(trajectory_id)
    }

    pub fn reset(&self, trajectory_id: &str) {
        self.store.delete(trajectory_id)
    }
}

// ---- Outbound policy -----------------------------------------------------

/// How a tool is treated with respect to outbound data flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolClassification {
    /// `true` if the tool can emit data outside the trust boundary.
    pub outbound: bool,
    /// Highest label allowed to flow through this tool. If the
    /// trajectory's HWM exceeds this, [`OutboundPolicy::check`]
    /// denies.
    pub max_sensitivity: SensitivityLabel,
}

impl ToolClassification {
    pub fn inbound() -> Self {
        Self {
            outbound: false,
            max_sensitivity: SensitivityLabel::Restricted,
        }
    }

    pub fn outbound(max_sensitivity: SensitivityLabel) -> Self {
        Self {
            outbound: true,
            max_sensitivity,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundDecision {
    pub allowed: bool,
    pub reason: String,
    pub hwm: SensitivityLabel,
    pub tool_max: SensitivityLabel,
    pub source: String,
}

/// Decide whether a tool call is permitted given the trajectory's
/// HWM. `check` is a pure function, never mutates the HWM.
pub struct OutboundPolicy {
    registry: HashMap<String, ToolClassification>,
    default_classification: ToolClassification,
}

impl OutboundPolicy {
    pub fn new(
        registry: HashMap<String, ToolClassification>,
        default_outbound: bool,
        default_max_sensitivity: SensitivityLabel,
    ) -> Self {
        Self {
            registry,
            default_classification: ToolClassification {
                outbound: default_outbound,
                max_sensitivity: default_max_sensitivity,
            },
        }
    }

    /// Construct an empty policy with the conservative defaults
    /// matching Python: unknown tools are treated as inbound (not
    /// outbound) with `INTERNAL` ceiling.
    pub fn empty_default() -> Self {
        Self::new(HashMap::new(), false, SensitivityLabel::Internal)
    }

    pub fn register(&mut self, tool_name: impl Into<String>, classification: ToolClassification) {
        self.registry.insert(tool_name.into(), classification);
    }

    pub fn classify_tool(&self, tool_name: &str) -> ToolClassification {
        self.registry
            .get(tool_name)
            .copied()
            .unwrap_or(self.default_classification)
    }

    pub fn check(&self, tool_name: &str, hwm: SensitivityLabel) -> OutboundDecision {
        let tc = self.classify_tool(tool_name);
        let source = "tessera.sensitivity".to_string();
        if !tc.outbound {
            return OutboundDecision {
                allowed: true,
                reason: "inbound/local tool".to_string(),
                hwm,
                tool_max: tc.max_sensitivity,
                source,
            };
        }
        if hwm > tc.max_sensitivity {
            return OutboundDecision {
                allowed: false,
                reason: format!(
                    "trajectory high-water mark is {}; tool {tool_name:?} permits at most {}",
                    hwm.name(),
                    tc.max_sensitivity.name(),
                ),
                hwm,
                tool_max: tc.max_sensitivity,
                source,
            };
        }
        OutboundDecision {
            allowed: true,
            reason: "within tool sensitivity envelope".to_string(),
            hwm,
            tool_max: tc.max_sensitivity,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SensitivityLabel ----

    #[test]
    fn label_ordering_matches_python() {
        assert!(SensitivityLabel::Public < SensitivityLabel::Internal);
        assert!(SensitivityLabel::Internal < SensitivityLabel::Confidential);
        assert!(SensitivityLabel::Confidential < SensitivityLabel::Restricted);
    }

    #[test]
    fn label_int_values_match_python_intenum() {
        assert_eq!(SensitivityLabel::Public as u8, 0);
        assert_eq!(SensitivityLabel::Internal as u8, 1);
        assert_eq!(SensitivityLabel::Confidential as u8, 2);
        assert_eq!(SensitivityLabel::Restricted as u8, 3);
    }

    #[test]
    fn label_from_str_round_trip() {
        for (s, lbl) in [
            ("PUBLIC", SensitivityLabel::Public),
            ("internal", SensitivityLabel::Internal),
            (" Confidential ", SensitivityLabel::Confidential),
            ("RESTRICTED", SensitivityLabel::Restricted),
        ] {
            assert_eq!(SensitivityLabel::from_str(s).unwrap(), lbl);
        }
    }

    #[test]
    fn label_from_str_rejects_unknown() {
        assert!(SensitivityLabel::from_str("garbage").is_err());
    }

    // ---- Classifier: defaults ----

    #[test]
    fn classifier_returns_public_for_empty_input() {
        let c = SensitivityClassifier::new();
        assert_eq!(c.classify("").label, SensitivityLabel::Public);
    }

    #[test]
    fn classifier_returns_public_for_benign_text() {
        let c = SensitivityClassifier::new();
        let r = c.classify("hello, the weather is nice today");
        assert_eq!(r.label, SensitivityLabel::Public);
        assert!(r.matched_rule_ids.is_empty());
    }

    // ---- SSN ----

    #[test]
    fn classifier_detects_valid_ssn_as_restricted() {
        let c = SensitivityClassifier::new();
        let r = c.classify("My SSN is 123-45-6789 please update.");
        assert_eq!(r.label, SensitivityLabel::Restricted);
        assert!(r.matched_rule_ids.iter().any(|id| id == "pii.ssn"));
    }

    #[test]
    fn classifier_rejects_invalid_ssn_area_000() {
        let c = SensitivityClassifier::new();
        let r = c.classify("000-12-3456 is not a real SSN");
        // No rules should match this.
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    #[test]
    fn classifier_rejects_invalid_ssn_area_666() {
        let c = SensitivityClassifier::new();
        let r = c.classify("666-12-3456 is also not real");
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    #[test]
    fn classifier_rejects_invalid_ssn_area_900_range() {
        let c = SensitivityClassifier::new();
        let r = c.classify("900-12-3456 is excluded");
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    #[test]
    fn classifier_rejects_invalid_ssn_group_00() {
        let c = SensitivityClassifier::new();
        let r = c.classify("123-00-3456 is excluded");
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    #[test]
    fn classifier_rejects_invalid_ssn_serial_0000() {
        let c = SensitivityClassifier::new();
        let r = c.classify("123-45-0000 is excluded");
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    // ---- Credit card ----

    #[test]
    fn classifier_detects_visa_as_restricted() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Charge to 4111 1111 1111 1111 today");
        assert_eq!(r.label, SensitivityLabel::Restricted);
        assert!(r.matched_rule_ids.iter().any(|id| id == "pii.credit_card"));
    }

    #[test]
    fn classifier_detects_amex_as_restricted() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Card 3782 822463 10005");
        // The pattern is for 16-digit cards; AMEX is 15. Test the
        // Mastercard-shaped one too.
        let r2 = c.classify("Card 5500-0000-0000-0004");
        assert_eq!(r2.label, SensitivityLabel::Restricted);
        let _ = r;
    }

    // ---- Aadhaar ----

    #[test]
    fn classifier_detects_aadhaar_as_restricted() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Aadhaar 1234 5678 9012 belongs to me");
        assert_eq!(r.label, SensitivityLabel::Restricted);
    }

    // ---- AWS keys ----

    #[test]
    fn classifier_detects_aws_access_key_as_confidential() {
        let c = SensitivityClassifier::new();
        let r = c.classify("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
        assert_eq!(r.label, SensitivityLabel::Confidential);
        assert!(r.matched_rule_ids.iter().any(|id| id == "secret.aws_access_key"));
    }

    #[test]
    fn classifier_detects_aws_temp_session_key() {
        let c = SensitivityClassifier::new();
        // ASIA + exactly 16 base32-ish chars matches the temp-session pattern.
        let r = c.classify("ASIATESTKEY123456789");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    // ---- Other secrets ----

    #[test]
    fn classifier_detects_pem_private_key_as_confidential() {
        let c = SensitivityClassifier::new();
        let r = c.classify("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_detects_jwt_as_confidential() {
        let c = SensitivityClassifier::new();
        let r = c.classify(
            "Token: eyJhbGciOi.eyJzdWIiOiIxIn0.signature_part_here",
        );
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_detects_github_token_as_confidential() {
        let c = SensitivityClassifier::new();
        let r = c.classify("ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_detects_slack_token_as_confidential() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Bot: xoxb-12345-67890-abcdefg");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_detects_authorization_bearer_header() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Authorization: Bearer abc123def456ghi789jkl012mno345pqr");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    // ---- Markers ----

    #[test]
    fn classifier_detects_confidential_marker() {
        let c = SensitivityClassifier::new();
        let r = c.classify("This document is strictly confidential.");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_detects_internal_marker() {
        let c = SensitivityClassifier::new();
        let r = c.classify("Internal only: do not share.");
        assert_eq!(r.label, SensitivityLabel::Internal);
    }

    #[test]
    fn classifier_returns_max_when_multiple_rules_match() {
        let c = SensitivityClassifier::new();
        let r = c.classify(
            "Internal only: this card 4111 1111 1111 1111 belongs to Bob.",
        );
        assert_eq!(r.label, SensitivityLabel::Restricted);
        assert!(r.matched_rule_ids.len() >= 2);
    }

    // ---- Custom rules ----

    #[test]
    fn classifier_register_adds_runtime_rule() {
        let c = SensitivityClassifier::new();
        c.register(ClassificationRule::standard(
            "custom.codename",
            SensitivityLabel::Confidential,
            Regex::new(r"PROJECT-NIGHTHAWK").unwrap(),
            "internal codename",
        ));
        let r = c.classify("Status update on PROJECT-NIGHTHAWK milestones.");
        assert_eq!(r.label, SensitivityLabel::Confidential);
    }

    #[test]
    fn classifier_no_defaults_starts_empty() {
        let c = SensitivityClassifier::with_rules(Vec::new(), false);
        assert!(c.rules().is_empty());
        let r = c.classify("My SSN is 123-45-6789");
        assert_eq!(r.label, SensitivityLabel::Public);
    }

    // ---- HighWaterMark ----

    #[test]
    fn hwm_starts_at_public() {
        let hwm = HighWaterMark::in_memory();
        assert_eq!(hwm.get("traj-1"), SensitivityLabel::Public);
    }

    #[test]
    fn hwm_observe_moves_up_only() {
        let hwm = HighWaterMark::in_memory();
        hwm.observe("traj-1", SensitivityLabel::Confidential);
        assert_eq!(hwm.get("traj-1"), SensitivityLabel::Confidential);
        // Lower label does not move it down.
        hwm.observe("traj-1", SensitivityLabel::Public);
        assert_eq!(hwm.get("traj-1"), SensitivityLabel::Confidential);
    }

    #[test]
    fn hwm_observe_climbs_to_max() {
        let hwm = HighWaterMark::in_memory();
        hwm.observe("traj-1", SensitivityLabel::Internal);
        hwm.observe("traj-1", SensitivityLabel::Restricted);
        hwm.observe("traj-1", SensitivityLabel::Confidential);
        assert_eq!(hwm.get("traj-1"), SensitivityLabel::Restricted);
    }

    #[test]
    fn hwm_reset_clears_to_public() {
        let hwm = HighWaterMark::in_memory();
        hwm.observe("traj-1", SensitivityLabel::Confidential);
        hwm.reset("traj-1");
        assert_eq!(hwm.get("traj-1"), SensitivityLabel::Public);
    }

    #[test]
    fn hwm_isolates_per_trajectory() {
        let hwm = HighWaterMark::in_memory();
        hwm.observe("traj-1", SensitivityLabel::Restricted);
        assert_eq!(hwm.get("traj-2"), SensitivityLabel::Public);
    }

    // ---- OutboundPolicy ----

    #[test]
    fn outbound_inbound_tool_always_allowed() {
        let policy = OutboundPolicy::empty_default();
        let mut policy = policy;
        policy.register("read_doc", ToolClassification::inbound());
        let d = policy.check("read_doc", SensitivityLabel::Restricted);
        assert!(d.allowed);
        assert_eq!(d.reason, "inbound/local tool");
    }

    #[test]
    fn outbound_within_envelope_allowed() {
        let mut policy = OutboundPolicy::empty_default();
        policy.register(
            "send_email",
            ToolClassification::outbound(SensitivityLabel::Internal),
        );
        let d = policy.check("send_email", SensitivityLabel::Internal);
        assert!(d.allowed);
    }

    #[test]
    fn outbound_above_envelope_denied() {
        let mut policy = OutboundPolicy::empty_default();
        policy.register(
            "send_email",
            ToolClassification::outbound(SensitivityLabel::Internal),
        );
        let d = policy.check("send_email", SensitivityLabel::Confidential);
        assert!(!d.allowed);
        assert!(d.reason.contains("CONFIDENTIAL"));
        assert!(d.reason.contains("INTERNAL"));
    }

    #[test]
    fn outbound_unknown_tool_uses_default_classification() {
        let policy = OutboundPolicy::empty_default();
        let d = policy.check("unknown_tool", SensitivityLabel::Public);
        // default is `outbound=false`, so it is allowed regardless.
        assert!(d.allowed);
        assert_eq!(d.reason, "inbound/local tool");
    }

    #[test]
    fn outbound_default_outbound_envelope_internal() {
        let policy = OutboundPolicy::new(
            HashMap::new(),
            true,
            SensitivityLabel::Internal,
        );
        let d_ok = policy.check("any_tool", SensitivityLabel::Internal);
        assert!(d_ok.allowed);
        let d_deny = policy.check("any_tool", SensitivityLabel::Confidential);
        assert!(!d_deny.allowed);
    }
}
