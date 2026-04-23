//! Tessera scanners (Phase 2).
//!
//! Each module mirrors a `tessera.scanners.*` module from the Python
//! reference. Wire formats (canary tokens) match Python byte-for-byte
//! so a scanner result produced by Rust verifies in Python and vice
//! versa.
//!
//! Scanners are independent functions, not methods on a trait: the
//! input shape varies (string, JSON value, tool list, ...) and a
//! single trait would not pay for itself in Rust the way the Python
//! Protocol does. The `Scanner` marker trait below exists for the
//! few callers that want to hold a heterogeneous list of scanners,
//! but most code calls `scan_*` functions directly.
//!
//! Phase 2 deliverables in this crate:
//! - `unicode`: hidden Unicode tag block (U+E0000..U+E007F) detection
//! - `tool_shadow`: Levenshtein-based confusable tool-name detection
//! - `directive`: imperative-mood prompt-injection patterns
//! - `heuristic`: cartesian-product injection scoring
//! - `intent`: cross-checked intent vs user prompt
//! - `tool_descriptions`: malicious-pattern scanning of MCP tool descriptions
//! - `tool_output_schema`: glob-based tool output schema enforcement
//! - `prompt_screen`: composes heuristic + directive + unicode
//! - `canary`: HMAC-bound canary tokens (cross-language interop)

pub mod binary_content;
pub mod canary;
pub mod directive;
pub mod heuristic;
pub mod intent;
pub mod pii;
pub mod prompt_screen;
pub mod rag;
pub mod supply_chain;
pub mod tool_descriptions;
pub mod tool_output_schema;
pub mod tool_shadow;
pub mod unicode;

/// Marker trait for scanner result types. Implementations carry the
/// detection flag and a scanner-specific detail payload via
/// `serde::Serialize` so callers can ship the result to a SIEM or
/// SecurityEvent without knowing the concrete type.
pub trait ScannerResult: serde::Serialize {
    fn detected(&self) -> bool;
    fn scanner_name(&self) -> &'static str;
}

/// Severity tier for findings emitted by structured scanners
/// (supply_chain, codeshield, ...). Mirrors the Python `Severity`
/// `Literal` and the `_SEVERITY_RANK` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

pub fn severity_rank(s: Severity) -> u8 {
    s.rank()
}

/// One finding from a scanner run. Mirrors Python `ScanFinding`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(default)]
    pub arg_path: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Result of a single scanner run. Mirrors Python `ScanResult`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub scanner: String,
    pub allowed: bool,
    #[serde(default)]
    pub findings: Vec<ScanFinding>,
}

impl ScanResult {
    pub fn max_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn primary_reason(&self) -> String {
        if self.allowed || self.findings.is_empty() {
            return String::new();
        }
        let top = self
            .findings
            .iter()
            .max_by_key(|f| f.severity.rank())
            .expect("non-empty findings");
        format!("{}: {}", top.rule_id, top.message)
    }
}

/// Merge multiple scan results into one. Allowed iff all are allowed.
pub fn combine(results: impl IntoIterator<Item = ScanResult>) -> ScanResult {
    let collected: Vec<ScanResult> = results.into_iter().collect();
    if collected.is_empty() {
        return ScanResult {
            scanner: "combined".to_string(),
            allowed: true,
            findings: Vec::new(),
        };
    }
    let allowed = collected.iter().all(|r| r.allowed);
    let findings: Vec<ScanFinding> = collected.into_iter().flat_map(|r| r.findings).collect();
    ScanResult {
        scanner: "combined".to_string(),
        allowed,
        findings,
    }
}
