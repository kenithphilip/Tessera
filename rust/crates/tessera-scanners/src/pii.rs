//! PII entity detection for context segments.
//!
//! Scans text for personally identifiable information using pattern-based
//! entity recognition. Mirrors `tessera.scanners.pii` in the Python reference,
//! regex-only path.
//!
//! Presidio backend gap: the Python `PIIScanner` optionally delegates to
//! Microsoft Presidio (`presidio-analyzer`) when the package is installed.
//! That backend is not ported here. This module provides only the built-in
//! regex path. A future phase can add a Presidio gRPC client or equivalent
//! if higher-accuracy detection is needed.
//!
//! Pattern adaptation note: Rust `regex` does not support lookahead or
//! lookbehind. The Python patterns did not use any; all seven patterns ported
//! verbatim with minor whitespace normalization.
//!
//! Source attribution: OWASP LLM02 (Sensitive Information Disclosure).

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ScannerResult;

// ---- Pattern table ----------------------------------------------------------
//
// Each entry is (entity_type, pattern, score).
// Scores mirror the Python reference exactly.

static BUILTIN_PATTERNS: LazyLock<Vec<(&'static str, Regex, f32)>> = LazyLock::new(|| {
    let raw: &[(&str, &str, f32)] = &[
        (
            "EMAIL",
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            0.9,
        ),
        (
            "PHONE",
            r"\b(?:\+?1[.\-\s]?)?\(?\d{3}\)?[.\-\s]?\d{3}[.\-\s]?\d{4}\b",
            0.7,
        ),
        ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", 0.95),
        (
            "CREDIT_CARD",
            r"\b(?:\d{4}[\-\s]?){3}\d{4}\b",
            0.8,
        ),
        (
            "IP_ADDRESS",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            0.6,
        ),
        ("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b", 0.95),
        (
            "GITHUB_TOKEN",
            r"\bgh[ps]_[A-Za-z0-9_]{36,}\b",
            0.95,
        ),
    ];
    raw.iter()
        .map(|(name, pat, score)| {
            (
                *name,
                Regex::new(pat).expect("PII pattern compiles"),
                *score,
            )
        })
        .collect()
});

const REDACTION_TEMPLATE_OPEN: &str = "<";
const REDACTION_TEMPLATE_CLOSE: &str = ">";

// ---- Public types -----------------------------------------------------------

/// A single detected PII entity in a text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PiiEntity {
    /// Entity category: EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS,
    /// AWS_KEY, or GITHUB_TOKEN.
    pub entity_type: String,
    /// Byte offset of the first character in the original text.
    pub start: usize,
    /// Byte offset one past the last character in the original text.
    pub end: usize,
    /// Confidence score in [0.0, 1.0].
    pub score: f32,
    /// The matched text span.
    pub text: String,
}

/// Result of a full PII scan over a text string.
///
/// `detected` is true when at least one entity passes the score threshold.
/// `entities` contains all passing entities sorted by `start` offset.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PiiScanResult {
    pub detected: bool,
    pub entities: Vec<PiiEntity>,
}

impl ScannerResult for PiiScanResult {
    fn detected(&self) -> bool {
        self.detected
    }
    fn scanner_name(&self) -> &'static str {
        "pii"
    }
}

// ---- Public functions -------------------------------------------------------

/// Scan `text` for PII entities using built-in regex patterns.
///
/// `entity_types`: if `Some`, restrict to the listed types. `None` matches all.
/// `score_threshold`: entities with a score below this value are suppressed.
///   Default in the Python reference is 0.5.
///
/// Returns a [`PiiScanResult`] with all passing entities sorted by start offset.
pub fn scan_pii(
    text: &str,
    entity_types: Option<&[&str]>,
    score_threshold: f32,
) -> PiiScanResult {
    let mut entities: Vec<PiiEntity> = Vec::new();

    for (entity_type, pattern, score) in BUILTIN_PATTERNS.iter() {
        if let Some(allowed) = entity_types {
            if !allowed.contains(entity_type) {
                continue;
            }
        }
        if *score < score_threshold {
            continue;
        }
        for m in pattern.find_iter(text) {
            entities.push(PiiEntity {
                entity_type: entity_type.to_string(),
                start: m.start(),
                end: m.end(),
                score: *score,
                text: m.as_str().to_string(),
            });
        }
    }

    entities.sort_by_key(|e| e.start);
    let detected = !entities.is_empty();
    PiiScanResult { detected, entities }
}

/// Scan `text` and replace every detected PII entity with a placeholder of
/// the form `<ENTITY_TYPE>`. Entities are replaced from end to start so that
/// byte offsets remain valid throughout the pass.
///
/// `entity_types` and `score_threshold` are forwarded to [`scan_pii`].
pub fn redact_pii(
    text: &str,
    entity_types: Option<&[&str]>,
    score_threshold: f32,
) -> String {
    let result = scan_pii(text, entity_types, score_threshold);
    if !result.detected {
        return text.to_string();
    }

    let mut out = text.to_string();
    // Reverse order so earlier offsets stay valid.
    let mut sorted = result.entities.clone();
    sorted.sort_by(|a, b| b.start.cmp(&a.start));

    for entity in sorted {
        let placeholder = format!(
            "{}{}{}",
            REDACTION_TEMPLATE_OPEN, entity.entity_type, REDACTION_TEMPLATE_CLOSE
        );
        out.replace_range(entity.start..entity.end, &placeholder);
    }
    out
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_THRESHOLD: f32 = 0.5;

    fn scan(text: &str) -> PiiScanResult {
        scan_pii(text, None, DEFAULT_THRESHOLD)
    }

    fn redact(text: &str) -> String {
        redact_pii(text, None, DEFAULT_THRESHOLD)
    }

    // ---- Detection tests ------------------------------------------------

    #[test]
    fn detect_email() {
        let r = scan("Contact alice@example.com for details");
        assert!(r.detected);
        let e = r.entities.iter().find(|e| e.entity_type == "EMAIL").unwrap();
        assert_eq!(e.text, "alice@example.com");
    }

    #[test]
    fn detect_phone() {
        let r = scan("Call me at 555-123-4567");
        assert!(r.detected);
        assert!(r.entities.iter().any(|e| e.entity_type == "PHONE"));
    }

    #[test]
    fn detect_ssn() {
        let r = scan("SSN: 123-45-6789");
        assert!(r.detected);
        let e = r.entities.iter().find(|e| e.entity_type == "SSN").unwrap();
        assert_eq!(e.text, "123-45-6789");
    }

    #[test]
    fn detect_credit_card() {
        let r = scan("Card: 4111 1111 1111 1111");
        assert!(r.detected);
        assert!(r.entities.iter().any(|e| e.entity_type == "CREDIT_CARD"));
    }

    #[test]
    fn detect_aws_key() {
        let r = scan("key: AKIAIOSFODNN7EXAMPLE");
        assert!(r.detected);
        assert!(r.entities.iter().any(|e| e.entity_type == "AWS_KEY"));
    }

    #[test]
    fn detect_github_token() {
        let r = scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(r.detected);
        assert!(r.entities.iter().any(|e| e.entity_type == "GITHUB_TOKEN"));
    }

    #[test]
    fn no_pii_in_clean_text() {
        let r = scan("The quarterly report shows 15% growth");
        assert!(!r.detected);
        assert!(r.entities.is_empty());
    }

    #[test]
    fn multiple_entities_detected() {
        let r = scan("Email alice@example.com or call 555-123-4567");
        assert!(r.entities.len() >= 2);
    }

    #[test]
    fn entities_sorted_by_position() {
        let r = scan("Call 555-123-4567 or email alice@example.com");
        assert!(r.entities.len() >= 2);
        for w in r.entities.windows(2) {
            assert!(w[0].start <= w[1].start, "entities not sorted by start");
        }
    }

    // ---- Redaction tests ------------------------------------------------

    #[test]
    fn redact_replaces_email() {
        let out = redact("Email alice@example.com for info");
        assert!(out.contains("<EMAIL>"), "got: {out}");
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn redact_preserves_non_pii() {
        let text = "No PII here, just normal text";
        assert_eq!(redact(text), text);
    }

    #[test]
    fn redact_multiple_entities() {
        let out = redact("SSN: 123-45-6789, email: bob@test.org");
        assert!(out.contains("<SSN>"), "got: {out}");
        assert!(out.contains("<EMAIL>"), "got: {out}");
        assert!(!out.contains("123-45-6789"));
        assert!(!out.contains("bob@test.org"));
    }

    // ---- Filter tests ---------------------------------------------------

    #[test]
    fn filter_by_entity_type() {
        let r = scan_pii(
            "Email alice@example.com, SSN 123-45-6789",
            Some(&["EMAIL"]),
            DEFAULT_THRESHOLD,
        );
        assert!(r.entities.iter().all(|e| e.entity_type == "EMAIL"));
        assert!(!r.entities.iter().any(|e| e.entity_type == "SSN"));
    }

    #[test]
    fn score_threshold_filters_ip_address() {
        // IP_ADDRESS score is 0.6; threshold 0.9 must suppress it.
        let r = scan_pii("Server at 192.168.1.1", None, 0.9);
        assert!(!r.entities.iter().any(|e| e.entity_type == "IP_ADDRESS"));
    }

    // ---- Trait and serde tests ------------------------------------------

    #[test]
    fn scanner_result_trait_methods() {
        let r = scan("hello world");
        assert_eq!(ScannerResult::scanner_name(&r), "pii");
        assert!(!ScannerResult::detected(&r));
    }

    #[test]
    fn serialize_round_trip() {
        let r = scan("Contact alice@example.com or 123-45-6789");
        let json = serde_json::to_string(&r).unwrap();
        let back: PiiScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
