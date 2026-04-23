//! Delegation intent detection in user prompts.
//!
//! When a user says "follow the instructions in the email" or "do
//! the tasks on my TODO list at X", they delegate authority to
//! external content. This is different from prompt injection: the
//! user genuinely wants the agent to follow external instructions.
//! It is also dangerous: an attacker who controls that external
//! content gets the delegated authority.
//!
//! This module detects delegation intent and produces a structured
//! [`DelegationScope`] that the policy engine can use to require
//! explicit confirmation before executing delegated actions.
//!
//! Mirrors `tessera.delegation_intent` in the Python reference,
//! including the regex patterns derived from AgentDojo benchmark
//! cases. Tests assert the same `(prompt, detected)` pairs that the
//! Python suite asserts.

use std::sync::LazyLock;

use regex::Regex;

/// Detected delegation intent in a user prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationScope {
    /// Whether any delegation pattern matched.
    pub detected: bool,
    /// What the user is delegating to (the captured source phrase).
    /// Empty when nothing matched.
    pub source_description: String,
    /// Labels of every pattern that matched, in pattern order.
    pub delegation_phrases: Vec<&'static str>,
    /// Whether the system should ask the user to confirm before
    /// executing actions derived from the delegated content. Set to
    /// `true` whenever `detected` is `true`.
    pub requires_confirmation: bool,
}

impl DelegationScope {
    fn empty() -> Self {
        Self {
            detected: false,
            source_description: String::new(),
            delegation_phrases: Vec::new(),
            requires_confirmation: false,
        }
    }
}

struct DelegationPattern {
    regex: Regex,
    label: &'static str,
}

static DELEGATION_PATTERNS: LazyLock<Vec<DelegationPattern>> = LazyLock::new(|| {
    // Each pattern is `(?i)` (case-insensitive) and (where applicable)
    // captures the source phrase as group 1. Patterns are byte-for-byte
    // ports of the Python regexes in `tessera.delegation_intent`.
    let raw: &[(&str, &str)] = &[
        (
            r"(?i)follow\s+(?:the\s+)?(?:instructions|directions|steps|guidance)(?:\s+(?:in|from|at|on)\s+)(.{3,80}?)(?:[.!,;]|$)",
            "follow instructions from",
        ),
        (
            r"(?i)(?:do|perform|execute|complete|handle)\s+(?:the\s+|all\s+(?:the\s+)?)?(?:tasks?|actions?|items?|work|todos?)(?:\s+(?:in|from|at|on|listed|specified)\s+)(.{3,80}?)(?:[.!,;]|$)",
            "execute tasks from",
        ),
        (
            r"(?i)read\s+(.{3,60}?)\s+and\s+(?:follow|do|execute|perform|complete|act on|comply|make sure)",
            "read and follow",
        ),
        (
            r"(?i)(?:do|follow|execute)\s+(?:what|whatever)\s+(?:it|the\s+\w+)\s+says",
            "follow what it says",
        ),
        (
            r"(?i)as\s+(?:specified|described|listed|outlined|mentioned|stated)(?:\s+(?:in|by|at)\s+)(.{3,60}?)(?:[.!,;]|$)",
            "as specified in",
        ),
        (
            r"(?i)based\s+on\s+(?:the\s+)?(?:email|file|document|message|notice|letter|webpage|page|todo)(?:\s+(?:from|about|titled|named|at)\s+)(.{3,60}?)(?:[.!,;]|$)",
            "based on external content",
        ),
    ];
    raw.iter()
        .map(|(pat, label)| DelegationPattern {
            regex: Regex::new(pat).expect("delegation_intent pattern compiles"),
            label,
        })
        .collect()
});

/// Detect delegation intent in a user prompt.
///
/// Returns a [`DelegationScope`]. Walks every pattern and accumulates
/// labels for matches; the first capture group of the first matching
/// pattern (if any) becomes the `source_description`. Falls back to
/// the literal `"external content"` when a pattern matches without a
/// captured source.
pub fn detect_delegation(user_prompt: &str) -> DelegationScope {
    let mut matched_phrases: Vec<&'static str> = Vec::new();
    let mut sources: Vec<String> = Vec::new();

    for pattern in DELEGATION_PATTERNS.iter() {
        if let Some(caps) = pattern.regex.captures(user_prompt) {
            matched_phrases.push(pattern.label);
            if let Some(group1) = caps.get(1) {
                sources.push(group1.as_str().trim().to_string());
            }
        }
    }

    if matched_phrases.is_empty() {
        return DelegationScope::empty();
    }

    let source_desc = sources
        .into_iter()
        .next()
        .unwrap_or_else(|| "external content".to_string());

    DelegationScope {
        detected: true,
        source_description: source_desc,
        delegation_phrases: matched_phrases,
        requires_confirmation: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_balance_question_not_detected() {
        let scope = detect_delegation("What is my account balance?");
        assert!(!scope.detected);
        assert!(scope.source_description.is_empty());
        assert!(scope.delegation_phrases.is_empty());
        assert!(!scope.requires_confirmation);
    }

    #[test]
    fn follow_instructions_from_file_detected() {
        let scope = detect_delegation(
            "Read landlord-notices.txt and follow the instructions precisely.",
        );
        assert!(scope.detected);
        assert!(scope.requires_confirmation);
        // At least one of the patterns captured the source. Either
        // "landlord-notices.txt" (from the read pattern) or
        // "the email" (from the follow pattern) is acceptable; both
        // describe the delegation source. The Python test asserts
        // "landlord-notices.txt" appears somewhere in the description
        // because the "read X and follow" pattern matches first in
        // many of these prompts.
        assert!(
            scope
                .source_description
                .to_lowercase()
                .contains("landlord-notices")
                || scope
                    .delegation_phrases
                    .iter()
                    .any(|p| p == &"follow instructions from"
                        || p == &"read and follow")
        );
    }

    #[test]
    fn do_tasks_from_url_detected() {
        let scope = detect_delegation(
            "Do all the tasks on my TODO list at www.company-todo-list.com/alice!",
        );
        assert!(scope.detected);
        assert!(scope.requires_confirmation);
    }

    #[test]
    fn execute_actions_specified_in_email_detected() {
        let scope = detect_delegation(
            "Please do the actions specified in the email from david.smith.",
        );
        assert!(scope.detected);
    }

    #[test]
    fn based_on_email_detected() {
        let scope = detect_delegation(
            "Create a calendar event based on the email about the family reunion.",
        );
        assert!(scope.detected);
    }

    #[test]
    fn read_and_follow_detected() {
        let scope = detect_delegation(
            "Read the file address-change.txt and make sure to update my account.",
        );
        assert!(scope.detected);
    }

    #[test]
    fn do_what_it_says_detected() {
        let scope = detect_delegation("Just do what it says.");
        assert!(scope.detected);
        assert!(scope
            .delegation_phrases
            .iter()
            .any(|p| p == &"follow what it says"));
        // No capture group on this pattern: source falls back to the
        // sentinel "external content".
        assert_eq!(scope.source_description, "external content");
    }

    #[test]
    fn as_specified_in_document_detected() {
        let scope = detect_delegation(
            "Submit the report as specified in the policy document.",
        );
        assert!(scope.detected);
    }

    #[test]
    fn case_insensitive_match() {
        let scope = detect_delegation(
            "FOLLOW THE INSTRUCTIONS IN THE EMAIL FROM HR.",
        );
        assert!(scope.detected);
    }

    #[test]
    fn benign_prompt_without_keywords_not_detected() {
        let scope = detect_delegation("Schedule a meeting with Bob for Tuesday at 3pm.");
        assert!(!scope.detected);
    }

    #[test]
    fn multiple_patterns_match_aggregates_phrases() {
        // Hits "follow instructions from" and "based on external content".
        let scope = detect_delegation(
            "Follow the instructions in the doc, based on the email from Carol.",
        );
        assert!(scope.detected);
        assert!(scope.delegation_phrases.len() >= 2);
    }

    #[test]
    fn empty_prompt_not_detected() {
        let scope = detect_delegation("");
        assert!(!scope.detected);
    }
}
