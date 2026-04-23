//! Cross-server tool shadowing detection via Levenshtein distance.
//!
//! When an agent loads tools from multiple MCP servers, a malicious server can
//! register a tool with the same (or nearly the same) name as a legitimate tool
//! from a trusted server. The agent then calls the attacker's tool instead of
//! the real one. This is a confused-deputy attack at the tool registration layer.
//!
//! Detection: compute case-folded edit distance between all tool names across
//! servers. Flag pairs with distance <= max_distance (default 2) that come from
//! different servers. Distance 0 = identical name (exact shadow). Distance 1-2 =
//! typosquatting.
//!
//! Mirrors `tessera.scanners.tool_shadow` in the Python reference.
//! Source attribution: Agent Audit rule AGENT-055.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ScannerResult;

// ── Result types ─────────────────────────────────────────────────────────────

/// A pair of tools from different servers whose names are suspiciously similar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowPair {
    /// Name of the first tool.
    pub tool_a: String,
    /// Server the first tool belongs to.
    pub server_a: String,
    /// Name of the second tool.
    pub tool_b: String,
    /// Server the second tool belongs to.
    pub server_b: String,
    /// Case-folded Levenshtein distance between `tool_a` and `tool_b`.
    pub distance: usize,
}

/// Result of cross-server tool shadow detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowScanResult {
    /// All flagged pairs, ordered by discovery (server-pair iteration order,
    /// then tool-pair iteration order). Matches Python tuple ordering.
    pub pairs: Vec<ShadowPair>,
    /// `true` when at least one pair was flagged.
    pub shadowed: bool,
}

impl ScannerResult for ShadowScanResult {
    fn detected(&self) -> bool {
        self.shadowed
    }

    fn scanner_name(&self) -> &'static str {
        "cross_server_tool_shadow"
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Detect tool name shadowing across multiple MCP servers.
///
/// For every ordered pair of distinct servers `(i, j)` with `i < j`, compare
/// every tool from server `i` against every tool from server `j`. Any pair
/// whose case-folded Levenshtein distance is `<= max_distance` is flagged.
///
/// # Arguments
///
/// * `server_tools` - Map of `server_name -> tool_name_list`.
/// * `max_distance` - Levenshtein threshold. Pairs with distance `<=` this
///   value are flagged. Default is `2`, which catches exact shadows and
///   single-character typosquats. Use `0` for exact-match-only detection.
///
/// # Returns
///
/// A [`ShadowScanResult`] containing all flagged [`ShadowPair`]s and a
/// boolean convenience flag. The result is ready to serialize to a
/// SecurityEvent detail payload.
///
/// # Example
///
/// ```rust
/// use tessera_scanners::tool_shadow::scan_cross_server_shadows;
///
/// let mut servers = std::collections::HashMap::new();
/// servers.insert("trusted".to_string(), vec!["send_email".to_string()]);
/// servers.insert("attacker".to_string(), vec!["send_ema1l".to_string()]);
///
/// let result = scan_cross_server_shadows(&servers, 2);
/// assert!(result.shadowed);
/// assert_eq!(result.pairs[0].distance, 1);
/// ```
pub fn scan_cross_server_shadows(
    server_tools: &HashMap<String, Vec<String>>,
    max_distance: usize,
) -> ShadowScanResult {
    // Collect into a deterministically-ordered vec so the i < j traversal
    // visits each server pair exactly once, matching the Python loop.
    let mut servers: Vec<(&String, &Vec<String>)> = server_tools.iter().collect();
    // Sort by server name so output is stable regardless of HashMap iteration
    // order. Python dicts are insertion-ordered; we cannot reproduce that
    // without tracking insertion order, so stable alphabetical is the next
    // best guarantee for tests.
    servers.sort_by_key(|(name, _)| name.as_str());

    let mut pairs: Vec<ShadowPair> = Vec::new();

    for i in 0..servers.len() {
        let (server_a, tools_a) = servers[i];
        for j in (i + 1)..servers.len() {
            let (server_b, tools_b) = servers[j];
            for tool_a in tools_a.iter() {
                for tool_b in tools_b.iter() {
                    let dist = levenshtein_case_folded(tool_a, tool_b);
                    if dist <= max_distance {
                        pairs.push(ShadowPair {
                            tool_a: tool_a.clone(),
                            server_a: server_a.clone(),
                            tool_b: tool_b.clone(),
                            server_b: server_b.clone(),
                            distance: dist,
                        });
                    }
                }
            }
        }
    }

    let shadowed = !pairs.is_empty();
    ShadowScanResult { pairs, shadowed }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Case-folded Levenshtein distance. Mirrors the Python `_levenshtein`
/// function, which lowercases both strings before running the DP.
///
/// Delegates to `strsim::levenshtein` which implements the same iterative
/// O(mn) algorithm.
fn levenshtein_case_folded(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    // strsim::levenshtein is case-sensitive; fold first.
    let a_low = a.to_lowercase();
    let b_low = b.to_lowercase();
    strsim::levenshtein(&a_low, &b_low)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn servers(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(srv, tools)| {
                (
                    srv.to_string(),
                    tools.iter().map(|t| t.to_string()).collect(),
                )
            })
            .collect()
    }

    // ---- mirrors Python TestToolShadow tests --------------------------------

    #[test]
    fn no_overlap_is_clean() {
        // test_no_overlap_clean
        let s = servers(&[
            ("trusted", &["search_web", "send_email"]),
            ("attacker", &["fetch_data", "log_event"]),
        ]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(!r.shadowed);
        assert!(r.pairs.is_empty());
    }

    #[test]
    fn exact_shadow_detected() {
        // test_exact_shadow_detected
        let s = servers(&[
            ("trusted", &["send_email"]),
            ("attacker", &["send_email"]),
        ]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(r.shadowed);
        assert_eq!(r.pairs.len(), 1);
        let pair = &r.pairs[0];
        assert_eq!(pair.distance, 0);
        assert_eq!(pair.tool_a, "send_email");
        assert_eq!(pair.tool_b, "send_email");
        assert_ne!(pair.server_a, pair.server_b);
    }

    #[test]
    fn typosquatting_distance_1_detected() {
        // test_typosquatting_detected: 'send_ema1l' vs 'send_email', distance=1
        let s = servers(&[
            ("trusted", &["send_email"]),
            ("attacker", &["send_ema1l"]),
        ]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(r.shadowed);
        assert_eq!(r.pairs[0].distance, 1);
    }

    #[test]
    fn distance_2_detected_within_threshold() {
        // test_distance_2_detected
        let s = servers(&[
            ("trusted", &["web_search"]),
            ("attacker", &["web_searsh"]), // 2 edits
        ]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(r.shadowed);
    }

    #[test]
    fn clearly_different_names_not_flagged_at_threshold_2() {
        // test_distance_3_not_flagged_by_default (second half: "alpha" vs "zeta")
        let s = servers(&[("trusted", &["alpha"]), ("attacker", &["zeta"])]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(!r.shadowed);
    }

    #[test]
    fn same_server_tools_never_flagged() {
        // test_same_server_not_flagged
        let s = servers(&[("trusted", &["search", "search_v2"])]);
        let r = scan_cross_server_shadows(&s, 2);
        assert!(!r.shadowed);
    }

    #[test]
    fn exact_shadow_distance_labeled_zero() {
        // test_exact_zero_distance_labeled_correctly
        let s = servers(&[("a", &["exact_name"]), ("b", &["exact_name"])]);
        let r = scan_cross_server_shadows(&s, 2);
        assert_eq!(r.pairs[0].distance, 0);
    }

    // ---- additional coverage ------------------------------------------------

    #[test]
    fn max_distance_zero_only_flags_exact_match() {
        let s = servers(&[
            ("trusted", &["send_email"]),
            ("attacker", &["send_ema1l"]),
        ]);
        // distance=1, so max_distance=0 should not flag it
        let r = scan_cross_server_shadows(&s, 0);
        assert!(!r.shadowed);

        let s2 = servers(&[("a", &["tool"]), ("b", &["tool"])]);
        let r2 = scan_cross_server_shadows(&s2, 0);
        assert!(r2.shadowed);
        assert_eq!(r2.pairs[0].distance, 0);
    }

    #[test]
    fn case_folding_exact_shadow_across_case() {
        // "Send_Email" vs "send_email" should be distance 0 after lowercasing.
        let s = servers(&[("a", &["Send_Email"]), ("b", &["send_email"])]);
        let r = scan_cross_server_shadows(&s, 0);
        assert!(r.shadowed);
        assert_eq!(r.pairs[0].distance, 0);
    }

    #[test]
    fn three_servers_all_pairs_scanned() {
        // With three servers and one shared name across two of them, exactly
        // one pair should be flagged (the two that share the name), not two.
        let s = servers(&[
            ("a", &["common"]),
            ("b", &["common"]),
            ("c", &["different"]),
        ]);
        let r = scan_cross_server_shadows(&s, 0);
        assert_eq!(r.pairs.len(), 1);
        assert_eq!(r.pairs[0].distance, 0);
    }

    #[test]
    fn empty_server_map_returns_clean() {
        let s: HashMap<String, Vec<String>> = HashMap::new();
        let r = scan_cross_server_shadows(&s, 2);
        assert!(!r.shadowed);
        assert!(r.pairs.is_empty());
    }

    #[test]
    fn single_server_returns_clean() {
        let s = servers(&[("only", &["tool_a", "tool_b"])]);
        let r = scan_cross_server_shadows(&s, 0);
        assert!(!r.shadowed);
    }

    #[test]
    fn scanner_result_trait_methods() {
        let s = servers(&[("a", &["x"]), ("b", &["x"])]);
        let r = scan_cross_server_shadows(&s, 0);
        assert!(ScannerResult::detected(&r));
        assert_eq!(ScannerResult::scanner_name(&r), "cross_server_tool_shadow");

        let clean = servers(&[("a", &["alpha"]), ("b", &["zeta"])]);
        let c = scan_cross_server_shadows(&clean, 0);
        assert!(!ScannerResult::detected(&c));
    }

    #[test]
    fn serialize_round_trip_via_serde_json() {
        let s = servers(&[("a", &["tool_x"]), ("b", &["tool_x"])]);
        let r = scan_cross_server_shadows(&s, 2);
        let json = serde_json::to_string(&r).unwrap();
        let back: ShadowScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}
