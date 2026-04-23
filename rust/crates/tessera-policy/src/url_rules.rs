//! Static URL pattern rules: a fast deterministic gate before any LLM
//! judge or DNS-resolving SSRF check.
//!
//! Mirrors `tessera.url_rules` from the Python reference. Three pattern
//! shapes evaluated in tier order (`exact > prefix > glob`); within each
//! tier, deny-wins-over-allow. A NO_MATCH falls through to the slower
//! checks (SSRF, scanners). Optional method allowlist per rule.

use serde::{Deserialize, Serialize};

/// What a rule does on hit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// How to interpret the rule's pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternKind {
    Exact,
    Prefix,
    Glob,
}

/// The engine's decision on a single URL+method check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    Allow,
    Deny,
    NoMatch,
}

/// One static URL rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlRule {
    pub rule_id: String,
    pub pattern: String,
    #[serde(default = "default_kind")]
    pub kind: PatternKind,
    #[serde(default = "default_action")]
    pub action: RuleAction,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub description: String,
}

fn default_kind() -> PatternKind {
    PatternKind::Exact
}
fn default_action() -> RuleAction {
    RuleAction::Allow
}

impl UrlRule {
    pub fn new(rule_id: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            pattern: pattern.into(),
            kind: PatternKind::Exact,
            action: RuleAction::Allow,
            methods: None,
            description: String::new(),
        }
    }

    pub fn kind(mut self, kind: PatternKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn action(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }

    pub fn methods(mut self, methods: Vec<String>) -> Self {
        self.methods = Some(methods.into_iter().map(|m| m.to_uppercase()).collect());
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    fn matches_method(&self, method: &str) -> bool {
        match &self.methods {
            None => true,
            Some(allow) => allow.iter().any(|m| m == &method.to_uppercase()),
        }
    }

    fn matches_url(&self, url: &str) -> bool {
        match self.kind {
            PatternKind::Exact => url == self.pattern,
            PatternKind::Prefix => url.starts_with(&self.pattern),
            PatternKind::Glob => {
                // Use the `glob` crate's Pattern matcher. fnmatch-style
                // `*` and `?` are the most common operator-friendly
                // shapes; the crate also supports `[...]` character
                // classes which is harmless to allow.
                match glob::Pattern::new(&self.pattern) {
                    Ok(p) => p.matches(url),
                    Err(_) => false,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlDecision {
    pub verdict: RuleVerdict,
    pub rule_id: String,
    pub description: String,
    pub method: String,
    pub url: String,
}

impl UrlDecision {
    pub fn no_match(url: &str, method: &str) -> Self {
        Self {
            verdict: RuleVerdict::NoMatch,
            rule_id: String::new(),
            description: String::new(),
            method: method.to_uppercase(),
            url: url.to_string(),
        }
    }

    pub fn allowed(&self) -> bool {
        matches!(self.verdict, RuleVerdict::Allow)
    }
}

/// URL rules engine. Build with [`UrlRulesEngine::new`] and call
/// [`UrlRulesEngine::evaluate`] per request.
#[derive(Clone, Debug)]
pub struct UrlRulesEngine {
    exact: Vec<UrlRule>,
    prefix: Vec<UrlRule>,
    glob: Vec<UrlRule>,
}

impl Default for UrlRulesEngine {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl UrlRulesEngine {
    pub fn new<I: IntoIterator<Item = UrlRule>>(rules: I) -> Self {
        let mut engine = Self {
            exact: Vec::new(),
            prefix: Vec::new(),
            glob: Vec::new(),
        };
        for rule in rules {
            engine.add(rule);
        }
        engine
    }

    pub fn add(&mut self, rule: UrlRule) {
        match rule.kind {
            PatternKind::Exact => self.exact.push(rule),
            PatternKind::Prefix => self.prefix.push(rule),
            PatternKind::Glob => self.glob.push(rule),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.exact.len() + self.prefix.len() + self.glob.len()
    }

    /// Walk the tiers in order (exact > prefix > glob); within each
    /// tier, deny wins over allow. The first decisive verdict wins.
    pub fn evaluate(&self, url: &str, method: &str) -> UrlDecision {
        for tier in [&self.exact, &self.prefix, &self.glob] {
            if let Some(d) = self.evaluate_tier(tier, url, method) {
                return d;
            }
        }
        UrlDecision::no_match(url, method)
    }

    fn evaluate_tier(&self, tier: &[UrlRule], url: &str, method: &str) -> Option<UrlDecision> {
        let mut allow_hit: Option<&UrlRule> = None;
        for rule in tier {
            if !rule.matches_url(url) {
                continue;
            }
            if !rule.matches_method(method) {
                continue;
            }
            if matches!(rule.action, RuleAction::Deny) {
                return Some(UrlDecision {
                    verdict: RuleVerdict::Deny,
                    rule_id: rule.rule_id.clone(),
                    description: rule.description.clone(),
                    method: method.to_uppercase(),
                    url: url.to_string(),
                });
            }
            if allow_hit.is_none() {
                allow_hit = Some(rule);
            }
        }
        allow_hit.map(|r| UrlDecision {
            verdict: RuleVerdict::Allow,
            rule_id: r.rule_id.clone(),
            description: r.description.clone(),
            method: method.to_uppercase(),
            url: url.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(id: &str, pat: &str, action: RuleAction) -> UrlRule {
        UrlRule::new(id, pat).kind(PatternKind::Exact).action(action)
    }
    fn prefix(id: &str, pat: &str, action: RuleAction) -> UrlRule {
        UrlRule::new(id, pat).kind(PatternKind::Prefix).action(action)
    }
    fn glob_rule(id: &str, pat: &str, action: RuleAction) -> UrlRule {
        UrlRule::new(id, pat).kind(PatternKind::Glob).action(action)
    }

    #[test]
    fn empty_engine_is_no_match() {
        let e = UrlRulesEngine::default();
        assert_eq!(
            e.evaluate("https://example.com/", "GET").verdict,
            RuleVerdict::NoMatch
        );
    }

    #[test]
    fn exact_allow_hit() {
        let e = UrlRulesEngine::new(vec![exact(
            "ok.api",
            "https://api.example.com/v1/health",
            RuleAction::Allow,
        )]);
        let d = e.evaluate("https://api.example.com/v1/health", "GET");
        assert_eq!(d.verdict, RuleVerdict::Allow);
        assert_eq!(d.rule_id, "ok.api");
    }

    #[test]
    fn exact_no_partial_match() {
        let e = UrlRulesEngine::new(vec![exact(
            "only.this",
            "https://api.example.com/v1/health",
            RuleAction::Allow,
        )]);
        assert_eq!(
            e.evaluate("https://api.example.com/v1/health/extra", "GET").verdict,
            RuleVerdict::NoMatch,
        );
    }

    #[test]
    fn exact_deny_wins_in_tier() {
        let e = UrlRulesEngine::new(vec![
            exact("good", "https://api.example.com/v1", RuleAction::Allow),
            exact("bad", "https://api.example.com/v1", RuleAction::Deny),
        ]);
        let d = e.evaluate("https://api.example.com/v1", "GET");
        assert_eq!(d.verdict, RuleVerdict::Deny);
        assert_eq!(d.rule_id, "bad");
    }

    #[test]
    fn prefix_match() {
        let e = UrlRulesEngine::new(vec![prefix(
            "github",
            "https://api.github.com/",
            RuleAction::Allow,
        )]);
        let d = e.evaluate("https://api.github.com/repos/foo/bar", "GET");
        assert_eq!(d.verdict, RuleVerdict::Allow);
        assert_eq!(d.rule_id, "github");
    }

    #[test]
    fn prefix_deny_wins_in_tier() {
        let e = UrlRulesEngine::new(vec![
            prefix("github.all", "https://api.github.com/", RuleAction::Allow),
            prefix(
                "github.admin",
                "https://api.github.com/admin/",
                RuleAction::Deny,
            ),
        ]);
        let d = e.evaluate("https://api.github.com/admin/users", "GET");
        assert_eq!(d.verdict, RuleVerdict::Deny);
        assert_eq!(d.rule_id, "github.admin");
    }

    #[test]
    fn glob_wildcard_matches() {
        let e = UrlRulesEngine::new(vec![glob_rule(
            "any.cdn",
            "https://*.cdn.example.com/*",
            RuleAction::Allow,
        )]);
        assert_eq!(
            e.evaluate("https://images.cdn.example.com/banner.png", "GET").verdict,
            RuleVerdict::Allow,
        );
        assert_eq!(
            e.evaluate("https://example.com/banner.png", "GET").verdict,
            RuleVerdict::NoMatch,
        );
    }

    #[test]
    fn exact_beats_prefix_when_exact_matches() {
        let e = UrlRulesEngine::new(vec![
            exact(
                "specific",
                "https://api.example.com/v1/health",
                RuleAction::Allow,
            ),
            prefix("broad.deny", "https://api.example.com/", RuleAction::Deny),
        ]);
        let d = e.evaluate("https://api.example.com/v1/health", "GET");
        assert_eq!(d.verdict, RuleVerdict::Allow);
        assert_eq!(d.rule_id, "specific");
    }

    #[test]
    fn prefix_falls_through_to_glob() {
        let e = UrlRulesEngine::new(vec![
            prefix("other", "https://other.com/", RuleAction::Allow),
            glob_rule(
                "cdn.match",
                "https://*.cdn.example.com/*",
                RuleAction::Allow,
            ),
        ]);
        let d = e.evaluate("https://images.cdn.example.com/x", "GET");
        assert_eq!(d.verdict, RuleVerdict::Allow);
        assert_eq!(d.rule_id, "cdn.match");
    }

    #[test]
    fn method_filter_only_allows_listed() {
        let e = UrlRulesEngine::new(vec![prefix("github.read", "https://api.github.com/", RuleAction::Allow)
            .methods(vec!["GET".into()])]);
        assert_eq!(
            e.evaluate("https://api.github.com/x", "GET").verdict,
            RuleVerdict::Allow
        );
        assert_eq!(
            e.evaluate("https://api.github.com/x", "POST").verdict,
            RuleVerdict::NoMatch
        );
    }

    #[test]
    fn method_case_insensitive() {
        let e = UrlRulesEngine::new(vec![prefix("ok", "https://x/", RuleAction::Allow)
            .methods(vec!["GET".into()])]);
        assert_eq!(
            e.evaluate("https://x/y", "get").verdict,
            RuleVerdict::Allow
        );
    }

    #[test]
    fn decision_carries_metadata() {
        let e = UrlRulesEngine::new(vec![prefix(
            "github.deny",
            "https://api.github.com/admin/",
            RuleAction::Deny,
        )
        .description("block GitHub admin endpoints")]);
        let d = e.evaluate("https://api.github.com/admin/users", "DELETE");
        assert_eq!(d.verdict, RuleVerdict::Deny);
        assert_eq!(d.rule_id, "github.deny");
        assert_eq!(d.description, "block GitHub admin endpoints");
        assert_eq!(d.method, "DELETE");
        assert_eq!(d.url, "https://api.github.com/admin/users");
        assert!(!d.allowed());
    }

    #[test]
    fn rule_count_reflects_inserted_rules() {
        let e = UrlRulesEngine::new(vec![
            exact("a", "https://x/a", RuleAction::Allow),
            prefix("b", "https://y/", RuleAction::Allow),
            glob_rule("c", "https://*/c", RuleAction::Allow),
            exact("d", "https://x/d", RuleAction::Allow),
        ]);
        assert_eq!(e.rule_count(), 4);
    }

    #[test]
    fn add_after_construction() {
        let mut e = UrlRulesEngine::new(vec![prefix("a", "https://a/", RuleAction::Allow)]);
        e.add(exact("b", "https://b/exact", RuleAction::Allow));
        assert_eq!(e.rule_count(), 2);
        assert_eq!(
            e.evaluate("https://b/exact", "GET").rule_id,
            "b"
        );
    }
}
