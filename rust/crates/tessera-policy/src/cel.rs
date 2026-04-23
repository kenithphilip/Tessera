//! CEL-based policy evaluation for attribute-driven deny rules.
//!
//! Mirrors `tessera.cel_engine` from the Python reference. CEL
//! expressions evaluate AFTER the taint-floor check passes; they
//! act as deny-only refinements that can block an otherwise-allowed
//! tool call but cannot allow a taint-denied one.
//!
//! The seven activation variables match the Python `CELContext`:
//! `tool` (string), `args` (map<string,string>, with all values
//! coerced via Python's `str(v)` for byte-equal parity),
//! `min_trust` (int), `principal` (string), `segment_count` (int),
//! `delegation_subject` (string, empty when None),
//! `delegation_actions` (list<string>).
//!
//! Cross-language interop is pinned by
//! `tests/python_cel_interop.rs`.

use std::collections::HashMap;

use cel_interpreter::{Context, Program, Value};
use serde::{Deserialize, Serialize};

/// Action a CEL rule applies when its expression returns true.
///
/// `Deny` rejects the tool call outright. `RequireApproval` returns
/// the rule decision so the caller can route the call through a
/// human-approval workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CelAction {
    Deny,
    RequireApproval,
}

impl CelAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::RequireApproval => "require_approval",
        }
    }
}

/// One CEL deny rule.
///
/// Matches Python `tessera.cel_engine.CELRule` field-for-field. The
/// `expression` is compiled once when the engine is constructed; the
/// engine retains the original [`CelRule`] alongside the compiled
/// program for introspection (AgentMesh reads `_rules` directly to
/// surface the rule list on `/v1/policy`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CelRule {
    pub name: String,
    pub expression: String,
    pub action: CelAction,
    pub message: String,
}

impl CelRule {
    pub fn new(
        name: impl Into<String>,
        expression: impl Into<String>,
        action: CelAction,
        message: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            expression: expression.into(),
            action,
            message: message.into(),
        }
    }
}

/// Variables exposed to CEL expressions.
///
/// Field-for-field mirror of Python `CELContext`. `args` values are
/// stringified at activation time (matching Python's
/// `str(v) for v in args.values()`) so a rule like
/// `args["count"] == "5"` works identically across both ports. This
/// is a known semantic quirk we intentionally preserve for v0.10.0
/// parity; a future release may swap both languages to typed args.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CelContext {
    pub tool: String,
    pub args: HashMap<String, String>,
    pub min_trust: i64,
    pub principal: String,
    pub segment_count: i64,
    /// `None` is mapped to `""` in the activation, matching Python.
    pub delegation_subject: Option<String>,
    pub delegation_actions: Vec<String>,
}

impl CelContext {
    /// Convenience constructor with sensible defaults for the optional
    /// delegation fields.
    pub fn new(
        tool: impl Into<String>,
        principal: impl Into<String>,
        min_trust: i64,
        segment_count: i64,
    ) -> Self {
        Self {
            tool: tool.into(),
            args: HashMap::new(),
            min_trust,
            principal: principal.into(),
            segment_count,
            delegation_subject: None,
            delegation_actions: Vec::new(),
        }
    }

    pub fn with_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.insert(key.into(), value.into());
        self
    }

    pub fn with_delegation(
        mut self,
        subject: impl Into<String>,
        actions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.delegation_subject = Some(subject.into());
        self.delegation_actions = actions.into_iter().map(Into::into).collect();
        self
    }
}

/// Result returned when a CEL rule fires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CelDecision {
    pub rule_name: String,
    pub action: CelAction,
    pub message: String,
}

/// Compile-time error from [`CelPolicyEngine::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CelCompileError {
    pub rule_name: String,
    pub expression: String,
    pub source: String,
}

impl std::fmt::Display for CelCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CEL rule {:?} failed to compile (expression: {:?}): {}",
            self.rule_name, self.expression, self.source
        )
    }
}

impl std::error::Error for CelCompileError {}

/// Compiled rule + its source. Internal; the engine returns
/// references to the original `CelRule` via [`CelPolicyEngine::rules`].
struct Compiled {
    rule: CelRule,
    program: Program,
}

/// Evaluates a sequence of CEL deny rules against a [`CelContext`].
///
/// Mirrors `tessera.cel_engine.CELPolicyEngine`. Compile expressions
/// once at construction time; `evaluate` reuses the compiled programs
/// per call.
pub struct CelPolicyEngine {
    rules: Vec<Compiled>,
}

impl std::fmt::Debug for CelPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // cel_interpreter::Program does not implement Debug; show the
        // engine as the rule list it holds.
        f.debug_struct("CelPolicyEngine")
            .field(
                "rules",
                &self.rules.iter().map(|c| &c.rule).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CelPolicyEngine {
    /// Compile every rule. Fails fast on the first compile error.
    pub fn new(rules: impl IntoIterator<Item = CelRule>) -> Result<Self, CelCompileError> {
        let mut compiled = Vec::new();
        for rule in rules {
            let program = Program::compile(&rule.expression).map_err(|e| CelCompileError {
                rule_name: rule.name.clone(),
                expression: rule.expression.clone(),
                source: e.to_string(),
            })?;
            compiled.push(Compiled { rule, program });
        }
        Ok(Self { rules: compiled })
    }

    /// Iterate over the rules in registration order. Used by AgentMesh
    /// (`proxy._policy.cel_engine._rules` introspection).
    pub fn rules(&self) -> impl Iterator<Item = &CelRule> {
        self.rules.iter().map(|c| &c.rule)
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Evaluate every rule in order. Return the first that matches,
    /// or `None` when all rules return false.
    pub fn evaluate(&self, ctx: &CelContext) -> Option<CelDecision> {
        if self.rules.is_empty() {
            return None;
        }
        let activation = build_activation(ctx);
        for compiled in &self.rules {
            match compiled.program.execute(&activation) {
                Ok(Value::Bool(true)) => {
                    return Some(CelDecision {
                        rule_name: compiled.rule.name.clone(),
                        action: compiled.rule.action,
                        message: compiled.rule.message.clone(),
                    });
                }
                Ok(_) => continue,
                Err(_e) => {
                    // Match Python: cel-python raises on missing
                    // variables / type errors; we swallow the error
                    // and treat it as a non-match. A future release
                    // may surface this as a structured warning.
                    continue;
                }
            }
        }
        None
    }
}

/// Build the cel-interpreter [`Context`] from a [`CelContext`].
///
/// Stringifies `args` values for byte-equal parity with the Python
/// activation. The empty-string mapping for `delegation_subject =
/// None` matches Python's `context.delegation_subject or ""`.
fn build_activation(ctx: &CelContext) -> Context<'static> {
    let mut activation = Context::default();
    activation.add_variable_from_value("tool", ctx.tool.clone());
    let args_value: HashMap<String, String> = ctx
        .args
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    activation.add_variable_from_value("args", args_value);
    activation.add_variable_from_value("min_trust", ctx.min_trust);
    activation.add_variable_from_value("principal", ctx.principal.clone());
    activation.add_variable_from_value("segment_count", ctx.segment_count);
    activation.add_variable_from_value(
        "delegation_subject",
        ctx.delegation_subject.clone().unwrap_or_default(),
    );
    activation.add_variable_from_value("delegation_actions", ctx.delegation_actions.clone());
    activation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_basic() -> CelContext {
        CelContext::new("send_email", "alice@example.com", 100, 3)
            .with_arg("to", "bob@example.com")
            .with_arg("count", "5")
    }

    fn rule_deny(name: &str, expr: &str) -> CelRule {
        CelRule::new(name, expr, CelAction::Deny, format!("rule {name} fired"))
    }

    // ---- Compilation ------------------------------------------------------

    #[test]
    fn empty_rule_set_returns_none() {
        let engine = CelPolicyEngine::new(Vec::new()).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_none());
    }

    #[test]
    fn invalid_expression_fails_to_compile() {
        let r = CelRule::new("bad", "tool ==", CelAction::Deny, "x");
        let err = CelPolicyEngine::new([r]).unwrap_err();
        assert_eq!(err.rule_name, "bad");
    }

    #[test]
    fn valid_expressions_all_compile() {
        let rules = vec![
            rule_deny("a", "tool == \"send_email\""),
            rule_deny("b", "min_trust < 200"),
            rule_deny("c", "tool == \"a\" || min_trust < 100"),
        ];
        let engine = CelPolicyEngine::new(rules).unwrap();
        assert_eq!(engine.rule_count(), 3);
    }

    // ---- Single-rule evaluation -----------------------------------------

    #[test]
    fn deny_rule_matching_tool_fires() {
        let engine =
            CelPolicyEngine::new([rule_deny("delete-block", "tool == \"send_email\"")]).unwrap();
        let d = engine.evaluate(&ctx_basic()).unwrap();
        assert_eq!(d.rule_name, "delete-block");
        assert_eq!(d.action, CelAction::Deny);
    }

    #[test]
    fn deny_rule_not_matching_tool_passes() {
        let engine = CelPolicyEngine::new([rule_deny("x", "tool == \"other\"")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_none());
    }

    #[test]
    fn integer_comparison_min_trust_below_threshold() {
        let engine = CelPolicyEngine::new([rule_deny("low", "min_trust < 200")]).unwrap();
        let d = engine.evaluate(&ctx_basic()).unwrap();
        assert_eq!(d.rule_name, "low");
    }

    #[test]
    fn integer_comparison_min_trust_at_or_above_threshold() {
        let mut ctx = ctx_basic();
        ctx.min_trust = 200;
        let engine = CelPolicyEngine::new([rule_deny("low", "min_trust < 200")]).unwrap();
        assert!(engine.evaluate(&ctx).is_none());
    }

    // ---- Multi-rule precedence -----------------------------------------

    #[test]
    fn first_matching_rule_wins() {
        let rules = vec![
            rule_deny("first", "min_trust < 200"),
            rule_deny("second", "tool == \"send_email\""),
        ];
        let engine = CelPolicyEngine::new(rules).unwrap();
        let d = engine.evaluate(&ctx_basic()).unwrap();
        assert_eq!(d.rule_name, "first");
    }

    #[test]
    fn earlier_non_match_does_not_block_later_match() {
        let rules = vec![
            rule_deny("first", "tool == \"never\""),
            rule_deny("second", "tool == \"send_email\""),
        ];
        let engine = CelPolicyEngine::new(rules).unwrap();
        let d = engine.evaluate(&ctx_basic()).unwrap();
        assert_eq!(d.rule_name, "second");
    }

    // ---- Action variants -----------------------------------------------

    #[test]
    fn require_approval_action_propagates() {
        let rule = CelRule::new(
            "approval",
            "tool == \"send_email\"",
            CelAction::RequireApproval,
            "needs human approval",
        );
        let engine = CelPolicyEngine::new([rule]).unwrap();
        let d = engine.evaluate(&ctx_basic()).unwrap();
        assert_eq!(d.action, CelAction::RequireApproval);
        assert_eq!(d.message, "needs human approval");
    }

    #[test]
    fn action_serializes_to_snake_case() {
        let s = serde_json::to_string(&CelAction::RequireApproval).unwrap();
        assert_eq!(s, "\"require_approval\"");
        let s = serde_json::to_string(&CelAction::Deny).unwrap();
        assert_eq!(s, "\"deny\"");
    }

    // ---- Activation variables ------------------------------------------

    #[test]
    fn principal_variable_available() {
        let engine = CelPolicyEngine::new([rule_deny(
            "by_principal",
            "principal == \"alice@example.com\"",
        )])
        .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn segment_count_variable_available() {
        let engine =
            CelPolicyEngine::new([rule_deny("many_segments", "segment_count > 2")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn args_map_lookup_string_value() {
        // args["to"] is stringified to "bob@example.com" in build_activation.
        let engine =
            CelPolicyEngine::new([rule_deny("to_bob", "args[\"to\"] == \"bob@example.com\"")])
                .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn args_map_lookup_stringified_int() {
        // ctx.args["count"] = "5" (already a string in our HashMap, but the
        // contract is "everything in args is a string" matching Python).
        let engine =
            CelPolicyEngine::new([rule_deny("count_eq_5", "args[\"count\"] == \"5\"")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn delegation_subject_empty_when_none() {
        let engine = CelPolicyEngine::new([rule_deny("no_deleg", "delegation_subject == \"\"")])
            .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn delegation_subject_populated_when_set() {
        let ctx = ctx_basic().with_delegation("svc-alpha", ["read", "write"]);
        let engine = CelPolicyEngine::new([rule_deny(
            "is_alpha",
            "delegation_subject == \"svc-alpha\"",
        )])
        .unwrap();
        assert!(engine.evaluate(&ctx).is_some());
    }

    #[test]
    fn delegation_actions_list_size_check() {
        let ctx = ctx_basic().with_delegation("svc-alpha", ["read", "write"]);
        let engine =
            CelPolicyEngine::new([rule_deny("two_actions", "size(delegation_actions) == 2")])
                .unwrap();
        assert!(engine.evaluate(&ctx).is_some());
    }

    // ---- Boolean composition -------------------------------------------

    #[test]
    fn or_short_circuits_on_first_true() {
        let engine = CelPolicyEngine::new([rule_deny(
            "a_or_b",
            "tool == \"send_email\" || tool == \"never\"",
        )])
        .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn and_requires_both_true() {
        let engine = CelPolicyEngine::new([rule_deny(
            "both",
            "tool == \"send_email\" && min_trust < 200",
        )])
        .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    #[test]
    fn and_returns_false_when_one_side_false() {
        let engine = CelPolicyEngine::new([rule_deny(
            "both",
            "tool == \"send_email\" && min_trust > 1000",
        )])
        .unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_none());
    }

    #[test]
    fn negation_works() {
        let engine =
            CelPolicyEngine::new([rule_deny("not_x", "!(tool == \"other\")")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_some());
    }

    // ---- Type / runtime safety ---------------------------------------

    #[test]
    fn missing_variable_evaluates_as_no_match() {
        // "nonexistent" is not in the activation; cel-interpreter raises,
        // we swallow and treat as non-match (mirrors Python behavior of
        // skipping after raising NameError-style exception).
        let engine =
            CelPolicyEngine::new([rule_deny("ghost", "nonexistent_var == \"x\"")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_none());
    }

    #[test]
    fn type_mismatch_evaluates_as_no_match() {
        // Comparing string to int: cel-interpreter raises; we treat as
        // non-match.
        let engine = CelPolicyEngine::new([rule_deny("bad_cmp", "tool == 42")]).unwrap();
        assert!(engine.evaluate(&ctx_basic()).is_none());
    }

    // ---- Introspection -----------------------------------------------

    #[test]
    fn rules_iterator_returns_originals_in_order() {
        let original = vec![
            rule_deny("first", "tool == \"a\""),
            rule_deny("second", "tool == \"b\""),
            rule_deny("third", "tool == \"c\""),
        ];
        let engine = CelPolicyEngine::new(original.clone()).unwrap();
        let returned: Vec<_> = engine.rules().cloned().collect();
        assert_eq!(returned, original);
    }

    // ---- Serde round-trip ---------------------------------------------

    #[test]
    fn cel_rule_round_trips_via_serde() {
        let r = rule_deny("x", "tool == \"y\"");
        let s = serde_json::to_string(&r).unwrap();
        let back: CelRule = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn cel_decision_round_trips_via_serde() {
        let d = CelDecision {
            rule_name: "x".to_owned(),
            action: CelAction::Deny,
            message: "blocked".to_owned(),
        };
        let s = serde_json::to_string(&d).unwrap();
        let back: CelDecision = serde_json::from_str(&s).unwrap();
        assert_eq!(d, back);
    }

    // ---- Determinism --------------------------------------------------

    #[test]
    fn evaluation_is_idempotent_across_repeated_calls() {
        let engine = CelPolicyEngine::new([rule_deny(
            "x",
            "tool == \"send_email\" && min_trust < 200",
        )])
        .unwrap();
        let ctx = ctx_basic();
        let d1 = engine.evaluate(&ctx).unwrap();
        let d2 = engine.evaluate(&ctx).unwrap();
        let d3 = engine.evaluate(&ctx).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d2, d3);
    }
}
