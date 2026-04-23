//! Taint-tracking policy engine.
//!
//! Mirrors `tessera.policy` from the Python reference. The engine
//! answers one question: given a [`Context`] and a proposed tool
//! call, is the *minimum* trust level in the context high enough to
//! clear the tool's required trust level?
//!
//! ```text
//! allow iff observed_trust >= required_trust
//! observed_trust = context.min_trust()
//! ```
//!
//! Side-effect-free tools are exempt from the taint-floor denial: they
//! can read tainted data but cannot act on it externally. Tools never
//! registered with the policy fall back to `default_required_trust`
//! (`TrustLevel::User` by default).

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use tessera_core::context::Context;
use tessera_core::labels::TrustLevel;

use crate::cel::{CelAction, CelContext, CelPolicyEngine};

/// Categories of resource subject to policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    Tool,
    Prompt,
    Resource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allow,
    Deny,
    RequireApproval,
}

/// The output of [`Policy::evaluate`].
///
/// `reason` is a `Cow<'static, str>` so the hot allow/deny paths
/// can return a borrowed static string without allocating. Numeric
/// detail (`required_trust`, `observed_trust`) lives in dedicated
/// fields rather than being embedded in `reason`, so callers that
/// want a structured view do not have to parse a string. Custom
/// reasons (delegation, scanner verdicts, OPA backends) use
/// `Cow::Owned` and pay one allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub kind: DecisionKind,
    pub reason: Cow<'static, str>,
    pub tool: String,
    pub required_trust: TrustLevel,
    pub observed_trust: TrustLevel,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self.kind, DecisionKind::Allow)
    }

    /// Convenience: the reason as a borrowed `&str`. Same data as
    /// `decision.reason.as_ref()`, just with a friendlier name for
    /// callers that don't want to think about Cow.
    pub fn reason_str(&self) -> &str {
        &self.reason
    }

    /// Format a long-form, human-readable reason that includes the
    /// trust-level numbers. Allocates; only use when displaying to
    /// an operator or writing a log line.
    pub fn formatted_reason(&self) -> String {
        match self.kind {
            DecisionKind::Allow => format!(
                "{} (min_trust={}, required={})",
                self.reason,
                self.observed_trust.as_int(),
                self.required_trust.as_int(),
            ),
            DecisionKind::Deny => format!(
                "{} (min_trust={} below required {} for tool {:?})",
                self.reason,
                self.observed_trust.as_int(),
                self.required_trust.as_int(),
                self.tool,
            ),
            DecisionKind::RequireApproval => format!(
                "{} (tool {:?})",
                self.reason, self.tool
            ),
        }
    }
}

/// Trust requirement for a single tool / prompt / resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceRequirement {
    pub name: String,
    pub resource_type: ResourceType,
    pub required_trust: TrustLevel,
    pub side_effects: bool,
}

impl ResourceRequirement {
    pub fn new_tool(name: impl Into<String>, required_trust: TrustLevel) -> Self {
        Self {
            name: name.into(),
            resource_type: ResourceType::Tool,
            required_trust,
            side_effects: true,
        }
    }

    pub fn read_only(mut self) -> Self {
        self.side_effects = false;
        self
    }
}

/// Backwards-compatible alias for the most common case.
pub type ToolRequirement = ResourceRequirement;

/// Per-tool trust requirements with deny-by-default semantics.
#[derive(Clone, Debug)]
pub struct Policy {
    requirements: HashMap<(String, ResourceType), ResourceRequirement>,
    pub default_required_trust: TrustLevel,
    human_approval_tools: std::collections::HashSet<String>,
    /// Optional CEL deny-rule engine. Mirrors Python
    /// `tessera.policy.Policy.cel_engine`. When present,
    /// `evaluate_with_cel` runs every rule after the taint-floor check
    /// and downgrades an `Allow` decision to `Deny` or
    /// `RequireApproval` if any rule fires.
    cel_engine: Option<Arc<CelPolicyEngine>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy {
    pub fn new() -> Self {
        Self {
            requirements: HashMap::new(),
            default_required_trust: TrustLevel::User,
            human_approval_tools: std::collections::HashSet::new(),
            cel_engine: None,
        }
    }

    /// Install a CEL deny-rule engine. Replaces any previously
    /// installed engine. Pass [`Arc::clone`] of an existing engine to
    /// share rule sets across multiple [`Policy`] instances.
    pub fn set_cel_engine(&mut self, engine: Arc<CelPolicyEngine>) {
        self.cel_engine = Some(engine);
    }

    /// Drop any installed CEL engine.
    pub fn clear_cel_engine(&mut self) {
        self.cel_engine = None;
    }

    /// Borrow the installed CEL engine, if any. Used by AgentMesh's
    /// adapter to expose `_rules` introspection (`/v1/policy`).
    pub fn cel_engine(&self) -> Option<&Arc<CelPolicyEngine>> {
        self.cel_engine.as_ref()
    }

    pub fn require(&mut self, requirement: ResourceRequirement) {
        let key = (requirement.name.clone(), requirement.resource_type);
        self.requirements.insert(key, requirement);
    }

    pub fn require_tool(&mut self, name: impl Into<String>, level: TrustLevel) {
        self.require(ResourceRequirement::new_tool(name, level));
    }

    pub fn require_human_approval(&mut self, tool: impl Into<String>) {
        self.human_approval_tools.insert(tool.into());
    }

    pub fn requires_human_approval(&self, tool: &str) -> bool {
        self.human_approval_tools.contains(tool)
    }

    fn lookup(&self, name: &str, resource_type: ResourceType) -> Option<&ResourceRequirement> {
        self.requirements.get(&(name.to_string(), resource_type))
    }

    pub fn requirements(&self) -> impl Iterator<Item = &ResourceRequirement> {
        self.requirements.values()
    }

    pub fn requirements_count(&self) -> usize {
        self.requirements.len()
    }

    /// Evaluate a tool call against the context's `min_trust`.
    ///
    /// Side-effect-free tools (registered with `side_effects=false`)
    /// are exempt from the taint floor: they always pass the trust
    /// check, regardless of what's in the context. They can still be
    /// gated by other layers (delegation, CEL rules, scanners), but
    /// the load-bearing taint floor does not apply.
    pub fn evaluate(&self, context: &Context, tool_name: &str) -> Decision {
        self.evaluate_resource(context, tool_name, ResourceType::Tool)
    }

    pub fn evaluate_resource(
        &self,
        context: &Context,
        name: &str,
        resource_type: ResourceType,
    ) -> Decision {
        let req = self.lookup(name, resource_type);
        let required = match req {
            Some(r) if !r.side_effects => TrustLevel::Untrusted, // exempt
            Some(r) => r.required_trust,
            None => self.default_required_trust,
        };
        let observed = context.min_trust();

        if observed >= required {
            // Hot path: allocate only the `tool` string. The reason
            // is a Cow::Borrowed(&'static str) so this avoids the
            // intermediate format!() temporary the v0.7.x code paid
            // on every evaluate.
            Decision {
                kind: DecisionKind::Allow,
                reason: Cow::Borrowed("min_trust meets required floor"),
                tool: name.to_string(),
                required_trust: required,
                observed_trust: observed,
            }
        } else {
            Decision {
                kind: DecisionKind::Deny,
                reason: Cow::Borrowed("context taint below required floor"),
                tool: name.to_string(),
                required_trust: required,
                observed_trust: observed,
            }
        }
    }

    /// Evaluate with both the taint-floor check and any installed CEL
    /// deny rules. Mirrors Python `Policy.evaluate(context, tool_name,
    /// tool_args, principal=..., delegation=...)`.
    ///
    /// CEL is a deny-only refinement: it can downgrade an `Allow` to
    /// `Deny` or `RequireApproval`, but it cannot upgrade a `Deny`.
    /// When the taint floor denies, this method short-circuits and
    /// never builds the CEL activation.
    ///
    /// `args` values are stringified into the CEL `args` map; the
    /// caller is expected to perform this coercion (matching the
    /// Python `str(v) for v in args.values()` quirk).
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_cel(
        &self,
        context: &Context,
        tool_name: &str,
        args: &HashMap<String, String>,
        principal: &str,
        delegation_subject: Option<&str>,
        delegation_actions: &[String],
    ) -> Decision {
        let mut decision = self.evaluate_resource(context, tool_name, ResourceType::Tool);

        // CEL only refines an allow. A deny stays denied.
        if !matches!(decision.kind, DecisionKind::Allow) {
            return decision;
        }

        let Some(engine) = self.cel_engine.as_ref() else {
            return decision;
        };

        let cel_ctx = CelContext {
            tool: tool_name.to_owned(),
            args: args.clone(),
            min_trust: context.min_trust().as_int(),
            principal: principal.to_owned(),
            segment_count: context.len() as i64,
            delegation_subject: delegation_subject.map(str::to_owned),
            delegation_actions: delegation_actions.to_vec(),
        };

        if let Some(cel_decision) = engine.evaluate(&cel_ctx) {
            decision.kind = match cel_decision.action {
                CelAction::Deny => DecisionKind::Deny,
                CelAction::RequireApproval => DecisionKind::RequireApproval,
            };
            decision.reason = Cow::Owned(cel_decision.message);
        }

        decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_core::context::{make_segment, Context};
    use tessera_core::labels::{HmacSigner, Origin};

    const KEY: &[u8] = b"test-policy-32bytes!!!!!!!!!!!!!";

    fn signer() -> HmacSigner {
        HmacSigner::new(KEY)
    }

    fn user_context() -> Context {
        let mut ctx = Context::new();
        ctx.add(make_segment("hi", Origin::User, "alice", &signer(), None));
        ctx
    }

    fn web_tainted_context() -> Context {
        let mut ctx = Context::new();
        ctx.add(make_segment("hi", Origin::User, "alice", &signer(), None));
        ctx.add(make_segment("evil", Origin::Web, "alice", &signer(), None));
        ctx
    }

    #[test]
    fn unregistered_tool_uses_default_required_trust() {
        let policy = Policy::new();
        // Default is USER; user-only context should pass.
        let decision = policy.evaluate(&user_context(), "anything");
        assert!(decision.allowed());
        // Web-tainted context should be denied.
        let denied = policy.evaluate(&web_tainted_context(), "anything");
        assert!(!denied.allowed());
    }

    #[test]
    fn registered_tool_uses_its_requirement() {
        let mut policy = Policy::new();
        policy.require_tool("public_search", TrustLevel::Tool);
        // TOOL-required tool passes for web-tainted context if min is
        // UNTRUSTED? No: UNTRUSTED < TOOL still denies.
        let decision = policy.evaluate(&web_tainted_context(), "public_search");
        assert!(!decision.allowed());
        // But a tool-only context (min=Tool) passes.
        let mut tool_ctx = Context::new();
        tool_ctx.add(make_segment("output", Origin::Tool, "alice", &signer(), None));
        assert!(policy.evaluate(&tool_ctx, "public_search").allowed());
    }

    #[test]
    fn read_only_tool_exempt_from_taint_floor() {
        // A read-only tool can run on UNTRUSTED context. The taint
        // floor only applies to side-effecting tools.
        let mut policy = Policy::new();
        policy.require(
            ResourceRequirement::new_tool("read_file", TrustLevel::User).read_only(),
        );
        let decision = policy.evaluate(&web_tainted_context(), "read_file");
        assert!(decision.allowed());
    }

    #[test]
    fn taint_tracking_uses_min_not_max() {
        // Pin the load-bearing property: any one untrusted segment
        // drags the floor down, regardless of how many trusted
        // segments are also present.
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let mut ctx = Context::new();
        for _ in 0..10 {
            ctx.add(make_segment("user", Origin::User, "alice", &signer(), None));
        }
        ctx.add(make_segment("evil", Origin::Web, "alice", &signer(), None));
        // Even though 10 segments are USER and only 1 is UNTRUSTED, the
        // verdict is deny.
        let decision = policy.evaluate(&ctx, "send_email");
        assert!(!decision.allowed());
        assert_eq!(decision.observed_trust, TrustLevel::Untrusted);
    }

    #[test]
    fn empty_context_passes_user_required_tool() {
        // Empty context defaults min_trust=System, which clears any
        // requirement. Matches the Python reference.
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let decision = policy.evaluate(&Context::new(), "send_email");
        assert!(decision.allowed());
    }

    #[test]
    fn decision_carries_metadata() {
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let decision = policy.evaluate(&web_tainted_context(), "send_email");
        assert_eq!(decision.tool, "send_email");
        assert_eq!(decision.required_trust, TrustLevel::User);
        assert_eq!(decision.observed_trust, TrustLevel::Untrusted);
        assert!(!decision.reason.is_empty());
    }

    #[test]
    fn human_approval_registry_is_separate_from_evaluate() {
        let mut policy = Policy::new();
        policy.require_human_approval("delete_database");
        assert!(policy.requires_human_approval("delete_database"));
        assert!(!policy.requires_human_approval("read_file"));
        // evaluate() is unchanged by approval flagging; the caller's
        // pipeline checks requires_human_approval separately.
        let decision = policy.evaluate(&user_context(), "delete_database");
        assert!(decision.allowed());
    }

    #[test]
    fn requirements_iter_round_trips() {
        let mut policy = Policy::new();
        policy.require_tool("a", TrustLevel::User);
        policy.require_tool("b", TrustLevel::Tool);
        assert_eq!(policy.requirements_count(), 2);
        let names: std::collections::HashSet<&str> = policy
            .requirements()
            .map(|r| r.name.as_str())
            .collect();
        assert!(names.contains("a") && names.contains("b"));
    }

    // ---- CEL wiring ----------------------------------------------------

    use std::sync::Arc;

    use crate::cel::{CelAction, CelPolicyEngine, CelRule};

    #[test]
    fn cel_engine_accessor_returns_installed_engine() {
        let mut policy = Policy::new();
        let engine = Arc::new(
            CelPolicyEngine::new([CelRule::new(
                "r",
                "tool == \"x\"",
                CelAction::Deny,
                "blocked",
            )])
            .unwrap(),
        );
        policy.set_cel_engine(engine.clone());
        let got = policy.cel_engine().unwrap();
        assert_eq!(got.rule_count(), 1);
    }

    #[test]
    fn cel_deny_downgrades_allow_to_deny() {
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        policy.set_cel_engine(Arc::new(
            CelPolicyEngine::new([CelRule::new(
                "block-by-cel",
                "tool == \"send_email\"",
                CelAction::Deny,
                "CEL: forbidden tool",
            )])
            .unwrap(),
        ));

        let decision = policy.evaluate_with_cel(
            &user_context(),
            "send_email",
            &HashMap::new(),
            "alice",
            None,
            &[],
        );
        assert!(matches!(decision.kind, DecisionKind::Deny));
        assert_eq!(decision.reason_str(), "CEL: forbidden tool");
    }

    #[test]
    fn cel_require_approval_downgrades_allow_to_require_approval() {
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        policy.set_cel_engine(Arc::new(
            CelPolicyEngine::new([CelRule::new(
                "needs-approval",
                "tool == \"send_email\"",
                CelAction::RequireApproval,
                "needs human eyes",
            )])
            .unwrap(),
        ));

        let decision = policy.evaluate_with_cel(
            &user_context(),
            "send_email",
            &HashMap::new(),
            "alice",
            None,
            &[],
        );
        assert!(matches!(decision.kind, DecisionKind::RequireApproval));
    }

    #[test]
    fn cel_does_not_upgrade_taint_deny_to_allow() {
        // A taint-floor deny short-circuits before CEL ever runs.
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        policy.set_cel_engine(Arc::new(
            CelPolicyEngine::new([CelRule::new(
                "always-allow",
                "true",  // would always fire if reached
                CelAction::Deny,
                "would never see this if CEL ran",
            )])
            .unwrap(),
        ));

        // Build a tainted context so the floor denies.
        let tainted = {
            use tessera_core::context::{make_segment, Context};
            use tessera_core::labels::Origin;
            let signer = HmacSigner::new(KEY.to_vec());
            let mut ctx = Context::new();
            ctx.add(make_segment(
                "untrusted webpage content",
                Origin::Web,
                "scrape",
                &signer,
                None,
            ));
            ctx
        };

        let decision = policy.evaluate_with_cel(
            &tainted,
            "send_email",
            &HashMap::new(),
            "alice",
            None,
            &[],
        );
        assert!(matches!(decision.kind, DecisionKind::Deny));
        // Reason is the taint-floor reason, NOT the CEL reason.
        assert!(decision.reason_str().contains("taint"));
    }

    #[test]
    fn cel_passes_args_principal_and_delegation() {
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        // A rule that exercises every activation variable.
        policy.set_cel_engine(Arc::new(
            CelPolicyEngine::new([CelRule::new(
                "wide",
                "tool == \"send_email\" && principal == \"alice\" && \
                 args[\"to\"] == \"bob\" && delegation_subject == \"svc\" && \
                 size(delegation_actions) == 2 && segment_count > 0 && \
                 min_trust >= 100",
                CelAction::Deny,
                "fired",
            )])
            .unwrap(),
        ));

        let mut args = HashMap::new();
        args.insert("to".to_owned(), "bob".to_owned());
        let decision = policy.evaluate_with_cel(
            &user_context(),
            "send_email",
            &args,
            "alice",
            Some("svc"),
            &["read".to_owned(), "write".to_owned()],
        );
        assert!(matches!(decision.kind, DecisionKind::Deny));
        assert_eq!(decision.reason_str(), "fired");
    }

    #[test]
    fn evaluate_with_cel_no_engine_behaves_like_evaluate() {
        // Without an installed engine, evaluate_with_cel must produce
        // the same Decision as evaluate() does.
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let ctx = user_context();
        let baseline = policy.evaluate(&ctx, "send_email");
        let extended = policy.evaluate_with_cel(
            &ctx,
            "send_email",
            &HashMap::new(),
            "alice",
            None,
            &[],
        );
        assert_eq!(baseline.kind as u8, extended.kind as u8);
        assert_eq!(baseline.required_trust, extended.required_trust);
        assert_eq!(baseline.observed_trust, extended.observed_trust);
        assert_eq!(baseline.reason_str(), extended.reason_str());
    }
}
