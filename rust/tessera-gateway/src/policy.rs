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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::labels::TrustLevel;

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub kind: DecisionKind,
    pub reason: String,
    pub tool: String,
    pub required_trust: TrustLevel,
    pub observed_trust: TrustLevel,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        matches!(self.kind, DecisionKind::Allow)
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
        }
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
            Decision {
                kind: DecisionKind::Allow,
                reason: format!(
                    "min_trust({}) >= required({})",
                    observed.as_int(),
                    required.as_int()
                ),
                tool: name.to_string(),
                required_trust: required,
                observed_trust: observed,
            }
        } else {
            Decision {
                kind: DecisionKind::Deny,
                reason: format!(
                    "context contains a segment at trust_level={}, below required {} for tool {:?}",
                    observed.as_int(),
                    required.as_int(),
                    name
                ),
                tool: name.to_string(),
                required_trust: required,
                observed_trust: observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{make_segment, Context};
    use crate::labels::{HmacSigner, Origin};

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
}
