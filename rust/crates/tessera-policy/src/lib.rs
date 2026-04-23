//! Tessera policy engine and outbound gates.
//!
//! Phase 1 ports the existing `policy`, `ssrf_guard`, and `url_rules`
//! modules from the single-crate gateway. Phase 2 adds sensitivity,
//! ratelimit, evidence, provenance, delegation, compliance, replay,
//! mcp_baseline, and policy_builder. Phase 3 adds rag_guard and
//! the SARIF surfaces; Phase 4 adds policy_builder_llm.

pub mod policy;
pub mod ssrf_guard;
pub mod url_rules;

pub use policy::{
    Decision, DecisionKind, Policy, ResourceRequirement, ResourceType, ToolRequirement,
};
pub use ssrf_guard::{
    parse_ip_any, Resolver, SsrfDecision, SsrfFinding, SsrfGuard, SsrfGuardBuilder, SystemResolver,
};
pub use url_rules::{
    PatternKind, RuleAction, RuleVerdict, UrlDecision, UrlRule, UrlRulesEngine,
};
