//! Tessera policy engine and outbound gates.
//!
//! Phase 1 ports the existing `policy`, `ssrf_guard`, and `url_rules`
//! modules from the single-crate gateway. Phase 2 adds sensitivity,
//! ratelimit, evidence, provenance, delegation, compliance, replay,
//! mcp_baseline, and policy_builder. Phase 3 adds rag_guard and
//! the SARIF surfaces; Phase 4 adds policy_builder_llm.

pub mod compliance;
pub mod delegation;
pub mod delegation_intent;
pub mod evidence;
pub mod mcp_baseline;
pub mod policy;
pub mod provenance;
pub mod ratelimit;
pub mod sensitivity;
pub mod ssrf_guard;
pub mod url_rules;

pub use compliance::{
    cwe_codes, enrich_event, known_event_kinds, nist_controls, owasp_asi, ChainedAuditLog,
    GENESIS_PREVIOUS_HASH,
};
pub use delegation::{
    narrow_delegation, sign_delegation, verify_delegation, DelegationNarrowingViolation,
    DelegationToken,
};
pub use delegation_intent::{detect_delegation, DelegationScope};
pub use mcp_baseline::{tool_hash, DriftPolicy, DriftResult, MCPBaseline, ToolDrift};
pub use evidence::{
    EvidenceBundle as PolicyEvidenceBundle, HmacEvidenceSigner, HmacEvidenceVerifier,
    SignedEvidenceBundle as PolicySignedEvidenceBundle, EVIDENCE_SCHEMA_VERSION,
};
pub use provenance::{
    ContextSegmentEnvelope, ManifestSegmentRef, PromptProvenanceManifest,
};
pub use ratelimit::{BudgetStatus, CallRateStatus, TokenBudget, ToolCallRateLimit};
pub use sensitivity::{
    default_rules as sensitivity_default_rules, Classification, ClassificationRule, HighWaterMark,
    HwmStore, InMemoryHwmStore, OutboundDecision, OutboundPolicy, RuleKind, SensitivityClassifier,
    SensitivityLabel, ToolClassification,
};
pub use policy::{
    Decision, DecisionKind, Policy, ResourceRequirement, ResourceType, ToolRequirement,
};
pub use ssrf_guard::{
    parse_ip_any, Resolver, SsrfDecision, SsrfFinding, SsrfGuard, SsrfGuardBuilder, SystemResolver,
};
pub use url_rules::{
    PatternKind, RuleAction, RuleVerdict, UrlDecision, UrlRule, UrlRulesEngine,
};
