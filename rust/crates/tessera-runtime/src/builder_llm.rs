//! LLM-driven proposer that emits [`Proposal`] objects from a
//! constrained template set.
//!
//! Layered on top of [`tessera_policy::builder`]. Reuses the same
//! [`Proposal`] shape so callers can score LLM-generated proposals
//! through the existing `score_proposal` machinery without caring
//! where the proposal came from.
//!
//! # Constrained templates, not free-form CEL
//!
//! LLMs are bad at writing CEL: they hallucinate predicates, miss
//! operator semantics, forget which fields are in scope. A
//! misgenerated CEL rule that fails to compile is an obvious bug; a
//! misgenerated rule that compiles but expresses the wrong predicate
//! is a silent security regression.
//!
//! This module keeps the LLM in the "explanation / recommendation"
//! lane only. The LLM sees a per-tool aggregate summary and returns
//! structured output (an [`LlmProposalBatch`]) drawn from a small
//! fixed template set:
//!
//! * `tighten` / `loosen` a tool's required_trust by one step
//! * `mark_read_only` to set `side_effects=false`
//! * `register_tool` to add a default requirement for a tool that
//!   appears in audit but is not in `policy.requirements`
//!
//! Each template compiles to a deterministic Policy mutation. The
//! LLM contributes signal (which tools to look at, why) and the
//! deterministic templates contribute correctness.
//!
//! # Why this lives in `tessera-runtime`
//!
//! The original plan placed this module at `tessera-policy::builder_llm`,
//! but that would require `tessera-policy` to depend on `tessera-runtime`
//! for the [`LlmClient`] trait and the breaker, creating a cycle.
//! Putting it here keeps the dependency direction one-way:
//! `runtime -> policy`. Public API stays close to Python by
//! re-exporting [`tessera_policy::builder::Proposal`] etc. as needed.

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::time::Instant;
#[cfg(test)]
use std::time::Duration;

use tessera_core::labels::TrustLevel;
use tessera_policy::builder::{
    Proposal, ProposalEvidence, ProposalKind,
};
use tessera_policy::policy::{Policy, ResourceRequirement, ResourceType};
use tessera_policy::replay::LabelStore;

use crate::guardrail::{BreakerConfig, OpenMode};
use crate::llm_client::{LlmClient, LlmRequest};

const SYSTEM_PROMPT: &str = concat!(
    "You are a security policy reviewer for an AI agent system. ",
    "You are given per-tool decision counts and label statistics from a ",
    "Tessera audit log. Your job is to suggest small, targeted edits to ",
    "the policy from a fixed template set.\n\n",
    "Templates you may use:\n",
    "- tighten: raise required_trust by one step (UNTRUSTED -> TOOL -> ",
    "USER -> SYSTEM). Use when allows are labeled INCORRECT.\n",
    "- loosen: lower required_trust by one step. Use when denies are ",
    "labeled INCORRECT.\n",
    "- mark_read_only: set side_effects=false. Use when a tool only ",
    "reads data and is being denied for taint when it should be exempt.\n",
    "- register_tool: add a default requirement. Use when a tool appears ",
    "in audit but is not in the policy.\n\n",
    "Rules:\n",
    "1. Only propose edits supported by the label evidence in the input. ",
    "Do not invent.\n",
    "2. Keep proposals to at most 5. Less is better.\n",
    "3. Confidence 0.9+ is reserved for proposals where >= 5 labeled ",
    "INCORRECT entries point at the same fix. Use lower confidence ",
    "for thinner evidence.\n",
    "4. If no edits are warranted, return an empty proposals list.\n\n",
    "Respond with ONLY a JSON object matching this schema:\n",
    "{\"proposals\": [{\"kind\": \"tighten|loosen|mark_read_only|register_tool\", ",
    "\"tool_name\": \"...\", \"target_trust\": \"UNTRUSTED|TOOL|USER|SYSTEM\"|null, ",
    "\"rationale\": \"...\", \"confidence\": 0.0-1.0}]}"
);

/// One LLM-emitted proposal, before it is compiled into a real
/// [`Proposal`]. Fields mirror Python `LLMProposal` exactly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmProposal {
    /// One of `tighten`, `loosen`, `mark_read_only`, `register_tool`.
    pub kind: String,
    pub tool_name: String,
    /// `UNTRUSTED`, `TOOL`, `USER`, or `SYSTEM`. Optional.
    #[serde(default)]
    pub target_trust: Option<String>,
    #[serde(default)]
    pub rationale: String,
    pub confidence: f64,
}

/// Batch of [`LlmProposal`] objects as the LLM returns them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmProposalBatch {
    #[serde(default)]
    pub proposals: Vec<LlmProposal>,
}

// ---- Lightweight breaker (private) --------------------------------------

#[derive(Debug)]
struct Breaker {
    config: BreakerConfig,
    inner: Mutex<BreakerInner>,
}

#[derive(Debug)]
struct BreakerInner {
    open_until: Option<Instant>,
    consecutive_failures: u32,
}

impl Breaker {
    fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(BreakerInner {
                open_until: None,
                consecutive_failures: 0,
            }),
        }
    }

    fn should_skip(&self) -> bool {
        let g = self.inner.lock();
        match g.open_until {
            Some(deadline) => Instant::now() < deadline,
            None => false,
        }
    }

    fn record_success(&self) {
        let mut g = self.inner.lock();
        g.consecutive_failures = 0;
        g.open_until = None;
    }

    fn record_failure(&self) {
        let mut g = self.inner.lock();
        g.consecutive_failures += 1;
        if g.consecutive_failures >= self.config.failure_threshold {
            g.open_until = Some(Instant::now() + self.config.open_duration);
        }
    }
}

// ---- Proposer ------------------------------------------------------------

/// Wraps an [`LlmClient`] to produce [`Proposal`] objects.
///
/// On any LLM failure (network, parse, schema), [`propose`] returns
/// an empty list and increments the breaker. The deterministic
/// `tessera_policy::builder::analyze` path remains available as the
/// fallback; this module is strictly additive.
pub struct LlmPolicyProposer {
    client: Arc<dyn LlmClient>,
    model: String,
    max_tokens: u32,
    breaker: Breaker,
}

impl LlmPolicyProposer {
    /// Defaults: 600 max_tokens, breaker matches
    /// [`BreakerConfig::default`] (5 failures, 30s open,
    /// `OpenMode::PassThrough`).
    pub fn new(client: Arc<dyn LlmClient>, model: impl Into<String>) -> Self {
        Self {
            client,
            model: model.into(),
            max_tokens: 600,
            breaker: Breaker::new(BreakerConfig::default()),
        }
    }

    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    pub fn with_breaker(mut self, breaker: BreakerConfig) -> Self {
        self.breaker = Breaker::new(breaker);
        self
    }

    /// Configure breaker open behavior. Currently the proposer does
    /// NOT honor `OpenMode::Deny` differently from `PassThrough`,
    /// because returning an empty proposal list is the fallback; a
    /// "deny" stance for the proposer would mean refusing to suggest
    /// edits, which is the same observable behavior. Provided for
    /// API symmetry with the guardrail.
    pub fn with_open_mode(self, _mode: OpenMode) -> Self {
        self
    }

    /// Build the user-facing prompt that summarizes per-tool stats.
    /// Public so callers can inspect what would be sent before paying
    /// the LLM call.
    pub fn format_evidence(
        evidence_map: &std::collections::HashMap<String, ProposalEvidence>,
        current_policy: &Policy,
    ) -> String {
        let mut sorted: Vec<&ProposalEvidence> = evidence_map.values().collect();
        sorted.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
        if sorted.is_empty() {
            return "(no observations)".to_string();
        }
        let mut lines: Vec<String> = Vec::with_capacity(sorted.len());
        for ev in sorted {
            let cur = current_requirement(current_policy, &ev.tool_name);
            let registered = current_policy
                .requirements()
                .any(|r| r.name == ev.tool_name && r.resource_type == ResourceType::Tool);
            lines.push(format!(
                "tool={} observed={} denied={} allowed={} \
                 labels(deny: correct={} incorrect={}; \
                 allow: correct={} incorrect={}) \
                 current_required_trust={} side_effects={} registered={}",
                ev.tool_name,
                ev.total_observations,
                ev.denied,
                ev.allowed,
                ev.labeled_correct_denials,
                ev.labeled_incorrect_denials,
                ev.labeled_correct_allows,
                ev.labeled_incorrect_allows,
                trust_level_name(cur.required_trust),
                cur.side_effects,
                registered,
            ));
        }
        lines.join("\n")
    }

    /// Return zero or more proposals based on labeled audit history.
    /// Returns empty when the breaker is open, the LLM raises, or
    /// there is no observed audit data.
    pub async fn propose(
        &self,
        audit_log_path: impl AsRef<std::path::Path>,
        current_policy: &Policy,
        labels: Option<&LabelStore>,
    ) -> Result<Vec<Proposal>, String> {
        if self.breaker.should_skip() {
            return Ok(Vec::new());
        }
        let evidence_map = collect_evidence(&audit_log_path, labels)?;
        if evidence_map.is_empty() {
            return Ok(Vec::new());
        }
        let user_msg = format!(
            "Current default_required_trust: {}\n\nPer-tool observations:\n{}",
            trust_level_name(current_policy.default_required_trust),
            Self::format_evidence(&evidence_map, current_policy),
        );
        let request = LlmRequest {
            model: self.model.clone(),
            system: SYSTEM_PROMPT.to_string(),
            user_message: user_msg,
            max_tokens: self.max_tokens,
            temperature: 0.0,
        };
        let raw = match self.client.complete(request).await {
            Ok(r) => r,
            Err(_) => {
                self.breaker.record_failure();
                return Ok(Vec::new());
            }
        };
        let batch = match parse_response(&raw) {
            Ok(b) => {
                self.breaker.record_success();
                b
            }
            Err(_) => {
                self.breaker.record_failure();
                return Ok(Vec::new());
            }
        };
        let mut compiled: Vec<Proposal> = Vec::new();
        for raw in batch.proposals {
            if let Some(p) = compile_proposal(&raw, current_policy, &evidence_map) {
                compiled.push(p);
            }
        }
        Ok(compiled)
    }
}

fn parse_response(raw: &str) -> Result<LlmProposalBatch, String> {
    let mut text = raw.trim().to_string();
    if text.starts_with("```") {
        text = text
            .lines()
            .filter(|line| !line.trim().starts_with("```"))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
    }
    let start = text.find('{');
    let end = text.rfind('}').map(|i| i + 1);
    let trimmed = match (start, end) {
        (Some(s), Some(e)) if e > s => &text[s..e],
        _ => &text[..],
    };
    serde_json::from_str(trimmed).map_err(|e| format!("LLM returned invalid batch: {e}"))
}

fn compile_proposal(
    raw: &LlmProposal,
    current_policy: &Policy,
    evidence_map: &std::collections::HashMap<String, ProposalEvidence>,
) -> Option<Proposal> {
    let ev = evidence_map.get(&raw.tool_name)?;
    match raw.kind.as_str() {
        "tighten" => make_tighten(ev, current_policy),
        "loosen" => make_loosen(ev, current_policy),
        "mark_read_only" => make_read_only(ev, current_policy),
        "register_tool" => make_register(ev, raw, current_policy),
        _ => None,
    }
}

fn current_requirement(policy: &Policy, tool_name: &str) -> ResourceRequirement {
    policy
        .requirements()
        .find(|r| r.name == tool_name && r.resource_type == ResourceType::Tool)
        .cloned()
        .unwrap_or_else(|| {
            ResourceRequirement::new_tool(tool_name, policy.default_required_trust)
        })
}

const LADDER: [TrustLevel; 4] = [
    TrustLevel::Untrusted,
    TrustLevel::Tool,
    TrustLevel::User,
    TrustLevel::System,
];

fn step(level: TrustLevel, up: bool) -> Option<TrustLevel> {
    let idx = LADDER.iter().position(|&l| l == level)?;
    let new_idx = if up { idx + 1 } else { idx.checked_sub(1)? };
    LADDER.get(new_idx).copied()
}

fn make_tighten(ev: &ProposalEvidence, current_policy: &Policy) -> Option<Proposal> {
    let cur = current_requirement(current_policy, &ev.tool_name);
    let new_level = step(cur.required_trust, true)?;
    if new_level == cur.required_trust {
        return None;
    }
    Some(Proposal {
        kind: ProposalKind::TightenRequirement,
        tool_name: ev.tool_name.clone(),
        current_required_trust: cur.required_trust,
        proposed_required_trust: new_level,
        summary: format!(
            "Raise required_trust on {} from {} to {} (LLM-suggested)",
            ev.tool_name,
            trust_level_name(cur.required_trust),
            trust_level_name(new_level),
        ),
        rationale: format!(
            "LLM proposer flagged {}: {} of {} recorded allows are labeled INCORRECT, \
             vs {} labeled CORRECT. Tightening should deny the labeled-incorrect allows.",
            ev.tool_name,
            ev.labeled_incorrect_allows,
            ev.allowed,
            ev.labeled_correct_allows,
        ),
        evidence: ev.clone(),
        diff: format!(
            "{}: required_trust {} -> {}",
            ev.tool_name,
            trust_level_name(cur.required_trust),
            trust_level_name(new_level),
        ),
    })
}

fn make_loosen(ev: &ProposalEvidence, current_policy: &Policy) -> Option<Proposal> {
    let cur = current_requirement(current_policy, &ev.tool_name);
    let new_level = step(cur.required_trust, false)?;
    if new_level == cur.required_trust {
        return None;
    }
    Some(Proposal {
        kind: ProposalKind::LoosenRequirement,
        tool_name: ev.tool_name.clone(),
        current_required_trust: cur.required_trust,
        proposed_required_trust: new_level,
        summary: format!(
            "Lower required_trust on {} from {} to {} (LLM-suggested)",
            ev.tool_name,
            trust_level_name(cur.required_trust),
            trust_level_name(new_level),
        ),
        rationale: format!(
            "LLM proposer flagged {}: {} of {} recorded denials are labeled INCORRECT, \
             vs {} labeled CORRECT. Loosening should let the labeled-incorrect denials through.",
            ev.tool_name,
            ev.labeled_incorrect_denials,
            ev.denied,
            ev.labeled_correct_denials,
        ),
        evidence: ev.clone(),
        diff: format!(
            "{}: required_trust {} -> {}",
            ev.tool_name,
            trust_level_name(cur.required_trust),
            trust_level_name(new_level),
        ),
    })
}

fn make_read_only(ev: &ProposalEvidence, current_policy: &Policy) -> Option<Proposal> {
    let cur = current_requirement(current_policy, &ev.tool_name);
    if !cur.side_effects {
        return None;
    }
    Some(Proposal {
        kind: ProposalKind::LoosenRequirement,
        tool_name: ev.tool_name.clone(),
        current_required_trust: cur.required_trust,
        proposed_required_trust: cur.required_trust,
        summary: format!("Mark {} as read-only (side_effects=false)", ev.tool_name),
        rationale: format!(
            "LLM proposer flagged {} as appearing read-only on its observed traffic. \
             Setting side_effects=false exempts it from the taint-floor denial.",
            ev.tool_name,
        ),
        evidence: ev.clone(),
        diff: format!("{}: side_effects true -> false", ev.tool_name),
    })
}

fn make_register(
    ev: &ProposalEvidence,
    raw: &LlmProposal,
    current_policy: &Policy,
) -> Option<Proposal> {
    let registered = current_policy
        .requirements()
        .any(|r| r.name == ev.tool_name && r.resource_type == ResourceType::Tool);
    if registered {
        return None;
    }
    let target = match raw.target_trust.as_deref().unwrap_or("USER") {
        "UNTRUSTED" => TrustLevel::Untrusted,
        "TOOL" => TrustLevel::Tool,
        "USER" => TrustLevel::User,
        "SYSTEM" => TrustLevel::System,
        _ => return None,
    };
    Some(Proposal {
        kind: ProposalKind::TightenRequirement,
        tool_name: ev.tool_name.clone(),
        current_required_trust: current_policy.default_required_trust,
        proposed_required_trust: target,
        summary: format!(
            "Register {} with required_trust={}",
            ev.tool_name,
            trust_level_name(target),
        ),
        rationale: format!(
            "{} appears in audit but has no explicit requirement; falls back to \
             default_required_trust={}. An explicit registration makes the rule audit-friendly.",
            ev.tool_name,
            trust_level_name(current_policy.default_required_trust),
        ),
        evidence: ev.clone(),
        diff: format!(
            "{}: register required_trust={}",
            ev.tool_name,
            trust_level_name(target),
        ),
    })
}

fn trust_level_name(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Untrusted => "UNTRUSTED",
        TrustLevel::Tool => "TOOL",
        TrustLevel::User => "USER",
        TrustLevel::System => "SYSTEM",
    }
}

/// Re-export of the synchronous evidence collector from
/// `tessera_policy::builder` so callers can build the input prompt
/// without needing a second dependency. Returns the same map
/// `analyze` would produce.
fn collect_evidence(
    audit_log_path: impl AsRef<std::path::Path>,
    labels: Option<&LabelStore>,
) -> Result<std::collections::HashMap<String, ProposalEvidence>, String> {
    use tessera_policy::replay::iter_replay_cases;
    let cases = iter_replay_cases(audit_log_path, None, None, None, None)?;
    let mut counts: std::collections::HashMap<String, ProposalEvidence> =
        std::collections::HashMap::new();
    for case in cases {
        let env = &case.envelope;
        let entry =
            counts
                .entry(env.tool_name.clone())
                .or_insert_with(|| ProposalEvidence {
                    tool_name: env.tool_name.clone(),
                    total_observations: 0,
                    denied: 0,
                    allowed: 0,
                    labeled_correct_denials: 0,
                    labeled_incorrect_denials: 0,
                    labeled_correct_allows: 0,
                    labeled_incorrect_allows: 0,
                    decision_sources: std::collections::BTreeMap::new(),
                    decision_reasons: std::collections::BTreeMap::new(),
                });
        entry.total_observations += 1;
        if env.decision_allowed {
            entry.allowed += 1;
        } else {
            entry.denied += 1;
        }
        if let Some(store) = labels {
            use tessera_policy::replay::Label;
            let lbl = store.get(case.seq, Some(&case.record_hash));
            match (lbl, env.decision_allowed) {
                (Label::Correct, true) => entry.labeled_correct_allows += 1,
                (Label::Correct, false) => entry.labeled_correct_denials += 1,
                (Label::Incorrect, true) => entry.labeled_incorrect_allows += 1,
                (Label::Incorrect, false) => entry.labeled_incorrect_denials += 1,
                (Label::Unreviewed, _) => {}
            }
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_client::CannedLlmClient;
    use serde_json::json;
    use serde_json::Map;
    use tempfile::tempdir;
    use tessera_audit::{AppendEntry, JsonlHashchainSink, ReplayEnvelope};
    use tessera_policy::policy::Policy;
    use tessera_policy::replay::{Label, LabelStore, iter_replay_cases};

    fn write_event(
        sink: &JsonlHashchainSink,
        ts: &str,
        tool: &str,
        allowed: bool,
        trust_level: i64,
    ) {
        let env = ReplayEnvelope {
            trajectory_id: "t".into(),
            tool_name: tool.into(),
            args: Map::new(),
            user_prompt: String::new(),
            segments: vec![json!({"trust_level": trust_level, "content_sha256": "x"})],
            sensitivity_hwm: "PUBLIC".into(),
            decision_allowed: allowed,
            decision_source: "test".into(),
            decision_reason: "rsn".into(),
        };
        sink.append(AppendEntry {
            timestamp: ts.into(),
            kind: "policy_deny".into(),
            principal: "alice".into(),
            detail: env.to_detail(Map::new()),
            correlation_id: None,
            trace_id: None,
        })
        .unwrap();
        sink.flush().unwrap();
    }

    #[tokio::test]
    async fn propose_returns_empty_when_no_audit_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        let client = Arc::new(CannedLlmClient::new());
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let policy = Policy::new();
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn propose_compiles_loosen_from_canned_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "send_email",
                false,
                100,
            );
        }
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        let mut labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }
        let canned = format!(
            r#"{{"proposals": [{{"kind": "loosen", "tool_name": "send_email", "target_trust": null, "rationale": "many false denials", "confidence": 0.92}}]}}"#
        );
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = proposer
            .propose(&path, &policy, Some(&labels))
            .await
            .unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].kind, ProposalKind::LoosenRequirement);
        assert_eq!(proposals[0].tool_name, "send_email");
        assert_eq!(proposals[0].proposed_required_trust, TrustLevel::Tool);
    }

    #[tokio::test]
    async fn propose_compiles_register_for_unregistered_tool() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "fetch_url",
                true,
                100,
            );
        }
        let canned = format!(
            r#"{{"proposals": [{{"kind": "register_tool", "tool_name": "fetch_url", "target_trust": "TOOL", "rationale": "register explicitly", "confidence": 0.7}}]}}"#
        );
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let policy = Policy::new();
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].proposed_required_trust, TrustLevel::Tool);
    }

    #[tokio::test]
    async fn propose_skips_tool_not_in_evidence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "real_tool", true, 100);
        let canned = format!(
            r#"{{"proposals": [{{"kind": "tighten", "tool_name": "hallucinated_tool", "target_trust": "USER", "rationale": "fake", "confidence": 0.5}}]}}"#
        );
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let policy = Policy::new();
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn propose_returns_empty_on_unparseable_response() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 100);
        let client = Arc::new(CannedLlmClient::new().with_fallback("not json"));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn propose_returns_empty_when_breaker_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 100);
        let client = Arc::new(CannedLlmClient::new().always_fail("upstream down"));
        let proposer = LlmPolicyProposer::new(client, "test-model")
            .with_breaker(BreakerConfig {
                failure_threshold: 1,
                open_duration: Duration::from_secs(60),
                open_mode: OpenMode::PassThrough,
            });
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let _ = proposer.propose(&path, &policy, None).await.unwrap();
        // Second call should be skipped by the breaker.
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn propose_handles_multiple_proposals_in_batch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "send_email",
                false,
                100,
            );
            write_event(
                &sink,
                &format!("2026-04-23T00:01:0{i}+00:00"),
                "list_files",
                true,
                100,
            );
        }
        let canned = r#"{"proposals": [
            {"kind": "loosen", "tool_name": "send_email", "target_trust": null, "rationale": "x", "confidence": 0.9},
            {"kind": "tighten", "tool_name": "list_files", "target_trust": null, "rationale": "y", "confidence": 0.7}
        ]}"#;
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        policy.require_tool("list_files", TrustLevel::Tool);
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert_eq!(proposals.len(), 2);
    }

    #[tokio::test]
    async fn parse_response_strips_markdown_fences() {
        let raw = "```json\n{\"proposals\": []}\n```";
        let batch = parse_response(raw).unwrap();
        assert!(batch.proposals.is_empty());
    }

    #[tokio::test]
    async fn parse_response_extracts_first_json_object() {
        let raw = r#"Sure: {"proposals": [{"kind": "tighten", "tool_name": "x", "confidence": 0.5}]} thanks"#;
        let batch = parse_response(raw).unwrap();
        assert_eq!(batch.proposals.len(), 1);
    }

    #[tokio::test]
    async fn parse_response_errors_on_garbage() {
        assert!(parse_response("complete garbage").is_err());
    }

    #[tokio::test]
    async fn format_evidence_renders_per_tool_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 100);
        let evidence_map = collect_evidence(&path, None).unwrap();
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let formatted = LlmPolicyProposer::format_evidence(&evidence_map, &policy);
        assert!(formatted.contains("tool=send_email"));
        assert!(formatted.contains("registered=true"));
    }

    #[tokio::test]
    async fn empty_evidence_map_renders_no_observations() {
        let map = std::collections::HashMap::new();
        let policy = Policy::new();
        let formatted = LlmPolicyProposer::format_evidence(&map, &policy);
        assert_eq!(formatted, "(no observations)");
    }

    #[tokio::test]
    async fn unknown_kind_in_proposal_is_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 100);
        let canned = r#"{"proposals": [{"kind": "scuba_dive", "tool_name": "send_email", "target_trust": null, "rationale": "x", "confidence": 0.9}]}"#;
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }

    #[tokio::test]
    async fn empty_proposal_batch_returns_empty_proposals() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 100);
        let canned = r#"{"proposals": []}"#;
        let client = Arc::new(CannedLlmClient::new().with_fallback(canned));
        let proposer = LlmPolicyProposer::new(client, "test-model");
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = proposer.propose(&path, &policy, None).await.unwrap();
        assert!(proposals.is_empty());
    }
}
