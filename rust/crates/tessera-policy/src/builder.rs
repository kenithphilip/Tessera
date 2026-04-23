//! Suggest policy edits from audit history, then score them via replay.
//!
//! Deterministic foundation of the policy-builder workflow. Reads
//! the JSONL audit log, aggregates per-tool decision counts and
//! ground-truth labels, and proposes targeted [`ResourceRequirement`]
//! adjustments where the data is unambiguous. Each [`Proposal`]
//! carries the tool name and proposed trust level; build a candidate
//! [`Policy`] with [`apply_proposal`] and pass it to
//! [`score_proposal`] to measure impact via [`crate::replay`].
//!
//! No LLM here on purpose. An LLM proposer can layer on top: it
//! generates additional [`Proposal`] objects (Phase 4 ships
//! `builder_llm`) and reuses [`score_proposal`] for evaluation.
//!
//! # Heuristics
//!
//! Both rules require ground-truth labels. Without labels there is
//! no signal that a current decision is wrong, so the analyzer
//! emits no proposals.
//!
//! * **LOOSEN** `required_trust` for tool `T` by one step when at
//!   least three deny entries for `T` are labeled INCORRECT and
//!   the labeled-INCORRECT denials outnumber labeled-CORRECT.
//! * **TIGHTEN** `required_trust` for tool `T` by one step when at
//!   least three allow entries for `T` are labeled INCORRECT and
//!   the labeled-INCORRECT allows outnumber labeled-CORRECT.
//!
//! A "step" walks the canonical TrustLevel ladder
//! `Untrusted -> Tool -> User -> System`. The analyzer never
//! proposes moves outside the ladder.
//!
//! Mirrors `tessera.policy_builder` in the Python reference. The
//! Rust port carries the proposed change as data on [`Proposal`]
//! rather than as a closure factory; [`apply_proposal`] is the
//! pure function that turns a proposal into a candidate Policy.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};
use tessera_audit::ReplayEnvelope;
use tessera_core::context::{make_segment, Context};
use tessera_core::labels::{HmacSigner, Origin, TrustLevel};

use crate::policy::{DecisionKind, Policy, ResourceRequirement, ResourceType};
use crate::replay::{
    iter_replay_cases, run_replay, FallibleFn, Label, LabelStore, PolicyDecision, ReplayStats,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    TightenRequirement,
    LoosenRequirement,
}

/// Per-tool counts that support a proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalEvidence {
    pub tool_name: String,
    pub total_observations: usize,
    pub denied: usize,
    pub allowed: usize,
    pub labeled_correct_denials: usize,
    pub labeled_incorrect_denials: usize,
    pub labeled_correct_allows: usize,
    pub labeled_incorrect_allows: usize,
    pub decision_sources: BTreeMap<String, usize>,
    pub decision_reasons: BTreeMap<String, usize>,
}

/// A candidate edit to the current policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub kind: ProposalKind,
    pub tool_name: String,
    pub current_required_trust: TrustLevel,
    pub proposed_required_trust: TrustLevel,
    pub summary: String,
    pub rationale: String,
    pub evidence: ProposalEvidence,
    pub diff: String,
}

/// A proposal plus the replay stats from running it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalImpact {
    pub proposal: Proposal,
    pub stats: ReplayStats,
}

impl ProposalImpact {
    pub fn net_fixes(&self) -> i64 {
        self.stats.fixed as i64 - self.stats.regressed as i64
    }
}

// ---- Counting + analysis -------------------------------------------------

fn collect_evidence(
    audit_log_path: impl AsRef<Path>,
    labels: Option<&LabelStore>,
) -> Result<HashMap<String, ProposalEvidence>, String> {
    let cases = iter_replay_cases(audit_log_path, None, None, None, None)?;
    let mut counts: HashMap<String, ProposalEvidence> = HashMap::new();
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
                    decision_sources: BTreeMap::new(),
                    decision_reasons: BTreeMap::new(),
                });
        entry.total_observations += 1;
        if env.decision_allowed {
            entry.allowed += 1;
        } else {
            entry.denied += 1;
        }
        if !env.decision_source.is_empty() {
            *entry
                .decision_sources
                .entry(env.decision_source.clone())
                .or_insert(0) += 1;
        }
        if !env.decision_reason.is_empty() {
            *entry
                .decision_reasons
                .entry(env.decision_reason.clone())
                .or_insert(0) += 1;
        }
        if let Some(store) = labels {
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

fn current_requirement(policy: &Policy, tool_name: &str) -> ResourceRequirement {
    policy
        .requirements()
        .find(|r| r.name == tool_name && r.resource_type == ResourceType::Tool)
        .cloned()
        .unwrap_or_else(|| {
            ResourceRequirement::new_tool(tool_name, policy.default_required_trust)
        })
}

/// Apply a [`Proposal`] to a base policy. Returns a clone of the
/// base with the proposal's tool requirement updated. Does not
/// mutate `base`.
pub fn apply_proposal(base: &Policy, proposal: &Proposal) -> Policy {
    let mut next = base.clone();
    let req = current_requirement(base, &proposal.tool_name);
    next.require(ResourceRequirement {
        name: proposal.tool_name.clone(),
        resource_type: ResourceType::Tool,
        required_trust: proposal.proposed_required_trust,
        side_effects: req.side_effects,
    });
    next
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
            "Lower required_trust on {} from {} to {}",
            ev.tool_name,
            cur.required_trust.as_int(),
            new_level.as_int()
        ),
        rationale: format!(
            "{} of {} recorded denials for {} are labeled INCORRECT, vs {} labeled CORRECT. \
             Loosening would let the labeled-incorrect denials through.",
            ev.labeled_incorrect_denials,
            ev.denied,
            ev.tool_name,
            ev.labeled_correct_denials,
        ),
        evidence: ev.clone(),
        diff: format!(
            "{}: required_trust {} -> {}",
            ev.tool_name,
            cur.required_trust.as_int(),
            new_level.as_int()
        ),
    })
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
            "Raise required_trust on {} from {} to {}",
            ev.tool_name,
            cur.required_trust.as_int(),
            new_level.as_int()
        ),
        rationale: format!(
            "{} of {} recorded allows for {} are labeled INCORRECT, vs {} labeled CORRECT. \
             Tightening would deny the labeled-incorrect allows.",
            ev.labeled_incorrect_allows,
            ev.allowed,
            ev.tool_name,
            ev.labeled_correct_allows,
        ),
        evidence: ev.clone(),
        diff: format!(
            "{}: required_trust {} -> {}",
            ev.tool_name,
            cur.required_trust.as_int(),
            new_level.as_int()
        ),
    })
}

/// Read audit history and emit ToolRequirement proposals. Returns
/// an empty Vec when `labels` is `None` (the heuristics here all
/// require label signal).
pub fn analyze(
    audit_log_path: impl AsRef<Path>,
    current_policy: &Policy,
    labels: Option<&LabelStore>,
    min_label_signal: usize,
) -> Result<Vec<Proposal>, String> {
    let labels = match labels {
        Some(l) => l,
        None => return Ok(Vec::new()),
    };
    let evidence_map = collect_evidence(&audit_log_path, Some(labels))?;
    // Sort by tool name so output order is deterministic across runs.
    let mut sorted: Vec<&ProposalEvidence> = evidence_map.values().collect();
    sorted.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    let mut proposals = Vec::new();
    for ev in sorted {
        if ev.labeled_incorrect_denials >= min_label_signal
            && ev.labeled_incorrect_denials > ev.labeled_correct_denials
        {
            if let Some(p) = make_loosen(ev, current_policy) {
                proposals.push(p);
            }
        }
        if ev.labeled_incorrect_allows >= min_label_signal
            && ev.labeled_incorrect_allows > ev.labeled_correct_allows
        {
            if let Some(p) = make_tighten(ev, current_policy) {
                proposals.push(p);
            }
        }
    }
    Ok(proposals)
}

// ---- Scoring -------------------------------------------------------------

/// Build a `FallibleFn` that wraps a Policy as a replay candidate.
/// The signing key is used only to satisfy [`make_segment`]; the
/// policy engine ignores label signatures during evaluate, so the
/// placeholder key never affects the verdict.
pub fn candidate_for(policy: Policy, signing_key: Vec<u8>) -> Box<FallibleFn> {
    Box::new(move |envelope: &ReplayEnvelope| {
        let signer = HmacSigner::new(signing_key.clone());
        let mut ctx = Context::new();
        for seg in &envelope.segments {
            let trust_int = seg.get("trust_level").and_then(|v| v.as_i64()).unwrap_or(0);
            let level = TrustLevel::from_int(trust_int).unwrap_or(TrustLevel::Untrusted);
            let content = seg
                .get("content_sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            ctx.add(make_segment(
                content,
                Origin::Web,
                "policy_builder",
                &signer,
                Some(level),
            ));
        }
        let decision = policy.evaluate(&ctx, &envelope.tool_name);
        Ok(PolicyDecision {
            allowed: decision.kind == DecisionKind::Allow,
            reason: decision.reason,
            source: "tessera.policy_builder.candidate".to_string(),
            metadata: serde_json::Value::Null,
        })
    })
}

/// Score one proposal: build the candidate Policy via
/// [`apply_proposal`], replay it against `audit_log_path`, return
/// the [`ReplayStats`] wrapped in a [`ProposalImpact`].
pub fn score_proposal(
    proposal: &Proposal,
    audit_log_path: impl AsRef<Path>,
    base_policy: &Policy,
    labels: Option<&LabelStore>,
    signing_key: Vec<u8>,
) -> Result<ProposalImpact, String> {
    let candidate_policy = apply_proposal(base_policy, proposal);
    let cb = candidate_for(candidate_policy, signing_key);
    let (stats, _results) = run_replay(audit_log_path, &*cb, labels, None, None, None, None)?;
    Ok(ProposalImpact {
        proposal: proposal.clone(),
        stats,
    })
}

/// Convenience: analyze, score every proposal, return ranked by
/// `net_fixes` descending; ties broken by smaller blast radius
/// (fewer overall disagreements).
pub fn analyze_and_score(
    audit_log_path: impl AsRef<Path>,
    current_policy: &Policy,
    labels: Option<&LabelStore>,
    min_label_signal: usize,
    signing_key: Vec<u8>,
) -> Result<Vec<ProposalImpact>, String> {
    let proposals = analyze(&audit_log_path, current_policy, labels, min_label_signal)?;
    let mut impacts = Vec::with_capacity(proposals.len());
    for p in &proposals {
        impacts.push(score_proposal(
            p,
            &audit_log_path,
            current_policy,
            labels,
            signing_key.clone(),
        )?);
    }
    impacts.sort_by(|a, b| {
        b.net_fixes()
            .cmp(&a.net_fixes())
            .then(a.stats.disagreed.cmp(&b.stats.disagreed))
    });
    Ok(impacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};
    use tempfile::tempdir;
    use tessera_audit::{AppendEntry, JsonlHashchainSink};

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
        // Force the writer thread to flush so iter_replay_cases sees
        // the record on the next read. Production callers do not need
        // this; the writer drains continuously and Drop guarantees a
        // final flush. Tests that write-then-immediately-read need it.
        sink.flush().unwrap();
    }

    #[test]
    fn step_walks_ladder_in_both_directions() {
        assert_eq!(step(TrustLevel::Untrusted, true), Some(TrustLevel::Tool));
        assert_eq!(step(TrustLevel::Tool, true), Some(TrustLevel::User));
        assert_eq!(step(TrustLevel::User, true), Some(TrustLevel::System));
        assert_eq!(step(TrustLevel::System, true), None);

        assert_eq!(step(TrustLevel::System, false), Some(TrustLevel::User));
        assert_eq!(step(TrustLevel::User, false), Some(TrustLevel::Tool));
        assert_eq!(step(TrustLevel::Tool, false), Some(TrustLevel::Untrusted));
        assert_eq!(step(TrustLevel::Untrusted, false), None);
    }

    #[test]
    fn analyze_with_no_labels_returns_empty() {
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
        let policy = Policy::new();
        let proposals = analyze(&path, &policy, None, 3).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn analyze_emits_loosen_when_majority_denials_labeled_incorrect() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // 5 denials all marked incorrect.
        for i in 0..5 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "send_email",
                false,
                100,
            );
        }
        // The chain prepends seq 1..=5; LabelStore keys on (seq, record_hash).
        // We do not know the exact hashes here, so call without hashes:
        // store labels by seq; LabelStore::get with None hash is permissive.
        let mut labels = LabelStore::new();
        for i in 0..5 {
            labels.set(i + 1, "irrelevant", Label::Incorrect);
        }
        // The Rust LabelStore checks the hash when supplied. To avoid a
        // chicken-and-egg issue, query labels without a hash via a custom
        // store loaded with the actual seq + hash from iter_replay_cases.
        // For this test, we patch every hash with the case's actual hash.
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }

        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = analyze(&path, &policy, Some(&labels), 3).unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].kind, ProposalKind::LoosenRequirement);
        assert_eq!(proposals[0].tool_name, "send_email");
        assert_eq!(proposals[0].current_required_trust, TrustLevel::User);
        assert_eq!(proposals[0].proposed_required_trust, TrustLevel::Tool);
    }

    #[test]
    fn analyze_emits_tighten_when_majority_allows_labeled_incorrect() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..5 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "send_email",
                true,
                100,
            );
        }
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        let mut labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::Tool);
        let proposals = analyze(&path, &policy, Some(&labels), 3).unwrap();
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].kind, ProposalKind::TightenRequirement);
        assert_eq!(proposals[0].proposed_required_trust, TrustLevel::User);
    }

    #[test]
    fn analyze_skips_below_min_label_signal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // Only 2 denials labeled incorrect; default min is 3.
        for i in 0..2 {
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
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = analyze(&path, &policy, Some(&labels), 3).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn analyze_skips_when_correct_outweighs_incorrect() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..6 {
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
        // 3 incorrect, 3 correct: incorrect not strictly > correct.
        for (i, c) in cases.iter().enumerate() {
            let lbl = if i < 3 { Label::Incorrect } else { Label::Correct };
            labels.set(c.seq, &c.record_hash, lbl);
        }
        let mut policy = Policy::new();
        policy.require_tool("send_email", TrustLevel::User);
        let proposals = analyze(&path, &policy, Some(&labels), 3).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn analyze_skips_at_ladder_boundary() {
        // tool already at Untrusted: cannot loosen further.
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..5 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "edge_tool",
                false,
                100,
            );
        }
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        let mut labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }
        let mut policy = Policy::new();
        policy.require_tool("edge_tool", TrustLevel::Untrusted);
        let proposals = analyze(&path, &policy, Some(&labels), 3).unwrap();
        assert!(proposals.is_empty());
    }

    #[test]
    fn apply_proposal_is_pure() {
        let mut base = Policy::new();
        base.require_tool("send_email", TrustLevel::User);
        let ev = ProposalEvidence {
            tool_name: "send_email".into(),
            total_observations: 10,
            denied: 5,
            allowed: 5,
            labeled_correct_denials: 0,
            labeled_incorrect_denials: 5,
            labeled_correct_allows: 0,
            labeled_incorrect_allows: 0,
            decision_sources: BTreeMap::new(),
            decision_reasons: BTreeMap::new(),
        };
        let proposal = Proposal {
            kind: ProposalKind::LoosenRequirement,
            tool_name: "send_email".into(),
            current_required_trust: TrustLevel::User,
            proposed_required_trust: TrustLevel::Tool,
            summary: "x".into(),
            rationale: "y".into(),
            evidence: ev,
            diff: "d".into(),
        };
        let next = apply_proposal(&base, &proposal);
        // base unchanged.
        let base_req = current_requirement(&base, "send_email");
        assert_eq!(base_req.required_trust, TrustLevel::User);
        // next has the new requirement.
        let next_req = current_requirement(&next, "send_email");
        assert_eq!(next_req.required_trust, TrustLevel::Tool);
    }

    #[test]
    fn score_proposal_runs_against_audit_history() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // 5 denied calls at trust_level 50 (Tool); current policy requires User=100 (denied).
        for i in 0..5 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "send_email",
                false,
                50,
            );
        }
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        let mut labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }
        let mut base = Policy::new();
        base.require_tool("send_email", TrustLevel::User);

        let proposal = make_loosen(
            &collect_evidence(&path, Some(&labels))
                .unwrap()
                .get("send_email")
                .unwrap()
                .clone(),
            &base,
        )
        .unwrap();
        let key = b"\x00".repeat(32);
        let impact = score_proposal(&proposal, &path, &base, Some(&labels), key).unwrap();
        // The candidate flips deny to allow on every case (Tool >= Tool).
        assert_eq!(impact.stats.flipped_deny_to_allow, 5);
        assert_eq!(impact.stats.fixed, 5);
        assert_eq!(impact.stats.regressed, 0);
        assert_eq!(impact.net_fixes(), 5);
    }

    #[test]
    fn analyze_and_score_orders_by_net_fixes_descending() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // 5 denials on tool A (loosen will fix 5).
        for i in 0..5 {
            write_event(
                &sink,
                &format!("2026-04-23T00:00:0{i}+00:00"),
                "tool_a",
                false,
                50,
            );
        }
        // 4 denials on tool B (loosen will fix 4).
        for i in 0..4 {
            write_event(
                &sink,
                &format!("2026-04-23T00:01:0{i}+00:00"),
                "tool_b",
                false,
                50,
            );
        }
        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        let mut labels = LabelStore::new();
        for c in &cases {
            labels.set(c.seq, &c.record_hash, Label::Incorrect);
        }
        let mut base = Policy::new();
        base.require_tool("tool_a", TrustLevel::User);
        base.require_tool("tool_b", TrustLevel::User);
        let key = b"\x00".repeat(32);
        let impacts = analyze_and_score(&path, &base, Some(&labels), 3, key).unwrap();
        assert!(impacts.len() >= 2);
        // First proposal should fix more.
        assert!(impacts[0].net_fixes() >= impacts[1].net_fixes());
    }

    #[test]
    fn collect_evidence_aggregates_per_tool_counts() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        write_event(&sink, "2026-04-23T00:00:00+00:00", "send_email", false, 0);
        write_event(&sink, "2026-04-23T00:00:01+00:00", "send_email", true, 100);
        write_event(&sink, "2026-04-23T00:00:02+00:00", "list_files", true, 100);

        let evidence = collect_evidence(&path, None).unwrap();
        let send = evidence.get("send_email").unwrap();
        assert_eq!(send.total_observations, 2);
        assert_eq!(send.denied, 1);
        assert_eq!(send.allowed, 1);
        let list = evidence.get("list_files").unwrap();
        assert_eq!(list.total_observations, 1);
        assert_eq!(list.allowed, 1);
    }
}
