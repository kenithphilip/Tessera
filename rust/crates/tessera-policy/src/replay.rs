//! Replay historical decisions against a candidate policy.
//!
//! Given a hash-chained audit log produced by [`tessera_audit`],
//! reconstruct the inputs to each decision (from the `replay`
//! envelope embedded in `SecurityEvent.detail`) and re-run them
//! against a candidate policy callable. Compare the candidate's
//! decision to the one that was recorded at the time and score the
//! result.
//!
//! Mirrors `tessera.replay` in the Python reference. The on-disk
//! audit format is the contract; ground-truth labels persist as
//! their own JSON file keyed by `(seq, record_hash)` so labels stay
//! attached across a chain rewrite.
//!
//! # Scope
//! This module does NOT re-execute the tool, NOT call the LLM. It
//! only re-runs the policy callable against the recorded envelope.
//! The candidate may consult its own signers, CEL engine, or
//! backends, but it must be pure with respect to the envelope: side
//! effects corrupt the run.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tessera_audit::{iter_records, ReplayEnvelope};

/// Did the candidate match the recorded decision?
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agreement {
    Agreed,
    Disagreed,
    Errored,
}

/// Human judgment on whether the original decision was right.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Correct,
    Incorrect,
    Unreviewed,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Correct => "correct",
            Label::Incorrect => "incorrect",
            Label::Unreviewed => "unreviewed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "correct" => Some(Label::Correct),
            "incorrect" => Some(Label::Incorrect),
            "unreviewed" => Some(Label::Unreviewed),
            _ => None,
        }
    }
}

/// One replayable audit entry.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayCase {
    pub seq: u64,
    pub record_hash: String,
    pub timestamp: String,
    pub envelope: ReplayEnvelope,
}

/// Decision returned by a candidate policy.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub metadata: Value,
}

/// Output of running one candidate against one case.
#[derive(Clone, Debug, PartialEq)]
pub struct ReplayResult {
    pub case: ReplayCase,
    pub agreement: Agreement,
    pub new_decision: Option<PolicyDecision>,
    pub error: Option<String>,
}

/// Aggregate statistics for a replay run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStats {
    pub total: usize,
    pub agreed: usize,
    pub disagreed: usize,
    pub errored: usize,
    pub flipped_allow_to_deny: usize,
    pub flipped_deny_to_allow: usize,
    pub labels: BTreeMap<String, usize>,
    pub fixed: usize,
    pub regressed: usize,
}

// ---- LabelStore ----------------------------------------------------------

/// In-memory store of ground-truth labels keyed by `(seq,
/// record_hash)`. The hash makes a label portable across a chain
/// rewrite: when the stored hash no longer matches the current
/// record hash, [`get`] returns `Unreviewed`.
///
/// Persistence is a JSON file: `{ "<seq>": { "hash": "...",
/// "label": "..." }, ... }`. Matches the Python wire format.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LabelStore {
    inner: BTreeMap<u64, (String, Label)>,
}

impl LabelStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, seq: u64, record_hash: impl Into<String>, label: Label) {
        self.inner.insert(seq, (record_hash.into(), label));
    }

    /// Return the label for `seq`, or `Unreviewed` when missing or
    /// when the stored hash does not match the supplied one.
    pub fn get(&self, seq: u64, record_hash: Option<&str>) -> Label {
        let entry = match self.inner.get(&seq) {
            Some(e) => e,
            None => return Label::Unreviewed,
        };
        if let Some(h) = record_hash {
            if entry.0 != h {
                return Label::Unreviewed;
            }
        }
        entry.1
    }

    pub fn all(&self) -> &BTreeMap<u64, (String, Label)> {
        &self.inner
    }

    /// Serialize to the Python-compatible JSON wire format.
    pub fn dump(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let mut map = BTreeMap::new();
        for (seq, (h, lbl)) in &self.inner {
            let mut entry = serde_json::Map::new();
            entry.insert("hash".into(), Value::String(h.clone()));
            entry.insert("label".into(), Value::String(lbl.as_str().to_string()));
            map.insert(seq.to_string(), Value::Object(entry));
        }
        let body = serde_json::to_string_pretty(&map).expect("LabelStore serializes");
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, body)
    }

    /// Load a store from `path`. Returns an empty store when the
    /// file does not exist (matches Python).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let body = std::fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
        let raw: BTreeMap<String, Value> =
            serde_json::from_str(&body).map_err(|e| format!("malformed label file: {e}"))?;
        let mut store = Self::default();
        for (seq_str, entry) in raw {
            let seq: u64 = seq_str.parse().map_err(|e| format!("bad seq key: {e}"))?;
            let hash = entry
                .get("hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing hash field".to_string())?
                .to_string();
            let label_str = entry
                .get("label")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing label field".to_string())?;
            let label = Label::from_str(label_str)
                .ok_or_else(|| format!("unknown label {label_str:?}"))?;
            store.inner.insert(seq, (hash, label));
        }
        Ok(store)
    }
}

// ---- Iteration filters ---------------------------------------------------

fn in_time_range(
    timestamp: &str,
    since: Option<&DateTime<Utc>>,
    until: Option<&DateTime<Utc>>,
) -> bool {
    if since.is_none() && until.is_none() {
        return true;
    }
    let parsed = match DateTime::parse_from_rfc3339(timestamp) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return since.is_none() && until.is_none(),
    };
    if let Some(s) = since {
        if parsed < *s {
            return false;
        }
    }
    if let Some(u) = until {
        if parsed > *u {
            return false;
        }
    }
    true
}

/// Walk the audit log and yield every entry that carries a replay
/// envelope. Filters by `kinds`, time range, and `trajectory_id`.
pub fn iter_replay_cases(
    audit_log_path: impl AsRef<Path>,
    kinds: Option<&[String]>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    trajectory_id: Option<&str>,
) -> Result<Vec<ReplayCase>, String> {
    let records = iter_records(audit_log_path).map_err(|e| format!("audit_log: {e:?}"))?;
    let mut out = Vec::new();
    for record in records {
        if let Some(ks) = kinds {
            if !ks.iter().any(|k| k == &record.kind) {
                continue;
            }
        }
        if !in_time_range(&record.timestamp, since.as_ref(), until.as_ref()) {
            continue;
        }
        let envelope = match ReplayEnvelope::from_detail(&record.detail) {
            Some(e) => e,
            None => continue,
        };
        if let Some(tid) = trajectory_id {
            if envelope.trajectory_id != tid {
                continue;
            }
        }
        out.push(ReplayCase {
            seq: record.seq,
            record_hash: record.hash,
            timestamp: record.timestamp,
            envelope,
        });
    }
    Ok(out)
}

// ---- Replay + scoring ----------------------------------------------------

/// A candidate policy: pure function from envelope to decision.
/// Matches the Python `PolicyFn` Protocol.
pub type PolicyFn = dyn Fn(&ReplayEnvelope) -> PolicyDecision + Sync;

/// A candidate policy that may panic. The replay loop catches
/// panics and converts them to `Errored` results so a single bad
/// case does not abort the run. Use [`replay`] for the catching
/// variant; [`replay_strict`] re-raises panics.
pub type FallibleFn =
    dyn Fn(&ReplayEnvelope) -> Result<PolicyDecision, String> + Sync;

fn decide_agreement(original: bool, candidate: &PolicyDecision) -> Agreement {
    if candidate.allowed == original {
        Agreement::Agreed
    } else {
        Agreement::Disagreed
    }
}

/// Replay every case through `candidate`. Returns one
/// [`ReplayResult`] per case in input order.
pub fn replay(cases: &[ReplayCase], candidate: &FallibleFn) -> Vec<ReplayResult> {
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        match candidate(&case.envelope) {
            Ok(decision) => {
                let agreement = decide_agreement(case.envelope.decision_allowed, &decision);
                results.push(ReplayResult {
                    case: case.clone(),
                    agreement,
                    new_decision: Some(decision),
                    error: None,
                });
            }
            Err(msg) => {
                results.push(ReplayResult {
                    case: case.clone(),
                    agreement: Agreement::Errored,
                    new_decision: None,
                    error: Some(msg),
                });
            }
        }
    }
    results
}

/// Aggregate replay results. When `labels` is supplied, `fixed` /
/// `regressed` are filled from the label map; without labels they
/// are 0.
pub fn score(results: &[ReplayResult], labels: Option<&LabelStore>) -> ReplayStats {
    let mut stats = ReplayStats {
        total: 0,
        agreed: 0,
        disagreed: 0,
        errored: 0,
        flipped_allow_to_deny: 0,
        flipped_deny_to_allow: 0,
        labels: BTreeMap::new(),
        fixed: 0,
        regressed: 0,
    };
    for result in results {
        stats.total += 1;
        match result.agreement {
            Agreement::Agreed => stats.agreed += 1,
            Agreement::Disagreed => {
                stats.disagreed += 1;
                if let Some(d) = &result.new_decision {
                    let original = result.case.envelope.decision_allowed;
                    if original && !d.allowed {
                        stats.flipped_allow_to_deny += 1;
                    } else if !original && d.allowed {
                        stats.flipped_deny_to_allow += 1;
                    }
                }
            }
            Agreement::Errored => stats.errored += 1,
        }
        let lbl = match labels {
            Some(store) => store.get(result.case.seq, Some(&result.case.record_hash)),
            None => Label::Unreviewed,
        };
        *stats.labels.entry(lbl.as_str().to_string()).or_insert(0) += 1;
        if labels.is_some() && result.agreement == Agreement::Disagreed {
            match lbl {
                Label::Incorrect => stats.fixed += 1,
                Label::Correct => stats.regressed += 1,
                Label::Unreviewed => {}
            }
        }
    }
    stats
}

/// Convenience: iterate, replay, score in one call. Returns
/// `(stats, results)`.
pub fn run_replay(
    audit_log_path: impl AsRef<Path>,
    candidate: &FallibleFn,
    labels: Option<&LabelStore>,
    kinds: Option<&[String]>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    trajectory_id: Option<&str>,
) -> Result<(ReplayStats, Vec<ReplayResult>), String> {
    let cases = iter_replay_cases(audit_log_path, kinds, since, until, trajectory_id)?;
    let results = replay(&cases, candidate);
    let stats = score(&results, labels);
    Ok((stats, results))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Map};
    use tempfile::tempdir;
    use tessera_audit::{AppendEntry, JsonlHashchainSink};

    fn write_audit_log(events: &[(u64, &str, ReplayEnvelope, &str, &str)]) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for (i, kind, env, ts, _) in events {
            let detail = env.to_detail(Map::new());
            sink.append(AppendEntry {
                timestamp: ts.to_string(),
                kind: kind.to_string(),
                principal: format!("rust-test-{i}"),
                detail,
                correlation_id: None,
                trace_id: None,
            })
            .unwrap();
        }
        dir
    }

    fn fixed_envelope(tid: &str, tool: &str, allowed: bool) -> ReplayEnvelope {
        ReplayEnvelope {
            trajectory_id: tid.to_string(),
            tool_name: tool.to_string(),
            args: Map::new(),
            user_prompt: String::new(),
            segments: Vec::new(),
            sensitivity_hwm: "PUBLIC".to_string(),
            decision_allowed: allowed,
            decision_source: "test".to_string(),
            decision_reason: String::new(),
        }
    }

    #[test]
    fn label_round_trip_via_strings() {
        for lbl in [Label::Correct, Label::Incorrect, Label::Unreviewed] {
            assert_eq!(Label::from_str(lbl.as_str()), Some(lbl));
        }
        assert_eq!(Label::from_str("garbage"), None);
    }

    #[test]
    fn label_store_set_get_round_trip() {
        let mut store = LabelStore::new();
        store.set(7, "abc", Label::Correct);
        assert_eq!(store.get(7, Some("abc")), Label::Correct);
        assert_eq!(store.get(7, Some("wrong-hash")), Label::Unreviewed);
        assert_eq!(store.get(99, None), Label::Unreviewed);
    }

    #[test]
    fn label_store_dump_load_round_trip() {
        let mut store = LabelStore::new();
        store.set(1, "h1", Label::Correct);
        store.set(2, "h2", Label::Incorrect);
        let dir = tempdir().unwrap();
        let path = dir.path().join("labels.json");
        store.dump(&path).unwrap();
        let loaded = LabelStore::load(&path).unwrap();
        assert_eq!(loaded.get(1, Some("h1")), Label::Correct);
        assert_eq!(loaded.get(2, Some("h2")), Label::Incorrect);
    }

    #[test]
    fn label_store_load_missing_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let store = LabelStore::load(&path).unwrap();
        assert!(store.all().is_empty());
    }

    #[test]
    fn iter_replay_cases_finds_only_records_with_envelope() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // One with envelope.
        let env = fixed_envelope("traj-1", "send_email", true);
        sink.append(AppendEntry {
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            kind: "policy_deny".into(),
            principal: "alice".into(),
            detail: env.to_detail(Map::new()),
            correlation_id: None,
            trace_id: None,
        })
        .unwrap();
        // One without.
        sink.append(AppendEntry {
            timestamp: "2026-04-23T00:00:01+00:00".into(),
            kind: "policy_deny".into(),
            principal: "alice".into(),
            detail: json!({"unrelated": "value"}),
            correlation_id: None,
            trace_id: None,
        })
        .unwrap();

        let cases = iter_replay_cases(&path, None, None, None, None).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].envelope.trajectory_id, "traj-1");
    }

    #[test]
    fn iter_replay_cases_filters_by_kind() {
        let env = fixed_envelope("t", "x", true);
        let dir = write_audit_log(&[
            (1, "policy_deny", env.clone(), "2026-04-23T00:00:00+00:00", ""),
            (2, "label_verify_failure", env.clone(), "2026-04-23T00:00:01+00:00", ""),
        ]);
        let path = dir.path().join("audit.jsonl");
        let kinds: Vec<String> = vec!["policy_deny".to_string()];
        let cases = iter_replay_cases(&path, Some(&kinds), None, None, None).unwrap();
        assert_eq!(cases.len(), 1);
    }

    #[test]
    fn iter_replay_cases_filters_by_trajectory_id() {
        let env_a = fixed_envelope("traj-A", "x", true);
        let env_b = fixed_envelope("traj-B", "x", true);
        let dir = write_audit_log(&[
            (1, "policy_deny", env_a, "2026-04-23T00:00:00+00:00", ""),
            (2, "policy_deny", env_b, "2026-04-23T00:00:01+00:00", ""),
        ]);
        let path = dir.path().join("audit.jsonl");
        let cases = iter_replay_cases(&path, None, None, None, Some("traj-A")).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].envelope.trajectory_id, "traj-A");
    }

    #[test]
    fn iter_replay_cases_filters_by_time_range() {
        let env = fixed_envelope("t", "x", true);
        let dir = write_audit_log(&[
            (1, "policy_deny", env.clone(), "2026-04-22T00:00:00+00:00", ""),
            (2, "policy_deny", env.clone(), "2026-04-23T00:00:00+00:00", ""),
            (3, "policy_deny", env, "2026-04-24T00:00:00+00:00", ""),
        ]);
        let path = dir.path().join("audit.jsonl");
        let since = DateTime::parse_from_rfc3339("2026-04-23T00:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let until = DateTime::parse_from_rfc3339("2026-04-23T23:59:59+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let cases =
            iter_replay_cases(&path, None, Some(since), Some(until), None).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].timestamp, "2026-04-23T00:00:00+00:00");
    }

    #[test]
    fn replay_agreement_when_decision_matches() {
        let env = fixed_envelope("t", "x", true);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: true,
                ..Default::default()
            })
        });
        let results = replay(&[case], &*candidate);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agreement, Agreement::Agreed);
    }

    #[test]
    fn replay_disagreement_when_decision_flips() {
        let env = fixed_envelope("t", "x", true);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: false,
                reason: "flip".into(),
                ..Default::default()
            })
        });
        let results = replay(&[case], &*candidate);
        assert_eq!(results[0].agreement, Agreement::Disagreed);
    }

    #[test]
    fn replay_error_propagates_as_errored_result() {
        let env = fixed_envelope("t", "x", true);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> =
            Box::new(|_e| Err("intentional candidate failure".to_string()));
        let results = replay(&[case], &*candidate);
        assert_eq!(results[0].agreement, Agreement::Errored);
        assert!(results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("intentional candidate failure"));
    }

    #[test]
    fn score_counts_flipped_allow_to_deny() {
        let env = fixed_envelope("t", "x", true);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: false,
                ..Default::default()
            })
        });
        let results = replay(&[case], &*candidate);
        let stats = score(&results, None);
        assert_eq!(stats.flipped_allow_to_deny, 1);
        assert_eq!(stats.flipped_deny_to_allow, 0);
    }

    #[test]
    fn score_counts_flipped_deny_to_allow() {
        let env = fixed_envelope("t", "x", false);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: true,
                ..Default::default()
            })
        });
        let results = replay(&[case], &*candidate);
        let stats = score(&results, None);
        assert_eq!(stats.flipped_deny_to_allow, 1);
        assert_eq!(stats.flipped_allow_to_deny, 0);
    }

    #[test]
    fn score_with_labels_counts_fixed_and_regressed() {
        let env_t = fixed_envelope("t", "x", true);
        let env_f = fixed_envelope("t", "y", false);
        let cases = vec![
            ReplayCase {
                seq: 1,
                record_hash: "h1".into(),
                timestamp: "2026-04-23T00:00:00+00:00".into(),
                envelope: env_t.clone(),
            },
            ReplayCase {
                seq: 2,
                record_hash: "h2".into(),
                timestamp: "2026-04-23T00:00:01+00:00".into(),
                envelope: env_f,
            },
        ];
        // Candidate flips both.
        let candidate: Box<FallibleFn> = Box::new(|e| {
            Ok(PolicyDecision {
                allowed: !e.decision_allowed,
                ..Default::default()
            })
        });
        let results = replay(&cases, &*candidate);
        let mut labels = LabelStore::new();
        labels.set(1, "h1", Label::Incorrect);
        labels.set(2, "h2", Label::Correct);
        let stats = score(&results, Some(&labels));
        // case 1: original allow, recorded as Incorrect -> flip is fix.
        // case 2: original deny, recorded as Correct -> flip is regression.
        assert_eq!(stats.fixed, 1);
        assert_eq!(stats.regressed, 1);
    }

    #[test]
    fn score_without_labels_marks_everything_unreviewed() {
        let env = fixed_envelope("t", "x", true);
        let case = ReplayCase {
            seq: 1,
            record_hash: "h".into(),
            timestamp: "2026-04-23T00:00:00+00:00".into(),
            envelope: env,
        };
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: true,
                ..Default::default()
            })
        });
        let results = replay(&[case], &*candidate);
        let stats = score(&results, None);
        assert_eq!(stats.labels.get("unreviewed"), Some(&1));
        assert_eq!(stats.fixed, 0);
        assert_eq!(stats.regressed, 0);
    }

    #[test]
    fn run_replay_end_to_end_yields_consistent_stats() {
        let env_a = fixed_envelope("t", "send_email", true);
        let env_b = fixed_envelope("t", "delete_file", false);
        let dir = write_audit_log(&[
            (1, "policy_deny", env_a, "2026-04-23T00:00:00+00:00", ""),
            (2, "policy_deny", env_b, "2026-04-23T00:00:01+00:00", ""),
        ]);
        let path = dir.path().join("audit.jsonl");
        // Candidate allows everything.
        let candidate: Box<FallibleFn> = Box::new(|_e| {
            Ok(PolicyDecision {
                allowed: true,
                ..Default::default()
            })
        });
        let (stats, results) =
            run_replay(&path, &*candidate, None, None, None, None, None).unwrap();
        assert_eq!(stats.total, 2);
        // Case 1 already allowed, case 2 was deny: flipping deny->allow.
        assert_eq!(stats.agreed, 1);
        assert_eq!(stats.disagreed, 1);
        assert_eq!(stats.flipped_deny_to_allow, 1);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn label_get_with_stale_hash_returns_unreviewed() {
        let mut store = LabelStore::new();
        store.set(5, "old-hash", Label::Correct);
        // Simulating a chain rewrite: hash changed.
        assert_eq!(store.get(5, Some("new-hash")), Label::Unreviewed);
    }

    #[test]
    fn replay_envelope_round_trip_through_detail() {
        let env = fixed_envelope("traj", "tool", true);
        let detail = env.to_detail(Map::new());
        let back = ReplayEnvelope::from_detail(&detail).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn replay_envelope_from_detail_returns_none_for_missing_key() {
        let v = json!({"unrelated": 1});
        assert!(ReplayEnvelope::from_detail(&v).is_none());
    }
}
