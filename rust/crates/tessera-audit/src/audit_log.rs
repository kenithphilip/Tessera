//! Append-only, hash-chained audit log.
//!
//! Mirrors `tessera.audit_log` from the Python reference. Each record
//! carries a `prev_hash` linking it to its predecessor; tamper at any
//! single event breaks verification for every subsequent event without
//! access to the signing key. Truncation is detected by an optional
//! sealing file: a separate `<path>.seal` JSON document contains the
//! last `(seq, hash)` pair plus an HMAC over them, so a truncated file
//! whose internal chain is still valid is still caught.
//!
//! The on-disk format is byte-for-byte interoperable with the Python
//! reference: same JSON keys, same canonical layout
//! (`json.dumps(..., sort_keys=True, separators=(",", ":"))`), same
//! SHA-256 over the canonical bytes excluding the `hash` field, same
//! HMAC-SHA256 seal layout. A chain written by the Rust gateway can be
//! verified by `tessera.audit_log.verify_chain` and vice versa.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One entry in the audit log with its chain hash.
///
/// `hash` is the SHA-256 of the canonical JSON of the other fields
/// (excluding `hash` itself), where `detail` is included as a
/// canonical JSON value. Field ordering does not affect the hash
/// because the canonical form sorts keys.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChainedRecord {
    pub seq: u64,
    pub timestamp: String,
    pub kind: String,
    pub principal: String,
    pub detail: Value,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// The information needed to re-evaluate a decision against a new
/// policy. Embed in `SecurityEvent.detail["replay"]` when the
/// evaluator wants the decision to be replayable. Mirrors
/// `tessera.audit_log.ReplayEnvelope`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReplayEnvelope {
    pub trajectory_id: String,
    pub tool_name: String,
    pub args: Map<String, Value>,
    #[serde(default)]
    pub user_prompt: String,
    #[serde(default)]
    pub segments: Vec<Value>,
    #[serde(default = "default_sensitivity_hwm")]
    pub sensitivity_hwm: String,
    #[serde(default = "default_decision_allowed")]
    pub decision_allowed: bool,
    #[serde(default)]
    pub decision_source: String,
    #[serde(default)]
    pub decision_reason: String,
}

fn default_sensitivity_hwm() -> String {
    "PUBLIC".to_string()
}

fn default_decision_allowed() -> bool {
    true
}

impl ReplayEnvelope {
    /// Reconstruct an envelope from a `detail["replay"]` JSON object.
    /// Returns `None` if the value is missing required fields or the
    /// wrong shape; callers should skip silently.
    pub fn from_detail(detail: &Value) -> Option<Self> {
        let payload = detail.get("replay")?;
        serde_json::from_value(payload.clone()).ok()
    }

    /// Build a `detail` JSON value that embeds this envelope under the
    /// `replay` key. `extra` is merged at the top level.
    pub fn to_detail(&self, extra: Map<String, Value>) -> Value {
        let mut base = extra;
        base.insert(
            "replay".to_string(),
            serde_json::to_value(self).expect("ReplayEnvelope serializes"),
        );
        Value::Object(base)
    }
}

impl ChainedRecord {
    /// Canonical JSON line for writing to disk. Sorted keys, no
    /// whitespace, trailing newline appended by the caller.
    pub fn to_canonical_json(&self) -> String {
        // serde_json::to_string with the default Serializer emits
        // unsorted keys for structs (insertion order). To match
        // Python's `sort_keys=True`, we go via `Map<String, Value>`
        // which we then serialize with the canonical writer below.
        let mut map = Map::new();
        map.insert("seq".into(), Value::from(self.seq));
        map.insert("timestamp".into(), Value::String(self.timestamp.clone()));
        map.insert("kind".into(), Value::String(self.kind.clone()));
        map.insert("principal".into(), Value::String(self.principal.clone()));
        map.insert("detail".into(), self.detail.clone());
        map.insert(
            "correlation_id".into(),
            self.correlation_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "trace_id".into(),
            self.trace_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        map.insert("prev_hash".into(), Value::String(self.prev_hash.clone()));
        map.insert("hash".into(), Value::String(self.hash.clone()));
        canonical_json(&Value::Object(map))
    }

    pub fn from_line(line: &str) -> Result<Self, AuditError> {
        serde_json::from_str(line).map_err(|e| AuditError::Parse(e.to_string()))
    }
}

/// Canonical JSON serialization matching Python's
/// `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
///
/// Key sort order is byte-wise on UTF-8 strings (matching Python's
/// default sort), no whitespace, no escaped non-ASCII (Python's
/// `ensure_ascii=False` is NOT used by default in
/// `tessera.audit_log`; the reference uses `ensure_ascii=True`).
/// `serde_json::to_string` already produces ASCII-escaped output by
/// default and no whitespace; we add the key sort.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).expect("string serializes"),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            // Sort keys lexicographically (matches Python's default).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let key_json = serde_json::to_string(k).expect("string serializes");
                    let val_json = canonical_json(&map[k]);
                    format!("{key_json}:{val_json}")
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Compute the canonical chain hash for a record's payload (everything
/// except the `hash` field itself).
fn compute_hash(
    seq: u64,
    timestamp: &str,
    kind: &str,
    principal: &str,
    detail: &Value,
    correlation_id: Option<&str>,
    trace_id: Option<&str>,
    prev_hash: &str,
) -> String {
    let mut map = Map::new();
    map.insert("seq".into(), Value::from(seq));
    map.insert("timestamp".into(), Value::String(timestamp.to_string()));
    map.insert("kind".into(), Value::String(kind.to_string()));
    map.insert("principal".into(), Value::String(principal.to_string()));
    map.insert("detail".into(), detail.clone());
    map.insert(
        "correlation_id".into(),
        correlation_id
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "trace_id".into(),
        trace_id
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert("prev_hash".into(), Value::String(prev_hash.to_string()));
    let canonical = canonical_json(&Value::Object(map));
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex::encode(hasher.finalize())
}

/// Sink that appends each event to a JSONL file with a chain hash.
pub struct JsonlHashchainSink {
    path: PathBuf,
    inner: Mutex<SinkInner>,
    fsync_every: u64,
    seal_key: Option<Vec<u8>>,
}

struct SinkInner {
    last_seq: u64,
    last_hash: String,
    writes_since_fsync: u64,
}

#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
    Parse(String),
    NotFound(PathBuf),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Io(e) => write!(f, "audit log io error: {e}"),
            AuditError::Parse(s) => write!(f, "audit log parse error: {s}"),
            AuditError::NotFound(p) => write!(f, "audit log file not found: {}", p.display()),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<std::io::Error> for AuditError {
    fn from(e: std::io::Error) -> Self {
        AuditError::Io(e)
    }
}

/// Input for `JsonlHashchainSink::append`.
#[derive(Clone, Debug)]
pub struct AppendEntry {
    pub timestamp: String,
    pub kind: String,
    pub principal: String,
    pub detail: Value,
    pub correlation_id: Option<String>,
    pub trace_id: Option<String>,
}

impl JsonlHashchainSink {
    /// Open a sink on `path`. Creates the parent directory if needed.
    /// Recovers `(last_seq, last_hash)` from the file tail so the chain
    /// resumes cleanly on reopen.
    pub fn new<P: AsRef<Path>>(
        path: P,
        fsync_every: u64,
        seal_key: Option<Vec<u8>>,
    ) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut sink = Self {
            path,
            inner: Mutex::new(SinkInner {
                last_seq: 0,
                last_hash: GENESIS_HASH.to_string(),
                writes_since_fsync: 0,
            }),
            fsync_every: fsync_every.max(1),
            seal_key,
        };
        sink.recover()?;
        Ok(sink)
    }

    fn recover(&mut self) -> Result<(), AuditError> {
        if !self.path.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(&self.path)?;
        if metadata.len() == 0 {
            return Ok(());
        }
        // Read the last non-empty line. Cheap full read for now;
        // matches the Python reference that reads up to 4 KiB from
        // the tail.
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut last_line: Option<String> = None;
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                last_line = Some(trimmed.to_string());
            }
        }
        let Some(last) = last_line else {
            return Ok(());
        };
        match ChainedRecord::from_line(&last) {
            Ok(record) => {
                let mut inner = self.inner.lock().unwrap();
                inner.last_seq = record.seq;
                inner.last_hash = record.hash;
            }
            Err(_) => {
                // Corrupt tail: stay at genesis. New writes will start
                // a fresh chain; verify_chain catches the resulting
                // gap if anyone trusts the whole file.
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_seq(&self) -> u64 {
        self.inner.lock().unwrap().last_seq
    }

    pub fn last_hash(&self) -> String {
        self.inner.lock().unwrap().last_hash.clone()
    }

    pub fn append(&self, entry: AppendEntry) -> Result<ChainedRecord, AuditError> {
        let mut inner = self.inner.lock().unwrap();
        let seq = inner.last_seq + 1;
        let prev_hash = inner.last_hash.clone();
        let hash = compute_hash(
            seq,
            &entry.timestamp,
            &entry.kind,
            &entry.principal,
            &entry.detail,
            entry.correlation_id.as_deref(),
            entry.trace_id.as_deref(),
            &prev_hash,
        );
        let record = ChainedRecord {
            seq,
            timestamp: entry.timestamp.clone(),
            kind: entry.kind.clone(),
            principal: entry.principal.clone(),
            detail: entry.detail.clone(),
            correlation_id: entry.correlation_id.clone(),
            trace_id: entry.trace_id.clone(),
            prev_hash,
            hash: hash.clone(),
        };
        let line = record.to_canonical_json();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        inner.writes_since_fsync += 1;
        if inner.writes_since_fsync >= self.fsync_every {
            file.flush()?;
            file.sync_data()?;
            inner.writes_since_fsync = 0;
        }
        inner.last_seq = seq;
        inner.last_hash = hash.clone();
        if let Some(key) = &self.seal_key {
            self.write_seal(seq, &hash, key)?;
        }
        Ok(record)
    }

    fn write_seal(&self, seq: u64, last_hash: &str, key: &[u8]) -> Result<(), AuditError> {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(format!("{seq}|{last_hash}").as_bytes());
        let tag = hex::encode(mac.finalize().into_bytes());
        let seal = serde_json::json!({
            "seq": seq,
            "hash": last_hash,
            "tag": tag,
        });
        let seal_path = seal_path_for(&self.path);
        let tmp = seal_path.with_extension("seal.tmp");
        std::fs::write(&tmp, canonical_json(&seal).as_bytes())?;
        std::fs::rename(tmp, seal_path)?;
        Ok(())
    }
}

fn seal_path_for(path: &Path) -> PathBuf {
    // <path>.seal regardless of existing extension, matching the
    // Python `path.with_suffix(path.suffix + ".seal")` semantics.
    let mut out = path.as_os_str().to_owned();
    out.push(".seal");
    PathBuf::from(out)
}

/// Outcome of walking the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub records_checked: u64,
    pub first_bad_seq: Option<u64>,
    pub reason: String,
    /// `Some(true)` if a seal file was checked and matched. `Some(false)`
    /// if it was checked and failed. `None` if no seal file was
    /// consulted (no key provided, or no seal file existed).
    pub seal_valid: Option<bool>,
}

/// Walk the JSONL file and verify the chain end-to-end.
pub fn verify_chain<P: AsRef<Path>>(
    path: P,
    seal_key: Option<&[u8]>,
) -> Result<VerificationResult, AuditError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(VerificationResult {
            valid: false,
            records_checked: 0,
            first_bad_seq: None,
            reason: format!("file not found: {}", path.display()),
            seal_valid: None,
        });
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq: u64 = 1;
    let mut records_checked: u64 = 0;
    let mut last_hash = GENESIS_HASH.to_string();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record = match ChainedRecord::from_line(line) {
            Ok(r) => r,
            Err(e) => {
                return Ok(VerificationResult {
                    valid: false,
                    records_checked,
                    first_bad_seq: Some(expected_seq),
                    reason: format!("unparseable record at expected seq {expected_seq}: {e}"),
                    seal_valid: None,
                });
            }
        };
        if record.seq != expected_seq {
            return Ok(VerificationResult {
                valid: false,
                records_checked,
                first_bad_seq: Some(record.seq),
                reason: format!(
                    "sequence gap: expected {expected_seq}, got {}",
                    record.seq
                ),
                seal_valid: None,
            });
        }
        if record.prev_hash != expected_prev {
            return Ok(VerificationResult {
                valid: false,
                records_checked,
                first_bad_seq: Some(record.seq),
                reason: format!(
                    "prev_hash mismatch at seq {}: expected {}, got {}",
                    record.seq,
                    &expected_prev[..16.min(expected_prev.len())],
                    &record.prev_hash[..16.min(record.prev_hash.len())]
                ),
                seal_valid: None,
            });
        }
        let computed = compute_hash(
            record.seq,
            &record.timestamp,
            &record.kind,
            &record.principal,
            &record.detail,
            record.correlation_id.as_deref(),
            record.trace_id.as_deref(),
            &record.prev_hash,
        );
        if computed != record.hash {
            return Ok(VerificationResult {
                valid: false,
                records_checked,
                first_bad_seq: Some(record.seq),
                reason: format!(
                    "hash mismatch at seq {}: record says {}, computed {}",
                    record.seq,
                    &record.hash[..16.min(record.hash.len())],
                    &computed[..16.min(computed.len())]
                ),
                seal_valid: None,
            });
        }
        records_checked += 1;
        expected_prev = record.hash.clone();
        expected_seq = record.seq + 1;
        last_hash = record.hash;
    }

    let mut seal_valid: Option<bool> = None;
    if let Some(key) = seal_key {
        let seal_path = seal_path_for(path);
        if seal_path.exists() {
            match std::fs::read_to_string(&seal_path) {
                Ok(seal_text) => match serde_json::from_str::<Value>(&seal_text) {
                    Ok(Value::Object(map)) => {
                        let stored_seq = map
                            .get("seq")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let stored_hash = map
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let stored_tag = map
                            .get("tag")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let mut mac = HmacSha256::new_from_slice(key)
                            .expect("HMAC accepts any key length");
                        mac.update(format!("{stored_seq}|{stored_hash}").as_bytes());
                        let expected_tag = hex::encode(mac.finalize().into_bytes());
                        let tag_ok = constant_time_eq(stored_tag.as_bytes(), expected_tag.as_bytes());
                        let matches_tail =
                            stored_seq == (expected_seq.saturating_sub(1)) && stored_hash == last_hash;
                        let ok = tag_ok && matches_tail;
                        seal_valid = Some(ok);
                        if !ok {
                            return Ok(VerificationResult {
                                valid: false,
                                records_checked,
                                first_bad_seq: None,
                                reason: if tag_ok {
                                    "seal does not match tail (truncation?)".to_string()
                                } else {
                                    "seal HMAC invalid".to_string()
                                },
                                seal_valid: Some(false),
                            });
                        }
                    }
                    _ => {
                        return Ok(VerificationResult {
                            valid: false,
                            records_checked,
                            first_bad_seq: None,
                            reason: "seal unreadable: not a JSON object".to_string(),
                            seal_valid: Some(false),
                        });
                    }
                },
                Err(e) => {
                    return Ok(VerificationResult {
                        valid: false,
                        records_checked,
                        first_bad_seq: None,
                        reason: format!("seal unreadable: {e}"),
                        seal_valid: Some(false),
                    });
                }
            }
        }
    }

    Ok(VerificationResult {
        valid: true,
        records_checked,
        first_bad_seq: None,
        reason: "ok".to_string(),
        seal_valid,
    })
}

/// Iterate records from the file, skipping unparseable lines. Does not
/// verify the chain. Mirrors `tessera.audit_log.iter_records`.
pub fn iter_records<P: AsRef<Path>>(path: P) -> Result<Vec<ChainedRecord>, AuditError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(record) = ChainedRecord::from_line(trimmed) {
            out.push(record);
        }
    }
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn entry(detail: Value) -> AppendEntry {
        AppendEntry {
            timestamp: "2026-04-23T00:00:00+00:00".to_string(),
            kind: "policy_deny".to_string(),
            principal: "test".to_string(),
            detail,
            correlation_id: None,
            trace_id: None,
        }
    }

    #[test]
    fn empty_file_starts_at_genesis() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        assert_eq!(sink.last_seq(), 0);
        assert_eq!(sink.last_hash(), GENESIS_HASH);
    }

    #[test]
    fn first_event_uses_genesis_prev_hash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        let r = sink.append(entry(json!({"x": 1}))).unwrap();
        assert_eq!(r.seq, 1);
        assert_eq!(r.prev_hash, GENESIS_HASH);
        assert_ne!(r.hash, GENESIS_HASH);
    }

    #[test]
    fn chain_links_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        let a = sink.append(entry(json!({"n": 1}))).unwrap();
        let b = sink.append(entry(json!({"n": 2}))).unwrap();
        let c = sink.append(entry(json!({"n": 3}))).unwrap();
        assert_eq!(a.prev_hash, GENESIS_HASH);
        assert_eq!(b.prev_hash, a.hash);
        assert_eq!(c.prev_hash, b.hash);
        assert_eq!(c.seq, 3);
    }

    #[test]
    fn file_is_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(lines.len(), 3);
        for ln in lines {
            // Each line is JSON on its own.
            let _: Value = serde_json::from_str(ln).unwrap();
        }
    }

    #[test]
    fn intact_chain_verifies() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..5 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid);
        assert_eq!(r.records_checked, 5);
        assert!(r.first_bad_seq.is_none());
    }

    #[test]
    fn missing_file_is_invalid() {
        let dir = tempdir().unwrap();
        let r = verify_chain(dir.path().join("never.jsonl"), None).unwrap();
        assert!(!r.valid);
        assert!(r.reason.contains("not found"));
    }

    #[test]
    fn modified_detail_breaks_chain() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        // Tamper line 2 (index 1): change detail, leave hash alone.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut record: ChainedRecord = serde_json::from_str(&lines[1]).unwrap();
        record.detail = json!({"n": "TAMPERED"});
        lines[1] = record.to_canonical_json();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let r = verify_chain(&path, None).unwrap();
        assert!(!r.valid);
        assert_eq!(r.first_bad_seq, Some(2));
        assert!(r.reason.contains("hash mismatch"));
    }

    #[test]
    fn sequence_gap_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..3 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<String> = content.lines().map(String::from).collect();
        // Drop the middle line.
        let kept = vec![lines[0].clone(), lines[2].clone()];
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();
        let r = verify_chain(&path, None).unwrap();
        assert!(!r.valid);
        assert!(r.reason.contains("sequence gap") || r.reason.contains("prev_hash mismatch"));
    }

    #[test]
    fn recovers_tail_on_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
            sink.append(entry(json!({"n": 1}))).unwrap();
            sink.append(entry(json!({"n": 2}))).unwrap();
        }
        let sink2 = JsonlHashchainSink::new(&path, 1, None).unwrap();
        assert_eq!(sink2.last_seq(), 2);
        sink2.append(entry(json!({"n": 3}))).unwrap();
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid);
        assert_eq!(r.records_checked, 3);
    }

    #[test]
    fn corrupt_tail_does_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "this is not json\n").unwrap();
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        // Stays at genesis; the corrupt prefix means a later
        // verify_chain would catch the resulting mismatch.
        assert_eq!(sink.last_seq(), 0);
    }

    #[test]
    fn seal_catches_truncation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = b"k".repeat(32);
        let sink = JsonlHashchainSink::new(&path, 1, Some(key.clone())).unwrap();
        for i in 0..5 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        // Truncate to 3 lines: internal chain still valid for those
        // three, but the seal references seq 5.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().take(3).collect();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let r = verify_chain(&path, Some(&key)).unwrap();
        assert!(!r.valid);
        assert_eq!(r.seal_valid, Some(false));
    }

    #[test]
    fn seal_valid_on_intact_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = b"k".repeat(32);
        let sink = JsonlHashchainSink::new(&path, 1, Some(key.clone())).unwrap();
        for i in 0..3 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let r = verify_chain(&path, Some(&key)).unwrap();
        assert!(r.valid);
        assert_eq!(r.seal_valid, Some(true));
    }

    #[test]
    fn seal_tampered_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = b"k".repeat(32);
        let sink = JsonlHashchainSink::new(&path, 1, Some(key.clone())).unwrap();
        sink.append(entry(json!({"n": 1}))).unwrap();
        let seal_path = seal_path_for(&path);
        let mut seal: Value = serde_json::from_str(&std::fs::read_to_string(&seal_path).unwrap()).unwrap();
        seal["tag"] = json!("0".repeat(64));
        std::fs::write(&seal_path, canonical_json(&seal)).unwrap();
        let r = verify_chain(&path, Some(&key)).unwrap();
        assert!(!r.valid);
        assert_eq!(r.seal_valid, Some(false));
    }

    #[test]
    fn iter_records_yields_all_in_order() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..10 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let recs = iter_records(&path).unwrap();
        assert_eq!(recs.len(), 10);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.seq, (i + 1) as u64);
        }
    }

    #[test]
    fn iter_records_skips_corrupt_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        sink.append(entry(json!({"n": 1}))).unwrap();
        // Append a junk line.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"not-json\n").unwrap();
        sink.append(entry(json!({"n": 2}))).unwrap();
        let recs = iter_records(&path).unwrap();
        // Two valid records; the junk line is skipped.
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = json!({"b": 1, "a": 2, "c": 3});
        let s = canonical_json(&v);
        assert_eq!(s, r#"{"a":2,"b":1,"c":3}"#);
    }

    #[test]
    fn canonical_json_handles_nulls_and_strings() {
        let v = json!({"x": null, "y": "hello"});
        assert_eq!(canonical_json(&v), r#"{"x":null,"y":"hello"}"#);
    }

    #[test]
    fn fsync_every_above_one_works() {
        // No assertion on fsync per se; just exercise the batching path.
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 5, None).unwrap();
        for i in 0..12 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid);
        assert_eq!(r.records_checked, 12);
    }

    #[test]
    fn concurrent_writers_keep_chain_intact() {
        use std::sync::Arc;
        use std::thread;
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = Arc::new(JsonlHashchainSink::new(&path, 1, None).unwrap());
        let mut handles = Vec::new();
        for tid in 0..4 {
            let s = Arc::clone(&sink);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    s.append(entry(json!({"thread": tid, "i": i}))).unwrap();
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid);
        assert_eq!(r.records_checked, 200);
    }
}

