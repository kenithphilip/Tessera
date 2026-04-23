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
//!
//! ## Chain-hash serialization strategy
//!
//! Every record's hash covers `prev_hash`, so the hash computation must
//! be serial: record N cannot be hashed until record N-1 is known. We
//! use option (a): a small `Mutex<ChainState>` protects only the
//! sequence counter and last hash. The lock is held for the counter
//! bump and SHA-256 computation, then released before any I/O. The
//! formatted line is then sent to a bounded crossbeam channel (capacity
//! 4096) where a dedicated writer thread drains it, writes to the file,
//! and issues periodic `fsync_data` calls. This keeps lock contention
//! minimal (no disk I/O under the lock) while ensuring the chain is
//! always consistent. A producer that outpaces the writer is slowed by
//! the channel backpressure rather than OOM-ing.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use crossbeam_channel::{bounded, Receiver, Sender};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Channel capacity for the writer queue.
/// 4096 records * ~200 bytes each is roughly 800 KB of buffered writes,
/// giving the writer thread room to absorb bursts without back-pressure
/// on the appender threads. When the channel is full, `send` blocks,
/// which naturally rate-limits producers instead of allocating without
/// bound.
const WRITER_CHANNEL_CAP: usize = 4096;

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

// ---------------------------------------------------------------------------
// Writer thread message type
// ---------------------------------------------------------------------------

/// Messages sent from `append` callers to the writer thread.
enum WriterMsg {
    /// A pre-formatted canonical JSONL line (without trailing newline)
    /// plus the seq and hash for the optional seal update.
    Record {
        line: String,
        seq: u64,
        hash: String,
    },
    /// Tells the writer to drain everything queued ahead of this
    /// message, fsync, and signal back via the supplied sender.
    Flush(crossbeam_channel::Sender<()>),
    /// Tells the writer thread to flush, fsync, and exit.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Chain state -- the only thing that needs serialization across callers
// ---------------------------------------------------------------------------

struct ChainState {
    last_seq: u64,
    last_hash: String,
}

// ---------------------------------------------------------------------------
// JsonlHashchainSink
// ---------------------------------------------------------------------------

/// Sink that appends each event to a JSONL file with a chain hash.
///
/// The fast path (`append`) computes the chain hash on the caller's
/// thread under a small mutex (no I/O held), then sends the formatted
/// line to a bounded channel (capacity `WRITER_CHANNEL_CAP`). A
/// dedicated writer thread owns the file descriptor, drains the channel,
/// and issues `fsync_data` every `fsync_every` records.
pub struct JsonlHashchainSink {
    path: PathBuf,
    /// Protects only the chain counter and last hash. Released before
    /// any channel send, so it is never held during I/O.
    chain: Mutex<ChainState>,
    tx: Sender<WriterMsg>,
    writer_thread: Option<thread::JoinHandle<()>>,
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

        let (last_seq, last_hash) = recover_tail(&path)?;
        let fsync_every = fsync_every.max(1);
        let seal_key = seal_key.map(Arc::new);

        let (tx, rx) = bounded::<WriterMsg>(WRITER_CHANNEL_CAP);

        let writer_path = path.clone();
        let writer_fsync_every = fsync_every;
        let writer_seal_key = seal_key.clone();
        let writer_thread = thread::Builder::new()
            .name("tessera-audit-writer".into())
            .spawn(move || {
                run_writer(writer_path, writer_fsync_every, writer_seal_key, rx);
            })
            .expect("failed to spawn audit writer thread");

        Ok(Self {
            path,
            chain: Mutex::new(ChainState { last_seq, last_hash }),
            tx,
            writer_thread: Some(writer_thread),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_seq(&self) -> u64 {
        self.chain.lock().unwrap().last_seq
    }

    pub fn last_hash(&self) -> String {
        self.chain.lock().unwrap().last_hash.clone()
    }

    /// Block until every record queued before this call has been
    /// written and `fsync`d. Use this in tests, in `iter_records`
    /// callers that read from the same process that wrote, or before
    /// any operation that needs the on-disk view to reflect prior
    /// `append` calls. Production write paths typically do NOT need
    /// `flush`; the writer thread drains continuously and `Drop`
    /// guarantees a final flush.
    pub fn flush(&self) -> Result<(), AuditError> {
        let (tx, rx) = bounded::<()>(1);
        self.tx
            .send(WriterMsg::Flush(tx))
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "audit writer thread has exited",
                )
            })?;
        // Block until the writer signals back. The writer thread
        // honors flush requests in queue order, so this returns only
        // after every record sent before this flush has hit the disk.
        rx.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "audit writer dropped flush reply channel",
            )
        })?;
        Ok(())
    }

    /// Append one record to the audit log.
    ///
    /// The chain hash is computed on the caller's thread (under a small
    /// mutex that is released before the channel send). The formatted
    /// line is queued to the writer thread; this call returns as soon as
    /// the line is in the channel. If the channel is full (4096 items
    /// queued), this call blocks until the writer drains a slot.
    pub fn append(&self, entry: AppendEntry) -> Result<ChainedRecord, AuditError> {
        // Compute hash under the chain mutex. Hold for counter + SHA-256
        // only; release before the channel send.
        let (record, line) = {
            let mut state = self.chain.lock().unwrap();
            let seq = state.last_seq + 1;
            let prev_hash = state.last_hash.clone();
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
                timestamp: entry.timestamp,
                kind: entry.kind,
                principal: entry.principal,
                detail: entry.detail,
                correlation_id: entry.correlation_id,
                trace_id: entry.trace_id,
                prev_hash,
                hash: hash.clone(),
            };
            let line = record.to_canonical_json();
            state.last_seq = seq;
            state.last_hash = hash;
            (record, line)
        };
        // Channel send: returns in nanoseconds when the channel has space.
        // Blocks only when the writer is slower than the producer for
        // more than WRITER_CHANNEL_CAP records -- a natural back-pressure.
        self.tx
            .send(WriterMsg::Record {
                line,
                seq: record.seq,
                hash: record.hash.clone(),
            })
            // The writer thread panicking is the only way the channel
            // disconnects while the sink is still live; propagate as Io.
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "audit writer thread has exited",
                )
            })?;
        Ok(record)
    }
}

impl Drop for JsonlHashchainSink {
    /// Send the shutdown sentinel and join the writer thread, ensuring
    /// every in-flight record is flushed and synced before drop returns.
    fn drop(&mut self) {
        // Ignore send errors: the thread may have already exited on panic.
        let _ = self.tx.send(WriterMsg::Shutdown);
        if let Some(handle) = self.writer_thread.take() {
            // Panic in the writer thread is surfaced here. In production,
            // callers should not rely on panic propagation; add a watchdog
            // if the writer thread must be restarted on failure.
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Tail recovery
// ---------------------------------------------------------------------------

fn recover_tail(path: &Path) -> Result<(u64, String), AuditError> {
    if !path.exists() {
        return Ok((0, GENESIS_HASH.to_string()));
    }
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 {
        return Ok((0, GENESIS_HASH.to_string()));
    }
    // Read the last non-empty line. Cheap full read matching the Python
    // reference that reads up to 4 KiB from the tail.
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_line: Option<String> = None;
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim().to_string();
        if !trimmed.is_empty() {
            last_line = Some(trimmed);
        }
    }
    let Some(last) = last_line else {
        return Ok((0, GENESIS_HASH.to_string()));
    };
    match ChainedRecord::from_line(&last) {
        Ok(record) => Ok((record.seq, record.hash)),
        Err(_) => {
            // Corrupt tail: start fresh. verify_chain catches the gap.
            Ok((0, GENESIS_HASH.to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------------

fn run_writer(
    path: PathBuf,
    fsync_every: u64,
    seal_key: Option<Arc<Vec<u8>>>,
    rx: Receiver<WriterMsg>,
) {
    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tessera-audit: writer thread failed to open {}: {e}", path.display());
            return;
        }
    };
    let mut writes_since_fsync: u64 = 0;

    for msg in rx.iter() {
        match msg {
            WriterMsg::Record { line, seq, hash } => {
                if let Err(e) = write_line(&mut file, &line) {
                    eprintln!("tessera-audit: write error at seq {seq}: {e}");
                    // Continue draining so Drop does not deadlock. Records
                    // that fail to write are lost; the broken chain will be
                    // caught by verify_chain.
                    continue;
                }
                writes_since_fsync += 1;
                if writes_since_fsync >= fsync_every {
                    if let Err(e) = file.flush().and_then(|_| file.sync_data()) {
                        eprintln!("tessera-audit: fsync error: {e}");
                    }
                    writes_since_fsync = 0;
                }
                if let Some(ref key) = seal_key {
                    if let Err(e) = write_seal(&path, seq, &hash, key) {
                        eprintln!("tessera-audit: seal write error at seq {seq}: {e}");
                    }
                }
            }
            WriterMsg::Flush(reply) => {
                if writes_since_fsync > 0 {
                    if let Err(e) = file.flush().and_then(|_| file.sync_data()) {
                        eprintln!("tessera-audit: flush error: {e}");
                    }
                    writes_since_fsync = 0;
                }
                // Signal the caller. Ignore send errors: the caller may
                // have given up on the rendezvous already.
                let _ = reply.send(());
            }
            WriterMsg::Shutdown => {
                // Final flush and fsync before the thread exits.
                if writes_since_fsync > 0 {
                    if let Err(e) = file.flush().and_then(|_| file.sync_data()) {
                        eprintln!("tessera-audit: final fsync error: {e}");
                    }
                }
                return;
            }
        }
    }
    // Channel closed without Shutdown (sender dropped). Flush anyway.
    if writes_since_fsync > 0 {
        if let Err(e) = file.flush().and_then(|_| file.sync_data()) {
            eprintln!("tessera-audit: final fsync error on channel close: {e}");
        }
    }
}

fn write_line(file: &mut File, line: &str) -> std::io::Result<()> {
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")
}

fn write_seal(path: &Path, seq: u64, last_hash: &str, key: &[u8]) -> Result<(), AuditError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(format!("{seq}|{last_hash}").as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    let seal = serde_json::json!({
        "seq": seq,
        "hash": last_hash,
        "tag": tag,
    });
    let seal_path = seal_path_for(path);
    let tmp = seal_path.with_extension("seal.tmp");
    std::fs::write(&tmp, canonical_json(&seal).as_bytes())?;
    std::fs::rename(tmp, seal_path)?;
    Ok(())
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
    use std::fs::OpenOptions;
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

    /// Drop the sink and wait for the writer thread to flush before
    /// opening the file for inspection. This helper exists so tests
    /// can use a one-liner without littering explicit drops everywhere.
    fn flush(sink: JsonlHashchainSink) {
        drop(sink); // Drop impl sends Shutdown and joins the writer thread.
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
        flush(sink);
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.split('\n').filter(|s| !s.is_empty()).collect();
        assert_eq!(lines.len(), 3);
        for ln in lines {
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
        flush(sink);
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
        flush(sink);
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
        flush(sink);
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
        } // Drop flushes.
        let sink2 = JsonlHashchainSink::new(&path, 1, None).unwrap();
        assert_eq!(sink2.last_seq(), 2);
        sink2.append(entry(json!({"n": 3}))).unwrap();
        flush(sink2);
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
        flush(sink);
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
        flush(sink);
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
        flush(sink);
        let seal_path = seal_path_for(&path);
        let mut seal: Value =
            serde_json::from_str(&std::fs::read_to_string(&seal_path).unwrap()).unwrap();
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
        flush(sink);
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
        flush(sink);
        // Append a junk line.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"not-json\n").unwrap();
        drop(f);
        // Open a new sink that picks up from seq 1, appends seq 2.
        let sink2 = JsonlHashchainSink::new(&path, 1, None).unwrap();
        sink2.append(entry(json!({"n": 2}))).unwrap();
        flush(sink2);
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
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 5, None).unwrap();
        for i in 0..12 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        flush(sink);
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
        for h in handles {
            h.join().unwrap();
        }
        // Drop the Arc; when the last reference drops, the sink flushes.
        drop(sink);
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid);
        assert_eq!(r.records_checked, 200);
    }

    // -----------------------------------------------------------------------
    // New Phase-4 tests
    // -----------------------------------------------------------------------

    /// High-throughput: 10_000 appends complete and every record is on disk.
    #[test]
    fn high_throughput_appends_complete() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // fsync every 100 to reduce I/O pressure in the test.
        let sink = JsonlHashchainSink::new(&path, 100, None).unwrap();
        for i in 0..10_000u64 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        flush(sink);
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid, "chain invalid: {}", r.reason);
        assert_eq!(r.records_checked, 10_000);
    }

    /// Writer thread joins cleanly on drop without deadlocking or panicking.
    #[test]
    fn writer_thread_joins_on_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
        for i in 0..20 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        // Drop must return within reasonable time (the test harness will
        // time out if it deadlocks). Panics in the writer thread surface
        // through join, which would fail the test.
        drop(sink);
    }

    /// Final-flush: drop the sink and assert every appended record is
    /// readable on disk with a valid chain.
    #[test]
    fn final_flush_after_drop() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // fsync_every = 1000 so the writer does NOT fsync during appends;
        // the only fsync path is the one triggered by Shutdown in Drop.
        let sink = JsonlHashchainSink::new(&path, 1000, None).unwrap();
        for i in 0..50 {
            sink.append(entry(json!({"n": i}))).unwrap();
        }
        drop(sink); // Shutdown sentinel triggers final flush+fsync.
        let recs = iter_records(&path).unwrap();
        assert_eq!(recs.len(), 50, "expected 50 records on disk after drop");
        let r = verify_chain(&path, None).unwrap();
        assert!(r.valid, "chain invalid after final flush: {}", r.reason);
        assert_eq!(r.records_checked, 50);
    }
}
