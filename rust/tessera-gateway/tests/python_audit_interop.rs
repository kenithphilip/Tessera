//! Cross-implementation interop test for the hash-chained audit log.
//!
//! Writes a chain in Rust, asks the Python `tessera.audit_log.verify_chain`
//! to verify it, and vice versa. The on-disk format is the public
//! contract; this test fails loudly if either side drifts.
//!
//! Skipped automatically when `python3` or the `tessera` package is
//! not on the PATH so the test suite stays green in environments
//! without the Python toolchain.

use std::process::Command;

use serde_json::json;
use tempfile::tempdir;
use tessera_gateway::audit_log::{verify_chain, AppendEntry, JsonlHashchainSink};

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.audit_log"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

#[test]
fn rust_chain_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let sink = JsonlHashchainSink::new(&path, 1, None).unwrap();
    for i in 0..5 {
        sink.append(AppendEntry {
            timestamp: format!("2026-04-23T00:00:0{i}+00:00"),
            kind: "policy_deny".into(),
            principal: "rust-test".into(),
            detail: json!({"n": i}),
            correlation_id: None,
            trace_id: None,
        })
        .unwrap();
    }

    let script = format!(
        r#"
from tessera.audit_log import verify_chain
result = verify_chain({path:?})
print('valid:', result.valid)
print('records:', result.records_checked)
print('reason:', result.reason)
assert result.valid, f'Python rejected Rust chain: {{result.reason}}'
assert result.records_checked == 5
"#,
        path = path.to_string_lossy().to_string()
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python verification failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn python_chain_verifies_in_rust() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let path_str = path.to_string_lossy().to_string();

    let script = format!(
        r#"
from datetime import datetime, timezone
from tessera.audit_log import JSONLHashchainSink
from tessera.events import EventKind, SecurityEvent

sink = JSONLHashchainSink({path:?})
for i in range(5):
    sink(SecurityEvent(
        kind=EventKind.POLICY_DENY,
        principal="python-test",
        detail={{"n": i}},
        timestamp=f"2026-04-23T00:00:0{{i}}+00:00",
        correlation_id=None,
        trace_id=None,
    ))
"#,
        path = path_str
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python writer failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let result = verify_chain(&path, None).expect("verify");
    assert!(
        result.valid,
        "Rust rejected Python chain: {}",
        result.reason
    );
    assert_eq!(result.records_checked, 5);
}

#[test]
fn rust_seal_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let key = b"k".repeat(32);
    let sink = JsonlHashchainSink::new(&path, 1, Some(key.clone())).unwrap();
    for i in 0..3 {
        sink.append(AppendEntry {
            timestamp: format!("2026-04-23T00:00:0{i}+00:00"),
            kind: "policy_deny".into(),
            principal: "rust-seal-test".into(),
            detail: json!({"n": i}),
            correlation_id: None,
            trace_id: None,
        })
        .unwrap();
    }

    let key_repr = format!("b{:?}", "k".repeat(32));
    let script = format!(
        r#"
from tessera.audit_log import verify_chain
result = verify_chain({path:?}, seal_key={key})
assert result.valid, f'Python rejected Rust sealed chain: {{result.reason}}'
assert result.seal_valid is True
"#,
        path = path.to_string_lossy().to_string(),
        key = key_repr,
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python seal verification failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
