//! Cross-implementation interop test for canary tokens.
//!
//! Canary tokens are random hex strings, not cryptographically bound
//! payloads, so "interop" here means format compatibility: a Python
//! token detected by `tessera.scanners.canary.CanaryGuard.check`
//! must also be detected by the Rust `CanaryGuard.check`, and vice
//! versa. The wire format is `[CANARY:<hex>]` for prompt canaries
//! and `[ref:<hex>]` for segment canaries; both sides must agree.

use std::process::Command;

use tessera_scanners::canary::{CanaryGuard, SegmentCanaryTracker};

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.scanners.canary"])
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
fn rust_token_detected_by_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let guard = CanaryGuard::default();
    let (_protected, token) = guard.inject("system prompt body");
    let leaked = format!("Sure, here it is: {token}.");

    let script = format!(
        r#"
from tessera.scanners.canary import CanaryGuard
guard = CanaryGuard()
ok = guard.check({leaked:?}, {token:?})
print('detected:', ok)
assert ok, 'Python failed to detect Rust-injected canary'
"#,
        leaked = leaked,
        token = token
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python check failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn python_token_detected_by_rust() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let script = r#"
from tessera.scanners.canary import CanaryGuard
guard = CanaryGuard()
prompt, token = guard.inject('the system prompt')
print(token)
"#;
    let out = run_python(script);
    assert!(out.status.success(), "python invocation failed");
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(token.len(), 16, "Python default token is 8 bytes = 16 hex chars");

    let guard = CanaryGuard::default();
    let leaked = format!("response with leaked token: {token}");
    assert!(guard.check(&leaked, &token), "Rust failed to detect Python-injected canary");
}

#[test]
fn rust_segment_ref_detected_by_python_segment_check() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let mut tracker = SegmentCanaryTracker::with_default_size();
    let (_w, token) = tracker.inject_segment("seg-1", "hotel xyz");
    let response = format!("the model echoed [ref:{token}]");

    let script = format!(
        r#"
from tessera.scanners.canary import SegmentCanaryTracker
t = SegmentCanaryTracker()
# Python expects to know the token to check; we register it manually
# here because tracker state is per-process.
t._segments['seg-1'] = {token:?}
infls = t.check_response({response:?})
assert len(infls) == 1, f'expected 1 influence, got {{len(infls)}}'
assert infls[0].canary_token == {token:?}
print('ok')
"#,
        token = token,
        response = response
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python check failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn token_format_lengths_match_python_defaults() {
    // No Python required: just locks in the format constants so a
    // future change to either side has to update both.
    let guard = CanaryGuard::default();
    let (_p, token) = guard.inject("x");
    assert_eq!(token.len(), 16, "default prompt token = 8 bytes hex = 16 chars (matches Python)");

    let mut tracker = SegmentCanaryTracker::with_default_size();
    let (_w, seg_token) = tracker.inject_segment("s", "x");
    assert_eq!(seg_token.len(), 12, "default segment token = 6 bytes hex = 12 chars (matches Python)");
}
