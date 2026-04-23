//! Cross-implementation interop test for signed evidence bundles.
//!
//! Builds a bundle in Rust, signs it with HMAC-SHA256, asks Python's
//! `tessera.evidence.HMACEvidenceVerifier` to verify it, and vice
//! versa. The wire format (canonical JSON + hex HMAC) is the public
//! contract; this test fails loudly if either side drifts.
//!
//! Skipped automatically when `python3` or the `tessera` package is
//! not on the PATH so the test suite stays green in environments
//! without the Python toolchain.

use std::collections::BTreeMap;
use std::process::Command;

use serde_json::json;
use tessera_policy::evidence::{
    EvidenceBundle, HmacEvidenceSigner, HmacEvidenceVerifier, SignedEvidenceBundle,
    EVIDENCE_SCHEMA_VERSION,
};

const KEY: &[u8] = b"interop-key-32bytes!!!!!!!!!!!!!";

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.evidence"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

fn sample_bundle() -> EvidenceBundle {
    let mut counts = BTreeMap::new();
    counts.insert("policy_deny".to_string(), 2);
    counts.insert("label_verify_failure".to_string(), 1);
    EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        generated_at: "2026-04-23T00:00:00+00:00".to_string(),
        event_count: 3,
        dropped_events: 0,
        counts_by_kind: counts,
        events: vec![
            json!({"kind": "policy_deny", "principal": "alice", "detail": {"tool": "send_email"}, "timestamp": "2026-04-23T00:00:00+00:00"}),
            json!({"kind": "policy_deny", "principal": "alice", "detail": {"tool": "delete_file"}, "timestamp": "2026-04-23T00:00:01+00:00"}),
            json!({"kind": "label_verify_failure", "principal": "unknown", "detail": {}, "timestamp": "2026-04-23T00:00:02+00:00"}),
        ],
    }
}

#[test]
fn rust_signed_bundle_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let signer = HmacEvidenceSigner::new(KEY.to_vec());
    let signed = signer.sign(sample_bundle());
    let signed_json = serde_json::to_string(&signed).unwrap();
    let key_b64 = format!("{:?}", KEY); // bytes literal Python understands

    let script = format!(
        r#"
import json
from tessera.evidence import EvidenceBundle, SignedEvidenceBundle, HMACEvidenceVerifier

raw = json.loads({signed_json:?})
signed = SignedEvidenceBundle.from_dict(raw)
verifier = HMACEvidenceVerifier(key={key_b64})
ok = verifier.verify(signed)
print('verified:', ok)
assert ok, 'Python rejected Rust-signed bundle'
print('python-side digest:', signed.bundle.digest)
"#,
        signed_json = signed_json,
        key_b64 = key_b64,
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
fn python_signed_bundle_verifies_in_rust() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let key_b64 = format!("{:?}", KEY);

    let script = format!(
        r#"
import json
from tessera.evidence import EvidenceBundle, HMACEvidenceSigner

bundle = EvidenceBundle.from_dict({{
    "schema_version": "tessera.evidence.v1",
    "generated_at": "2026-04-23T00:00:00+00:00",
    "event_count": 3,
    "dropped_events": 0,
    "counts_by_kind": {{"label_verify_failure": 1, "policy_deny": 2}},
    "events": [
        {{"kind": "policy_deny", "principal": "alice", "detail": {{"tool": "send_email"}}, "timestamp": "2026-04-23T00:00:00+00:00"}},
        {{"kind": "policy_deny", "principal": "alice", "detail": {{"tool": "delete_file"}}, "timestamp": "2026-04-23T00:00:01+00:00"}},
        {{"kind": "label_verify_failure", "principal": "unknown", "detail": {{}}, "timestamp": "2026-04-23T00:00:02+00:00"}},
    ],
}})
signer = HMACEvidenceSigner(key={key_b64})
signed = signer.sign(bundle)
print(json.dumps(signed.to_dict()))
"#,
        key_b64 = key_b64,
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python signing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json_line = stdout.trim();
    let signed: SignedEvidenceBundle =
        serde_json::from_str(json_line).expect("Python output is valid JSON");

    let verifier = HmacEvidenceVerifier::new(KEY.to_vec());
    assert!(
        verifier.verify(&signed),
        "Rust rejected Python-signed bundle (digest match required)"
    );
}

#[test]
fn rust_and_python_produce_identical_digest() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let bundle = sample_bundle();
    let rust_digest = bundle.digest();

    let script = r#"
from tessera.evidence import EvidenceBundle
b = EvidenceBundle.from_dict({
    "schema_version": "tessera.evidence.v1",
    "generated_at": "2026-04-23T00:00:00+00:00",
    "event_count": 3,
    "dropped_events": 0,
    "counts_by_kind": {"label_verify_failure": 1, "policy_deny": 2},
    "events": [
        {"kind": "policy_deny", "principal": "alice", "detail": {"tool": "send_email"}, "timestamp": "2026-04-23T00:00:00+00:00"},
        {"kind": "policy_deny", "principal": "alice", "detail": {"tool": "delete_file"}, "timestamp": "2026-04-23T00:00:01+00:00"},
        {"kind": "label_verify_failure", "principal": "unknown", "detail": {}, "timestamp": "2026-04-23T00:00:02+00:00"},
    ],
})
print(b.digest)
"#;
    let out = run_python(script);
    assert!(out.status.success(), "python digest call failed");
    let py_digest = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        rust_digest, py_digest,
        "Rust and Python produced different bundle digests; canonical JSON must match byte-for-byte"
    );
}
