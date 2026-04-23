//! Cross-implementation interop test for prompt provenance.
//!
//! Builds an envelope and a manifest in Rust, asks Python's
//! `tessera.provenance.ContextSegmentEnvelope.verify` and
//! `PromptProvenanceManifest.verify` to verify, and vice versa. The
//! wire format (canonical JSON + hex HMAC) is the public contract;
//! this test fails loudly if either side drifts.

use std::process::Command;

use tessera_core::labels::{Origin, TrustLevel};
use tessera_policy::provenance::{ContextSegmentEnvelope, PromptProvenanceManifest};

const KEY: &[u8] = b"interop-prov-key-32bytes!!!!!!!";

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.provenance"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

fn build_envelope(content: &str) -> ContextSegmentEnvelope {
    ContextSegmentEnvelope::create(
        content,
        Origin::User,
        "interop-issuer",
        "alice",
        TrustLevel::User,
        KEY,
        Some("seg-fixed-1".to_string()),
        Vec::new(),
        None,
        Vec::new(),
        "2026-04-23T00:00:00+00:00".to_string(),
    )
}

#[test]
fn rust_envelope_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let env = build_envelope("hello world");
    let env_json = serde_json::to_string(&env).unwrap();
    let key_lit = format!("{:?}", KEY);

    let script = format!(
        r#"
import json
from tessera.provenance import ContextSegmentEnvelope
from tessera.labels import Origin, TrustLevel

raw = json.loads({env_json:?})
env = ContextSegmentEnvelope(
    segment_id=raw['segment_id'],
    origin=Origin(raw['origin']),
    issuer=raw['issuer'],
    principal=raw['principal'],
    trust_level=TrustLevel(raw['trust_level']),
    content_sha256=raw['content_sha256'],
    parent_ids=tuple(raw['parent_ids']),
    delegating_user=raw['delegating_user'],
    sensitivity=tuple(raw['sensitivity']),
    created_at=raw['created_at'],
    schema_version=raw['schema_version'],
    signature=raw['signature'],
)
ok = env.verify('hello world', {key_lit})
print('verified:', ok)
assert ok, 'Python rejected Rust-signed envelope'
"#,
        env_json = env_json,
        key_lit = key_lit,
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
fn python_envelope_verifies_in_rust() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let key_lit = format!("{:?}", KEY);
    let script = format!(
        r#"
import json
from tessera.provenance import ContextSegmentEnvelope
from tessera.labels import Origin, TrustLevel

env = ContextSegmentEnvelope.create(
    content='hello world',
    origin=Origin.USER,
    issuer='interop-issuer',
    principal='alice',
    trust_level=TrustLevel.USER,
    key={key_lit},
    segment_id='seg-fixed-1',
    parent_ids=(),
    delegating_user=None,
    sensitivity=(),
    created_at='2026-04-23T00:00:00+00:00',
)
print(json.dumps(env.to_dict()))
"#,
        key_lit = key_lit,
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python signing failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env: ContextSegmentEnvelope =
        serde_json::from_str(stdout.trim()).expect("Python output is valid JSON");

    assert!(
        env.verify("hello world", KEY),
        "Rust rejected Python-signed envelope (canonical JSON must match byte-for-byte)"
    );
}

#[test]
fn rust_manifest_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let env_a = build_envelope("first");
    let env_b = ContextSegmentEnvelope::create(
        "second",
        Origin::User,
        "interop-issuer",
        "alice",
        TrustLevel::User,
        KEY,
        Some("seg-fixed-2".to_string()),
        Vec::new(),
        None,
        Vec::new(),
        "2026-04-23T00:00:00+00:00".to_string(),
    );
    let manifest = PromptProvenanceManifest::assemble(
        &[env_a.clone(), env_b.clone()],
        "interop-proxy",
        KEY,
        Some("session-fixed".to_string()),
        Some("manifest-fixed".to_string()),
        None,
        "2026-04-23T00:00:00+00:00".to_string(),
    );
    let manifest_json = serde_json::to_string(&manifest).unwrap();
    let env_a_json = serde_json::to_string(&env_a).unwrap();
    let env_b_json = serde_json::to_string(&env_b).unwrap();
    let key_lit = format!("{:?}", KEY);

    let script = format!(
        r#"
import json
from tessera.provenance import (
    ContextSegmentEnvelope,
    ManifestSegmentRef,
    PromptProvenanceManifest,
)
from tessera.labels import Origin, TrustLevel

def to_env(raw):
    return ContextSegmentEnvelope(
        segment_id=raw['segment_id'],
        origin=Origin(raw['origin']),
        issuer=raw['issuer'],
        principal=raw['principal'],
        trust_level=TrustLevel(raw['trust_level']),
        content_sha256=raw['content_sha256'],
        parent_ids=tuple(raw['parent_ids']),
        delegating_user=raw['delegating_user'],
        sensitivity=tuple(raw['sensitivity']),
        created_at=raw['created_at'],
        schema_version=raw['schema_version'],
        signature=raw['signature'],
    )

env_a = to_env(json.loads({env_a_json:?}))
env_b = to_env(json.loads({env_b_json:?}))
mraw = json.loads({manifest_json:?})
manifest = PromptProvenanceManifest(
    manifest_id=mraw['manifest_id'],
    session_id=mraw['session_id'],
    principal_set=tuple(mraw['principal_set']),
    segments=tuple(
        ManifestSegmentRef(
            segment_id=s['segment_id'],
            position=s['position'],
            content_sha256=s['content_sha256'],
        )
        for s in mraw['segments']
    ),
    assembled_by=mraw['assembled_by'],
    assembled_at=mraw['assembled_at'],
    schema_version=mraw['schema_version'],
    signature=mraw['signature'],
)
ok = manifest.verify([env_a, env_b], {key_lit})
print('verified:', ok)
assert ok, 'Python rejected Rust-signed manifest'
"#,
        env_a_json = env_a_json,
        env_b_json = env_b_json,
        manifest_json = manifest_json,
        key_lit = key_lit,
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python verification failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
