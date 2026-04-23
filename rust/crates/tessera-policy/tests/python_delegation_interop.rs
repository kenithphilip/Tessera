//! Cross-implementation interop test for delegation tokens.
//!
//! Builds a token in Rust, asks Python's
//! `tessera.delegation.verify_delegation` to verify it, and vice
//! versa. The wire format (canonical JSON + hex HMAC) is the public
//! contract; this test fails loudly if either side drifts.

use std::process::Command;

use chrono::TimeZone;
use chrono::Utc;
use serde_json::json;
use tessera_policy::delegation::{
    sign_delegation, verify_delegation, DelegationToken,
};

const KEY: &[u8] = b"interop-deleg-key-32bytes!!!!!!!";

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.delegation"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

fn fixed_token() -> DelegationToken {
    DelegationToken::new(
        "alice",
        "agent-A",
        "tessera-proxy",
        vec!["send_email".to_string(), "list_files".to_string()],
        json!({"max_cost_usd": 10.0}),
        "sess-fixed",
        Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
    )
}

#[test]
fn rust_token_verifies_in_python() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let token = sign_delegation(fixed_token(), KEY);
    let token_json = serde_json::to_string(&token).unwrap();
    let key_lit = format!("{:?}", KEY);

    let script = format!(
        r#"
import json
from datetime import datetime
from tessera.delegation import DelegationToken, verify_delegation

raw = json.loads({token_json:?})
expires_at = datetime.fromisoformat(raw['expires_at'])
token = DelegationToken(
    subject=raw['subject'],
    delegate=raw['delegate'],
    audience=raw['audience'],
    authorized_actions=tuple(raw['authorized_actions']),
    constraints=raw['constraints'],
    session_id=raw['session_id'],
    expires_at=expires_at,
    signature=raw['signature'],
)
ok = verify_delegation(token, {key_lit}, audience='tessera-proxy', now=datetime.fromisoformat('2026-04-23T00:00:00+00:00'))
assert ok, 'Python rejected Rust-signed delegation token'
print('verified:', ok)
"#,
        token_json = token_json,
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
fn python_token_verifies_in_rust() {
    if !python_with_tessera_available() {
        eprintln!("skipping: python3 + tessera package not available");
        return;
    }
    let key_lit = format!("{:?}", KEY);
    let script = format!(
        r#"
import json
from datetime import datetime
from tessera.delegation import DelegationToken, sign_delegation

token = DelegationToken(
    subject='alice',
    delegate='agent-A',
    audience='tessera-proxy',
    authorized_actions=('send_email', 'list_files'),
    constraints={{'max_cost_usd': 10.0}},
    session_id='sess-fixed',
    expires_at=datetime.fromisoformat('2030-01-01T00:00:00+00:00'),
)
signed = sign_delegation(token, {key_lit})
out = {{
    'subject': signed.subject,
    'delegate': signed.delegate,
    'audience': signed.audience,
    'authorized_actions': list(signed.authorized_actions),
    'constraints': signed.constraints,
    'session_id': signed.session_id,
    'expires_at': signed.expires_at.isoformat(),
    'signature': signed.signature,
}}
print(json.dumps(out))
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
    let token: DelegationToken =
        serde_json::from_str(stdout.trim()).expect("Python output is valid JSON");
    assert!(
        verify_delegation(
            &token,
            KEY,
            Some("tessera-proxy"),
            Utc.with_ymd_and_hms(2026, 4, 23, 0, 0, 0).unwrap()
        ),
        "Rust rejected Python-signed delegation token"
    );
}
