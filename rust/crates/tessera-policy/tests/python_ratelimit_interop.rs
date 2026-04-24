//! Cross-implementation interop test for ToolCallRateLimit.
//!
//! Tessera ports the rate limiter to both Python (`tessera.ratelimit`)
//! and Rust (`tessera_policy::ratelimit`). The two implementations
//! must agree on (a) when calls are allowed, (b) when window/burst/
//! lifetime limits trip, and (c) the deny-reason text format
//! consumed by SIEM rules.
//!
//! Skipped automatically when `python3` or the `tessera` package is
//! not on the PATH so the test suite stays green in environments
//! without the Python toolchain.

use std::process::Command;

use chrono::{Duration, TimeZone, Utc};
use tessera_policy::ratelimit::ToolCallRateLimit;

fn python_with_tessera_available() -> bool {
    let probe = Command::new("python3")
        .args(["-c", "import tessera.ratelimit"])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

const PY_HELPER: &str = r#"
from datetime import datetime, timedelta, timezone
from tessera.ratelimit import ToolCallRateLimit

def check_n(limiter, session_id, n, start_iso):
    base = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
    out = []
    for i in range(n):
        allowed, reason = limiter.check(session_id, "tool", at=base + timedelta(milliseconds=i * 10))
        out.append((allowed, reason))
    return out
"#;

#[test]
fn window_limit_trips_on_same_request_count() {
    if !python_with_tessera_available() {
        return;
    }
    let limiter = ToolCallRateLimit::new(
        3,
        Duration::seconds(60),
        99,                           // burst threshold high enough not to trip
        Duration::seconds(5),
        Duration::seconds(30),
        Some(1000),
    );
    let base = Utc.with_ymd_and_hms(2026, 4, 24, 12, 0, 0).unwrap();
    let mut rust_results = Vec::new();
    for i in 0..5 {
        let at = base + Duration::milliseconds(i * 10);
        let (allowed, reason) = limiter.check_at("session-A", "tool", at);
        rust_results.push((allowed, reason));
    }
    // Rust: 3 allowed, 2 denied with "rate limit: ..." reason.
    assert_eq!(rust_results.iter().filter(|(a, _)| *a).count(), 3);
    let denied_reason = rust_results[3].1.as_deref().unwrap();
    assert!(
        denied_reason.starts_with("rate limit: 3/3 per 60s"),
        "rust reason was {denied_reason:?}"
    );

    let script = format!(
        r#"
{PY_HELPER}
limiter = ToolCallRateLimit(max_calls=3, window=timedelta(seconds=60), burst_threshold=99, burst_window=timedelta(seconds=5), cooldown=timedelta(seconds=30), session_lifetime_max=1000)
results = check_n(limiter, "session-A", 5, "2026-04-24T12:00:00Z")
for r in results: print(r)
"#,
    );
    let out = run_python(&script);
    assert!(out.status.success(), "python failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);

    let allowed_lines = stdout
        .lines()
        .filter(|l| l.starts_with("(True"))
        .count();
    let denied_lines = stdout
        .lines()
        .filter(|l| l.starts_with("(False"))
        .count();
    assert_eq!(allowed_lines, 3, "python allowed count diverged: {stdout}");
    assert_eq!(denied_lines, 2, "python denied count diverged: {stdout}");
    assert!(
        stdout.contains("rate limit: 3/3 per 60s"),
        "python reason text diverged: {stdout}"
    );
}

#[test]
fn burst_limit_trips_within_burst_window() {
    if !python_with_tessera_available() {
        return;
    }
    // burst_threshold = 5 means the 5th call within burst_window
    // trips; configure max_calls high enough that the window cap
    // does not interfere.
    let limiter = ToolCallRateLimit::new(
        100,
        Duration::seconds(60),
        5,
        Duration::seconds(5),
        Duration::seconds(30),
        Some(1000),
    );
    let base = Utc.with_ymd_and_hms(2026, 4, 24, 12, 0, 0).unwrap();
    let mut rust_results = Vec::new();
    for i in 0..6 {
        let at = base + Duration::milliseconds(i * 10);
        let (allowed, reason) = limiter.check_at("session-B", "tool", at);
        rust_results.push((allowed, reason));
    }
    // Rust: 4 allowed, 5th and 6th denied (burst at the 5th call,
    // cooldown blocks the 6th).
    assert!(rust_results[3].0, "4th call should be allowed");
    assert!(!rust_results[4].0, "5th call should trip burst");
    let burst_reason = rust_results[4].1.as_deref().unwrap();
    assert!(
        burst_reason.starts_with("burst detected: 5 calls in 5s"),
        "rust burst reason was {burst_reason:?}"
    );

    let script = format!(
        r#"
{PY_HELPER}
limiter = ToolCallRateLimit(max_calls=100, window=timedelta(seconds=60), burst_threshold=5, burst_window=timedelta(seconds=5), cooldown=timedelta(seconds=30), session_lifetime_max=1000)
results = check_n(limiter, "session-B", 6, "2026-04-24T12:00:00Z")
for r in results: print(r)
"#,
    );
    let out = run_python(&script);
    assert!(out.status.success(), "python failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("burst detected: 5 calls in 5s"),
        "python burst reason diverged: {stdout}"
    );
}

#[test]
fn lifetime_cap_trips_at_configured_total() {
    if !python_with_tessera_available() {
        return;
    }
    let limiter = ToolCallRateLimit::new(
        100,
        Duration::seconds(60),
        99,
        Duration::seconds(5),
        Duration::seconds(30),
        Some(2),
    );
    let base = Utc.with_ymd_and_hms(2026, 4, 24, 12, 0, 0).unwrap();
    for i in 0..2 {
        let at = base + Duration::milliseconds(i * 10);
        assert!(limiter.check_at("session-C", "tool", at).0);
    }
    let (allowed, reason) = limiter.check_at(
        "session-C",
        "tool",
        base + Duration::milliseconds(20),
    );
    assert!(!allowed);
    let r = reason.unwrap();
    assert_eq!(r, "session lifetime limit: 2/2");

    let script = format!(
        r#"
{PY_HELPER}
limiter = ToolCallRateLimit(max_calls=100, window=timedelta(seconds=60), burst_threshold=99, burst_window=timedelta(seconds=5), cooldown=timedelta(seconds=30), session_lifetime_max=2)
results = check_n(limiter, "session-C", 3, "2026-04-24T12:00:00Z")
for r in results: print(r)
"#,
    );
    let out = run_python(&script);
    assert!(out.status.success(), "python failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("session lifetime limit: 2/2"),
        "python lifetime reason diverged: {stdout}"
    );
}
