//! Microbenchmarks for the load-bearing primitives.
//!
//! Run with:
//!     cargo bench --bench policy_eval
//!
//! Times reported are per-operation in nanoseconds. Compare against
//! the Python numbers in `benchmarks/microbenchmarks.md` (Python
//! reference): Tessera Python policy evaluation is ~50 us per call
//! including HMAC overhead. Rust should be roughly an order of
//! magnitude faster for the same workload because there is no GIL,
//! no PyObject allocation, and `min_trust` is a simple linear scan
//! over a `Vec<LabeledSegment>`.
//!
//! This is a no-dependency bench (`#[bench]` would require
//! `cargo bench` on nightly); instead we expose `main` as a
//! self-timed harness that runs in stable Rust under `cargo run
//! --release --bin policy_eval_bench` if you wire up a `[[bin]]`,
//! or under `cargo bench` once you add `criterion`. We default to
//! the standalone binary path because it lets operators reproduce
//! numbers without adding `criterion` to the gateway's dep tree.

use std::time::Instant;

use tessera_gateway::context::{make_segment, Context};
use tessera_gateway::labels::{HmacSigner, HmacVerifier, Origin, TrustLabel, TrustLevel};
use tessera_gateway::policy::{Policy, ResourceRequirement};

const ITERATIONS: u32 = 100_000;
const KEY: &[u8] = b"bench-key-32bytes!!!!!!!!!!!!!!!";

fn bench<F: FnMut()>(name: &str, mut f: F) {
    // Warm-up
    for _ in 0..1000 {
        f();
    }
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f();
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    let ops_per_sec = 1_000_000_000.0 / per_op_ns;
    println!(
        "{name:40} {per_op_ns:>8.1} ns/op   {ops_per_sec:>10.0} ops/sec",
    );
}

fn build_user_context(signer: &HmacSigner) -> Context {
    let mut ctx = Context::new();
    ctx.add(make_segment("user prompt", Origin::User, "alice", signer, None));
    ctx
}

fn build_tainted_context(signer: &HmacSigner) -> Context {
    let mut ctx = Context::new();
    ctx.add(make_segment("user prompt", Origin::User, "alice", signer, None));
    ctx.add(make_segment(
        "<html>scraped content</html>",
        Origin::Web,
        "alice",
        signer,
        None,
    ));
    ctx
}

fn main() {
    let signer = HmacSigner::new(KEY);
    let verifier = HmacVerifier::new(KEY);
    let mut policy = Policy::new();
    policy.require(ResourceRequirement::new_tool("send_email", TrustLevel::User));

    println!("# tessera-gateway microbenchmarks (Rust)");
    println!("# {ITERATIONS} iterations per benchmark, 1000-op warm-up");
    println!();

    bench("label_sign (HMAC over 32 bytes)", || {
        let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
        let _ = signer.sign(label, "hello world");
    });

    let segment = make_segment("hello world", Origin::User, "alice", &signer, None);
    bench("label_verify (HMAC over 32 bytes)", || {
        verifier.verify(&segment.label, "hello world").unwrap();
    });

    bench("make_segment (sign + wrap)", || {
        let _ = make_segment("hello world", Origin::User, "alice", &signer, None);
    });

    let user_ctx = build_user_context(&signer);
    bench("policy.evaluate clean (allow path)", || {
        let _ = policy.evaluate(&user_ctx, "send_email");
    });

    let tainted = build_tainted_context(&signer);
    bench("policy.evaluate tainted (deny path)", || {
        let _ = policy.evaluate(&tainted, "send_email");
    });

    // 10-segment context: closer to a real session that's been alive
    // for several tool calls.
    let mut ten_seg = Context::new();
    for i in 0..10 {
        let origin = if i == 7 { Origin::Web } else { Origin::User };
        ten_seg.add(make_segment(
            format!("segment {i}"),
            origin,
            "alice",
            &signer,
            None,
        ));
    }
    bench("policy.evaluate 10-segment context", || {
        let _ = policy.evaluate(&ten_seg, "send_email");
    });

    // Session context store
    use std::sync::Arc;
    use tessera_gateway::session_context::SessionContextStore;
    let store = Arc::new(SessionContextStore::new(3600.0, 10_000));
    let mut session_counter: u32 = 0;
    bench("SessionContextStore.get (new session each time)", || {
        let sid = format!("sess-{session_counter}");
        session_counter = session_counter.wrapping_add(1);
        let _ = store.get(&sid).unwrap();
    });

    let _ = store.get("warm-session").unwrap();
    bench("SessionContextStore.get (existing session)", || {
        let _ = store.get("warm-session").unwrap();
    });

    // Audit log
    use tempfile::tempdir;
    use serde_json::json;
    use tessera_gateway::audit_log::{AppendEntry, JsonlHashchainSink};
    let dir = tempdir().unwrap();
    let path = dir.path().join("bench-audit.jsonl");
    let sink = JsonlHashchainSink::new(&path, 10_000, None).unwrap();
    let mut audit_counter: u32 = 0;
    bench("audit_log.append (no fsync)", || {
        let _ = sink
            .append(AppendEntry {
                timestamp: "2026-04-23T00:00:00+00:00".into(),
                kind: "policy_deny".into(),
                principal: "bench".into(),
                detail: json!({"n": audit_counter}),
                correlation_id: None,
                trace_id: None,
            })
            .unwrap();
        audit_counter = audit_counter.wrapping_add(1);
    });

    // SSRF guard
    use tessera_gateway::ssrf_guard::SsrfGuard;
    let ssrf = SsrfGuard::with_defaults();
    bench("ssrf_guard.check_url (loopback literal)", || {
        let _ = ssrf.check_url("http://127.0.0.1/");
    });
    bench("ssrf_guard.check_url (encoded loopback)", || {
        let _ = ssrf.check_url("http://0x7f000001/");
    });
    bench("ssrf_guard.check_url (cloud metadata)", || {
        let _ = ssrf.check_url("http://169.254.169.254/latest/meta-data/");
    });

    // URL rules
    use tessera_gateway::url_rules::{PatternKind, RuleAction, UrlRule, UrlRulesEngine};
    let mut engine = UrlRulesEngine::default();
    engine.add(UrlRule::new("github.read", "https://api.github.com/")
        .kind(PatternKind::Prefix)
        .action(RuleAction::Allow));
    engine.add(UrlRule::new("admin.deny", "https://api.github.com/admin/")
        .kind(PatternKind::Prefix)
        .action(RuleAction::Deny));
    bench("url_rules.evaluate (allow hit)", || {
        let _ = engine.evaluate("https://api.github.com/repos/foo/bar", "GET");
    });
    bench("url_rules.evaluate (deny hit)", || {
        let _ = engine.evaluate("https://api.github.com/admin/users", "DELETE");
    });
    bench("url_rules.evaluate (no match)", || {
        let _ = engine.evaluate("https://example.com/", "GET");
    });

    println!();
    println!("# Done. Compare against `benchmarks/` in the Python repo.");
}
