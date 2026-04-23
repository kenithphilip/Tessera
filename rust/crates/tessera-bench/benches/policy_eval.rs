//! Criterion microbenchmarks for the load-bearing primitives.
//!
//! Run with:
//!     cargo bench -p tessera-bench --bench policy_eval
//!
//! Workloads mirror the original manual harness in
//! `crates/tessera-gateway/benches/policy_eval.rs` so the numbers
//! are directly comparable across the workspace split. Compare
//! against the Python numbers in `benchmarks/microbenchmarks.md`:
//! Tessera Python policy evaluation is roughly 50 microseconds per
//! call including HMAC overhead; the Rust path runs in tens to low
//! hundreds of nanoseconds for the same workload.

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use tempfile::tempdir;
use tessera_audit::audit_log::{AppendEntry, JsonlHashchainSink};
use tessera_core::context::{make_segment, Context};
use tessera_core::labels::{HmacSigner, HmacVerifier, Origin, TrustLabel, TrustLevel};
use tessera_policy::policy::{Policy, ResourceRequirement};
use tessera_policy::ssrf_guard::SsrfGuard;
use tessera_policy::url_rules::{PatternKind, RuleAction, UrlRule, UrlRulesEngine};
use tessera_runtime::session_context::SessionContextStore;

const KEY: &[u8] = b"bench-key-32bytes!!!!!!!!!!!!!!!";

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

fn build_ten_segment_context(signer: &HmacSigner) -> Context {
    let mut ctx = Context::new();
    for i in 0..10 {
        let origin = if i == 7 { Origin::Web } else { Origin::User };
        ctx.add(make_segment(
            format!("segment {i}"),
            origin,
            "alice",
            signer,
            None,
        ));
    }
    ctx
}

fn bench_labels(c: &mut Criterion) {
    let signer = HmacSigner::new(KEY);
    let verifier = HmacVerifier::new(KEY);
    let segment = make_segment("hello world", Origin::User, "alice", &signer, None);

    c.bench_function("label_sign", |b| {
        b.iter(|| {
            let label = TrustLabel::new(Origin::User, "alice", TrustLevel::User, None);
            let signed = signer.sign(black_box(label), black_box("hello world"));
            black_box(signed);
        });
    });

    c.bench_function("label_verify", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&segment.label), black_box("hello world"))
                .unwrap();
        });
    });

    c.bench_function("make_segment", |b| {
        b.iter(|| {
            let seg = make_segment(
                black_box("hello world"),
                Origin::User,
                "alice",
                &signer,
                None,
            );
            black_box(seg);
        });
    });
}

fn bench_policy(c: &mut Criterion) {
    let signer = HmacSigner::new(KEY);
    let mut policy = Policy::new();
    policy.require(ResourceRequirement::new_tool("send_email", TrustLevel::User));

    let user_ctx = build_user_context(&signer);
    let tainted_ctx = build_tainted_context(&signer);
    let ten_seg_ctx = build_ten_segment_context(&signer);

    c.bench_function("policy_evaluate_clean_allow", |b| {
        b.iter(|| {
            let decision = policy.evaluate(black_box(&user_ctx), black_box("send_email"));
            black_box(decision);
        });
    });

    c.bench_function("policy_evaluate_tainted_deny", |b| {
        b.iter(|| {
            let decision = policy.evaluate(black_box(&tainted_ctx), black_box("send_email"));
            black_box(decision);
        });
    });

    c.bench_function("policy_evaluate_10_segments", |b| {
        b.iter(|| {
            let decision = policy.evaluate(black_box(&ten_seg_ctx), black_box("send_email"));
            black_box(decision);
        });
    });
}

fn bench_session_store(c: &mut Criterion) {
    let store = Arc::new(SessionContextStore::new(3600.0, 10_000));
    let _ = store.get("warm-session").unwrap();

    c.bench_function("session_store_get_warm", |b| {
        b.iter(|| {
            let entry = store.get(black_box("warm-session")).unwrap();
            black_box(entry);
        });
    });

    let mut counter: u64 = 0;
    c.bench_function("session_store_get_new", |b| {
        b.iter(|| {
            let sid = format!("sess-{counter}");
            counter = counter.wrapping_add(1);
            let entry = store.get(&sid).unwrap();
            black_box(entry);
        });
    });
}

fn bench_audit_log(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("bench-audit.jsonl");
    let sink = JsonlHashchainSink::new(&path, 10_000, None).unwrap();
    let mut counter: u64 = 0;

    c.bench_function("audit_append_no_fsync", |b| {
        b.iter(|| {
            let res = sink
                .append(AppendEntry {
                    timestamp: "2026-04-23T00:00:00+00:00".into(),
                    kind: "policy_deny".into(),
                    principal: "bench".into(),
                    detail: json!({"n": counter}),
                    correlation_id: None,
                    trace_id: None,
                })
                .unwrap();
            counter = counter.wrapping_add(1);
            black_box(res);
        });
    });
}

fn bench_ssrf_guard(c: &mut Criterion) {
    let ssrf = SsrfGuard::with_defaults();

    c.bench_function("ssrf_loopback_literal", |b| {
        b.iter(|| {
            let r = ssrf.check_url(black_box("http://127.0.0.1/"));
            black_box(r);
        });
    });

    c.bench_function("ssrf_encoded_loopback", |b| {
        b.iter(|| {
            let r = ssrf.check_url(black_box("http://0x7f000001/"));
            black_box(r);
        });
    });

    c.bench_function("ssrf_cloud_metadata", |b| {
        b.iter(|| {
            let r = ssrf.check_url(black_box("http://169.254.169.254/latest/meta-data/"));
            black_box(r);
        });
    });
}

fn bench_url_rules(c: &mut Criterion) {
    let mut engine = UrlRulesEngine::default();
    engine.add(
        UrlRule::new("github.read", "https://api.github.com/")
            .kind(PatternKind::Prefix)
            .action(RuleAction::Allow),
    );
    engine.add(
        UrlRule::new("admin.deny", "https://api.github.com/admin/")
            .kind(PatternKind::Prefix)
            .action(RuleAction::Deny),
    );

    c.bench_function("url_rules_allow_hit", |b| {
        b.iter(|| {
            let r = engine.evaluate(
                black_box("https://api.github.com/repos/foo/bar"),
                black_box("GET"),
            );
            black_box(r);
        });
    });

    c.bench_function("url_rules_deny_hit", |b| {
        b.iter(|| {
            let r = engine.evaluate(
                black_box("https://api.github.com/admin/users"),
                black_box("DELETE"),
            );
            black_box(r);
        });
    });

    c.bench_function("url_rules_no_match", |b| {
        b.iter(|| {
            let r = engine.evaluate(black_box("https://example.com/"), black_box("GET"));
            black_box(r);
        });
    });
}

criterion_group!(
    benches,
    bench_labels,
    bench_policy,
    bench_session_store,
    bench_audit_log,
    bench_ssrf_guard,
    bench_url_rules,
);
criterion_main!(benches);
