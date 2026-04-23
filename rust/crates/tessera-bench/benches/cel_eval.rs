//! CEL evaluation microbench: cel-interpreter vs cranelift-jit.
//!
//! Run with `cargo bench --bench cel_eval -p tessera-bench --features tessera-policy/cel-jit`.
//!
//! The bench shapes match what Tessera production rules look like:
//! a single int comparison (the cheapest case), a 5-rule pack
//! (typical small policy), and a 50-rule pack (large). All rules
//! evaluate to the same result via both engines so the bench is
//! a true apples-to-apples comparison.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use tessera_policy::cel::{CelAction, CelContext, CelPolicyEngine, CelRule};
use tessera_policy::cel_jit::{CelEvaluator, JitCelEvaluator};

fn ctx() -> CelContext {
    CelContext::new("send_email", "alice@example.com", 100, 3)
}

fn rule(name: &str, expr: &str) -> CelRule {
    CelRule::new(name, expr, CelAction::Deny, format!("rule {name}"))
}

fn int_rule_pack(n: usize) -> Vec<CelRule> {
    // n int-only rules so the JIT can compile every one. The first
    // rules deliberately do not match so we exercise the full chain
    // before hitting the matching rule at the end.
    let mut rules: Vec<CelRule> = Vec::with_capacity(n);
    for i in 0..(n - 1) {
        rules.push(rule(
            &format!("no-match-{i}"),
            &format!("min_trust > {}", 1000 + i as i64),
        ));
    }
    rules.push(rule("match", "min_trust < 200"));
    rules
}

fn bench_single_rule(c: &mut Criterion) {
    let mut group = c.benchmark_group("cel_single_rule");
    let r = rule("low", "min_trust < 200");
    let interp = CelPolicyEngine::new([r.clone()]).unwrap();
    let jit = JitCelEvaluator::new([r]).unwrap();
    let context = ctx();

    group.bench_function("interpreter", |b| {
        b.iter(|| {
            let d = interp.evaluate(black_box(&context));
            black_box(d);
        });
    });
    group.bench_function("jit", |b| {
        b.iter(|| {
            let d = CelEvaluator::evaluate(&jit, black_box(&context));
            black_box(d);
        });
    });
    group.finish();
}

fn bench_rule_pack(c: &mut Criterion) {
    let mut group = c.benchmark_group("cel_rule_pack");
    for &n in &[5usize, 50] {
        let rules = int_rule_pack(n);
        let interp = CelPolicyEngine::new(rules.clone()).unwrap();
        let jit = JitCelEvaluator::new(rules).unwrap();
        let context = ctx();

        group.bench_with_input(
            BenchmarkId::new("interpreter", n),
            &context,
            |b, ctx| {
                b.iter(|| {
                    let d = interp.evaluate(ctx);
                    black_box(d);
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("jit", n), &context, |b, ctx| {
            b.iter(|| {
                let d = CelEvaluator::evaluate(&jit, ctx);
                black_box(d);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_single_rule, bench_rule_pack);
criterion_main!(benches);
