//! Cross-implementation interop test for the CEL deny-rule engine.
//!
//! Tessera's CEL surface (Python `tessera.cel_engine` and Rust
//! `tessera_policy::cel`) must agree on which expression patterns
//! match a given context. The wire format is the rule expression
//! itself plus the seven activation variables; this test pins the
//! parity by driving the same rule + context through both ports
//! and asserting the decisions match.
//!
//! Skipped automatically when `python3` or the `tessera` package
//! (with `cel-python` installed) is not available.

use std::collections::HashMap;
use std::process::Command;

use tessera_policy::cel::{CelAction, CelContext, CelPolicyEngine, CelRule};

fn python_with_cel_available() -> bool {
    let probe = Command::new("python3")
        .args([
            "-c",
            "import tessera.cel_engine; import celpy",
        ])
        .output();
    matches!(probe, Ok(o) if o.status.success())
}

fn run_python(script: &str) -> std::process::Output {
    Command::new("python3")
        .args(["-c", script])
        .output()
        .expect("python3 invocation")
}

/// Run the same rule + context through Python and assert it matches
/// (or does not match) per `expect_match`. Encodes the context as
/// a tiny JSON blob the Python script reads back.
fn assert_python_agrees(
    rule_name: &str,
    rule_expr: &str,
    rule_action: &str,
    rule_msg: &str,
    ctx: &CelContext,
    expect_match: bool,
) {
    let args_json: String = {
        let mut entries: Vec<String> = ctx
            .args
            .iter()
            .map(|(k, v)| format!("{:?}: {:?}", k, v))
            .collect();
        entries.sort();
        format!("{{{}}}", entries.join(", "))
    };
    let actions_list: String = {
        let parts: Vec<String> = ctx
            .delegation_actions
            .iter()
            .map(|a| format!("{:?}", a))
            .collect();
        format!("({},)", parts.join(", "))
    };
    let subject_lit = match &ctx.delegation_subject {
        Some(s) => format!("{:?}", s),
        None => "None".to_owned(),
    };

    let script = format!(
        r#"
from tessera.cel_engine import CELRule, CELContext, CELPolicyEngine

rule = CELRule(name={rule_name:?}, expression={rule_expr:?}, action={rule_action:?}, message={rule_msg:?})
engine = CELPolicyEngine([rule])
ctx = CELContext(
    tool={tool:?},
    args={args},
    min_trust={min_trust},
    principal={principal:?},
    segment_count={segment_count},
    delegation_subject={subject},
    delegation_actions={actions},
)
decision = engine.evaluate(ctx)
expect_match = {expect_match}
if expect_match:
    assert decision is not None, "expected match, got None"
    assert decision.rule_name == {rule_name:?}
    assert decision.action == {rule_action:?}
    assert decision.message == {rule_msg:?}
else:
    assert decision is None, f"expected no match, got {{decision}}"
print("ok")
"#,
        rule_name = rule_name,
        rule_expr = rule_expr,
        rule_action = rule_action,
        rule_msg = rule_msg,
        tool = ctx.tool,
        args = args_json,
        min_trust = ctx.min_trust,
        principal = ctx.principal,
        segment_count = ctx.segment_count,
        subject = subject_lit,
        actions = actions_list,
        expect_match = if expect_match { "True" } else { "False" },
    );
    let out = run_python(&script);
    assert!(
        out.status.success(),
        "python CEL evaluation diverged from Rust:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn ctx() -> CelContext {
    let mut args = HashMap::new();
    args.insert("to".to_owned(), "bob@example.com".to_owned());
    args.insert("count".to_owned(), "5".to_owned());
    CelContext {
        tool: "send_email".to_owned(),
        args,
        min_trust: 100,
        principal: "alice@example.com".to_owned(),
        segment_count: 3,
        delegation_subject: Some("svc-alpha".to_owned()),
        delegation_actions: vec!["read".to_owned(), "write".to_owned()],
    }
}

fn rust_evaluate(rule: CelRule, ctx: &CelContext) -> Option<()> {
    let engine = CelPolicyEngine::new([rule]).unwrap();
    engine.evaluate(ctx).map(|_| ())
}

#[test]
fn parity_string_equality_match() {
    if !python_with_cel_available() {
        eprintln!("skipping: python3 + tessera + celpy not available");
        return;
    }
    let r = CelRule::new(
        "tool-eq",
        r#"tool == "send_email""#,
        CelAction::Deny,
        "blocked",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_string_equality_no_match() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "tool-eq-other",
        r#"tool == "delete_account""#,
        CelAction::Deny,
        "blocked",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_none());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, false);
}

#[test]
fn parity_int_comparison() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "low-trust",
        "min_trust < 200",
        CelAction::Deny,
        "untrusted floor",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_args_lookup() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "args-lookup",
        r#"args["to"] == "bob@example.com""#,
        CelAction::Deny,
        "to-bob",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_delegation_subject() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "deleg-subject",
        r#"delegation_subject == "svc-alpha""#,
        CelAction::Deny,
        "svc-alpha matched",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_delegation_actions_size() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "deleg-size",
        "size(delegation_actions) == 2",
        CelAction::Deny,
        "two-action delegation",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_compound_and() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "compound",
        r#"tool == "send_email" && min_trust < 200"#,
        CelAction::Deny,
        "compound match",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_compound_or_short_circuit() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "either",
        r#"tool == "never" || principal == "alice@example.com""#,
        CelAction::Deny,
        "either side matches",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}

#[test]
fn parity_require_approval_action() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "ask-human",
        r#"tool == "send_email""#,
        CelAction::RequireApproval,
        "needs human eyes",
    );
    let ctx = ctx();
    let engine = CelPolicyEngine::new([r.clone()]).unwrap();
    let d = engine.evaluate(&ctx).unwrap();
    assert_eq!(d.action, CelAction::RequireApproval);
    assert_python_agrees(
        &r.name,
        &r.expression,
        "require_approval",
        &r.message,
        &ctx,
        true,
    );
}

#[test]
fn parity_segment_count_threshold() {
    if !python_with_cel_available() {
        return;
    }
    let r = CelRule::new(
        "many-segs",
        "segment_count > 2",
        CelAction::Deny,
        "too many segments",
    );
    let ctx = ctx();
    assert!(rust_evaluate(r.clone(), &ctx).is_some());
    assert_python_agrees(&r.name, &r.expression, "deny", &r.message, &ctx, true);
}
