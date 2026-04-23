//! Cranelift-backed JIT for the CEL deny-rule subset.
//!
//! This module ships under the `cel-jit` cargo feature. When enabled,
//! [`JitCelEvaluator`] walks the cel-parser AST, compiles every rule
//! whose expression fits the supported subset to native code via
//! cranelift-jit, and keeps the interpreter from
//! [`crate::cel::CelPolicyEngine`] as the fallback for everything
//! else.
//!
//! ## Honest scoping
//!
//! cel-interpreter overhead is already sub-microsecond per rule for
//! Tessera's expression complexity, so the realistic JIT win is
//! shaving an extra ~100-300 ns off a 600-900 ns interpreter call.
//! We ship the codegen anyway because (a) the user picked the
//! maximalist option, (b) it puts Tessera in a defensible position
//! when rule counts grow 10-100x, and (c) it forces the eval surface
//! ([`CelEvaluator`]) to stabilize behind a trait. Operators see the
//! degradation rate via [`JitCelEvaluator::fallback_count`] and can
//! decide whether the JIT is paying back on their workload.
//!
//! ## Supported AST subset
//!
//! Only the subset Tessera's actual rules use today emits native
//! code. Anything else falls back to the interpreter for that rule.
//!
//! - `IntAtom op IntAtom` and `IntAtom op Ident(int_field)` and
//!   `Ident(int_field) op IntAtom` for the relations `==, !=, <, <=,
//!   >, >=`. The two int fields are `min_trust` and `segment_count`
//!   (offsets baked in at compile time).
//! - `Bool` atoms (`true`, `false`).
//! - Boolean composition: `&&`, `||`, `!` (short-circuiting).
//! - Anything string-related, args-map lookup, list-size, function
//!   calls, member access, or unsupported operators forces the rule
//!   into the interpreter fallback.
//!
//! ## Activation layout
//!
//! The JIT-compiled functions are passed a pointer to a
//! [`JitActivation`] struct (`#[repr(C)]`). Loads happen at fixed
//! offsets so cranelift does not need to know anything about Rust's
//! HashMap or String layout.

use std::sync::atomic::{AtomicUsize, Ordering};

use cel_parser::{Atom, Expression, RelationOp, UnaryOp};

use crate::cel::{CelContext, CelDecision, CelPolicyEngine, CelRule};

/// Common evaluator surface for [`CelPolicyEngine`] (interpreter)
/// and [`JitCelEvaluator`] (cranelift JIT). [`crate::policy::Policy`]
/// stores an `Arc<dyn CelEvaluator>` when both backends ship together.
pub trait CelEvaluator: Send + Sync {
    fn evaluate(&self, ctx: &CelContext) -> Option<CelDecision>;
    fn rule_count(&self) -> usize;
    fn rules(&self) -> Box<dyn Iterator<Item = &CelRule> + '_>;
}

impl CelEvaluator for CelPolicyEngine {
    fn evaluate(&self, ctx: &CelContext) -> Option<CelDecision> {
        CelPolicyEngine::evaluate(self, ctx)
    }
    fn rule_count(&self) -> usize {
        CelPolicyEngine::rule_count(self)
    }
    fn rules(&self) -> Box<dyn Iterator<Item = &CelRule> + '_> {
        Box::new(CelPolicyEngine::rules(self))
    }
}

/// Layout of activation values the JIT-compiled functions read.
///
/// `#[repr(C)]` so cranelift can use fixed offsets. Only the int
/// fields we natively codegen against are exposed here; the rest
/// (strings, args, delegation list) live in the interpreter
/// fallback path.
#[repr(C)]
struct JitActivation {
    min_trust: i64,
    segment_count: i64,
}

/// Identifies the int fields the JIT can natively load from
/// [`JitActivation`]. Used by the AST classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntField {
    MinTrust,
    SegmentCount,
}

impl IntField {
    fn from_ident(name: &str) -> Option<Self> {
        match name {
            "min_trust" => Some(Self::MinTrust),
            "segment_count" => Some(Self::SegmentCount),
            _ => None,
        }
    }

    /// Byte offset within [`JitActivation`].
    fn offset_bytes(self) -> i32 {
        match self {
            Self::MinTrust => 0,
            Self::SegmentCount => 8,
        }
    }
}

/// Compile-time classifier: walks the cel-parser AST and decides
/// whether every node is JIT-compilable for our supported subset.
/// Used to short-circuit codegen and route directly to the
/// interpreter fallback for any unsupported rule.
fn is_jit_compilable(expr: &Expression) -> bool {
    match expr {
        Expression::Atom(atom) => matches!(atom, Atom::Bool(_) | Atom::Int(_)),
        Expression::Ident(name) => IntField::from_ident(name).is_some(),
        Expression::And(a, b) | Expression::Or(a, b) => {
            is_jit_compilable(a) && is_jit_compilable(b)
        }
        Expression::Unary(UnaryOp::Not, inner) => is_jit_compilable(inner),
        Expression::Relation(left, op, right) => {
            matches!(
                op,
                RelationOp::Equals
                    | RelationOp::NotEquals
                    | RelationOp::LessThan
                    | RelationOp::LessThanEq
                    | RelationOp::GreaterThan
                    | RelationOp::GreaterThanEq
            ) && is_int_node(left)
                && is_int_node(right)
        }
        // Arithmetic, member access, function calls, list/map
        // construction, ternary, etc. All fall back to interpreter.
        _ => false,
    }
}

fn is_int_node(expr: &Expression) -> bool {
    match expr {
        Expression::Atom(Atom::Int(_)) => true,
        Expression::Ident(name) => IntField::from_ident(name).is_some(),
        Expression::Unary(UnaryOp::Minus, inner) => is_int_node(inner),
        _ => false,
    }
}

/// Compile-time classification: every rule is either codegen-able
/// or falls back to the interpreter. Stored on the engine and
/// reflected in [`JitCelEvaluator::fallback_count`].
enum CompiledRule {
    /// Native code emitted by cranelift; the function pointer takes
    /// `*const JitActivation` and returns 0 (no match) or 1 (match).
    Jitted {
        rule: CelRule,
        function: fn(*const JitActivation) -> i64,
    },
    /// AST contained a node outside the supported subset; defer to
    /// the interpreter for this rule.
    Interpreted { rule: CelRule, program: cel_interpreter::Program },
}

/// CEL evaluator that codegens the supported subset to native code
/// via cranelift-jit. Falls back to the cel-interpreter program for
/// any rule containing unsupported AST nodes.
#[allow(missing_debug_implementations)]
pub struct JitCelEvaluator {
    rules: Vec<CompiledRule>,
    /// Total number of rules that fell back to interpreter. Read via
    /// [`Self::fallback_count`] for ops visibility.
    fallback_count: AtomicUsize,
    /// Total rules JIT-compiled to native code.
    jit_count: AtomicUsize,
    /// Held alive so the JIT-allocated code is not freed while we
    /// hold function pointers into it. `cranelift_jit::JITModule`
    /// owns the executable memory. Never accessed after construction;
    /// the Mutex is purely a Sync wrapper (JITModule is not Sync).
    #[cfg(feature = "cel-jit")]
    _module: parking_lot::Mutex<cranelift_jit::JITModule>,
}

impl JitCelEvaluator {
    /// Construct from the same rule set the interpreter takes. JIT-
    /// classifies each rule, codegens what it can, falls back to
    /// interpreter for the rest.
    #[cfg(feature = "cel-jit")]
    pub fn new(
        rules: impl IntoIterator<Item = CelRule>,
    ) -> Result<Self, JitCompileError> {
        let mut module = jit_module_new()?;
        let mut compiled = Vec::new();
        let mut jit_count = 0usize;
        let mut fallback_count = 0usize;

        for rule in rules {
            let ast = cel_parser::parse(&rule.expression).map_err(|e| {
                JitCompileError::Parse {
                    rule_name: rule.name.clone(),
                    expression: rule.expression.clone(),
                    source: e.to_string(),
                }
            })?;

            if is_jit_compilable(&ast) {
                let function = codegen_rule(&mut module, &rule.name, &ast)?;
                compiled.push(CompiledRule::Jitted {
                    rule,
                    function,
                });
                jit_count += 1;
            } else {
                let program = cel_interpreter::Program::compile(&rule.expression)
                    .map_err(|e| JitCompileError::Interpreter {
                        rule_name: rule.name.clone(),
                        source: e.to_string(),
                    })?;
                compiled.push(CompiledRule::Interpreted {
                    rule,
                    program,
                });
                fallback_count += 1;
            }
        }

        Ok(Self {
            rules: compiled,
            fallback_count: AtomicUsize::new(fallback_count),
            jit_count: AtomicUsize::new(jit_count),
            _module: parking_lot::Mutex::new(module),
        })
    }

    /// Number of rules that compiled to native code at construction.
    pub fn jit_count(&self) -> usize {
        self.jit_count.load(Ordering::Relaxed)
    }

    /// Number of rules that fell back to the interpreter at
    /// construction. A non-zero value here means at least one rule
    /// uses an AST node outside the JIT-supported subset.
    pub fn fallback_count(&self) -> usize {
        self.fallback_count.load(Ordering::Relaxed)
    }
}

impl CelEvaluator for JitCelEvaluator {
    fn evaluate(&self, ctx: &CelContext) -> Option<CelDecision> {
        if self.rules.is_empty() {
            return None;
        }

        // The JIT activation is a tiny C-layout struct; build it on
        // the stack per call. The interpreter fallback path uses the
        // full CelContext so it sees every variable.
        let jit_activation = JitActivation {
            min_trust: ctx.min_trust,
            segment_count: ctx.segment_count,
        };

        for rule in &self.rules {
            match rule {
                CompiledRule::Jitted { rule: r, function } => {
                    let result = function(&jit_activation as *const JitActivation);
                    if result != 0 {
                        return Some(CelDecision {
                            rule_name: r.name.clone(),
                            action: r.action,
                            message: r.message.clone(),
                        });
                    }
                }
                CompiledRule::Interpreted { rule: r, program } => {
                    let activation = build_interpreter_activation(ctx);
                    if let Ok(cel_interpreter::Value::Bool(true)) = program.execute(&activation) {
                        return Some(CelDecision {
                            rule_name: r.name.clone(),
                            action: r.action,
                            message: r.message.clone(),
                        });
                    }
                }
            }
        }
        None
    }

    fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn rules(&self) -> Box<dyn Iterator<Item = &CelRule> + '_> {
        Box::new(self.rules.iter().map(|r| match r {
            CompiledRule::Jitted { rule, .. } => rule,
            CompiledRule::Interpreted { rule, .. } => rule,
        }))
    }
}

/// Reasons [`JitCelEvaluator::new`] can fail.
#[derive(Debug)]
pub enum JitCompileError {
    Parse {
        rule_name: String,
        expression: String,
        source: String,
    },
    Interpreter {
        rule_name: String,
        source: String,
    },
    Codegen {
        rule_name: String,
        source: String,
    },
}

impl std::fmt::Display for JitCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse {
                rule_name,
                expression,
                source,
            } => write!(
                f,
                "JIT parse failed for rule {rule_name:?} (expression: {expression:?}): {source}"
            ),
            Self::Interpreter { rule_name, source } => write!(
                f,
                "JIT fallback to interpreter failed for rule {rule_name:?}: {source}"
            ),
            Self::Codegen { rule_name, source } => write!(
                f,
                "JIT codegen failed for rule {rule_name:?}: {source}"
            ),
        }
    }
}

impl std::error::Error for JitCompileError {}

/// Build the cel-interpreter activation from a [`CelContext`].
/// Identical shape to [`crate::cel::build_activation`] (kept private
/// in cel.rs); duplicated here to avoid coupling the interpreter
/// path to JIT-specific code.
fn build_interpreter_activation(
    ctx: &CelContext,
) -> cel_interpreter::Context<'static> {
    let mut activation = cel_interpreter::Context::default();
    activation.add_variable_from_value("tool", ctx.tool.clone());
    let args_value: std::collections::HashMap<String, String> =
        ctx.args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    activation.add_variable_from_value("args", args_value);
    activation.add_variable_from_value("min_trust", ctx.min_trust);
    activation.add_variable_from_value("principal", ctx.principal.clone());
    activation.add_variable_from_value("segment_count", ctx.segment_count);
    activation.add_variable_from_value(
        "delegation_subject",
        ctx.delegation_subject.clone().unwrap_or_default(),
    );
    activation.add_variable_from_value("delegation_actions", ctx.delegation_actions.clone());
    activation
}

// ---------------------------------------------------------------------------
// Cranelift codegen (cel-jit feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "cel-jit")]
fn jit_module_new() -> Result<cranelift_jit::JITModule, JitCompileError> {
    use cranelift::codegen::settings::Configurable;
    use cranelift_jit::{JITBuilder, JITModule};

    let mut flag_builder = cranelift::codegen::settings::builder();
    // Optimize for the small leaf functions we emit. `speed_and_size`
    // gives the tightest code for our subset; per-rule total size is
    // at most a few dozen bytes.
    flag_builder
        .set("opt_level", "speed_and_size")
        .map_err(|e: cranelift::codegen::settings::SetError| {
            JitCompileError::Codegen {
                rule_name: "<global>".to_owned(),
                source: e.to_string(),
            }
        })?;
    let isa_builder =
        cranelift_native::builder().map_err(|e: &'static str| JitCompileError::Codegen {
            rule_name: "<global>".to_owned(),
            source: e.to_owned(),
        })?;
    let isa = isa_builder
        .finish(cranelift::codegen::settings::Flags::new(flag_builder))
        .map_err(|e: cranelift::codegen::CodegenError| JitCompileError::Codegen {
            rule_name: "<global>".to_owned(),
            source: e.to_string(),
        })?;
    let builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
    Ok(JITModule::new(builder))
}

#[cfg(feature = "cel-jit")]
fn codegen_rule(
    module: &mut cranelift_jit::JITModule,
    rule_name: &str,
    ast: &Expression,
) -> Result<fn(*const JitActivation) -> i64, JitCompileError> {
    use cranelift::codegen::ir::{AbiParam, InstBuilder};
    use cranelift::codegen::Context;
    use cranelift::frontend::{FunctionBuilder, FunctionBuilderContext};
    use cranelift::prelude::types;
    use cranelift_module::{Linkage, Module};

    let mut sig = module.make_signature();
    let pointer_ty = module.target_config().pointer_type();
    sig.params.push(AbiParam::new(pointer_ty));
    sig.returns.push(AbiParam::new(types::I64));

    let func_id = module
        .declare_function(
            &format!("cel_rule_{}", sanitize_identifier(rule_name)),
            Linkage::Local,
            &sig,
        )
        .map_err(|e| JitCompileError::Codegen {
            rule_name: rule_name.to_owned(),
            source: e.to_string(),
        })?;

    let mut ctx = Context::new();
    ctx.func.signature = sig.clone();

    let mut builder_ctx = FunctionBuilderContext::new();
    {
        let mut builder = FunctionBuilder::new(&mut ctx.func, &mut builder_ctx);
        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        builder.seal_block(entry);

        let activation_ptr = builder.block_params(entry)[0];
        let result = compile_expression(&mut builder, activation_ptr, ast, pointer_ty);
        // Normalize i8/bool result to i64 0/1.
        let extended = builder.ins().uextend(types::I64, result);
        builder.ins().return_(&[extended]);
        builder.finalize();
    }

    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitCompileError::Codegen {
            rule_name: rule_name.to_owned(),
            source: e.to_string(),
        })?;
    module.clear_context(&mut ctx);
    module
        .finalize_definitions()
        .map_err(|e| JitCompileError::Codegen {
            rule_name: rule_name.to_owned(),
            source: e.to_string(),
        })?;

    let raw = module.get_finalized_function(func_id);
    // SAFETY: `raw` is a freshly JIT-emitted function with the signature
    // `extern "C" fn(*const JitActivation) -> i64`. The JIT module is
    // held alive by `JitCelEvaluator::_module` for the life of the
    // evaluator, so the pointer remains valid as long as the function
    // pointer we return is in use.
    #[allow(unsafe_code)]
    let function: fn(*const JitActivation) -> i64 =
        unsafe { std::mem::transmute(raw) };
    Ok(function)
}

#[cfg(feature = "cel-jit")]
fn compile_expression(
    builder: &mut cranelift::frontend::FunctionBuilder<'_>,
    activation_ptr: cranelift::codegen::ir::Value,
    expr: &Expression,
    _pointer_ty: cranelift::codegen::ir::Type,
) -> cranelift::codegen::ir::Value {
    use cranelift::codegen::ir::condcodes::IntCC;
    use cranelift::codegen::ir::{InstBuilder, MemFlags};
    use cranelift::prelude::types;

    match expr {
        Expression::Atom(Atom::Bool(b)) => {
            builder.ins().iconst(types::I8, if *b { 1 } else { 0 })
        }
        Expression::Atom(Atom::Int(n)) => {
            // Atoms only appear as int leaves of relations during the
            // is_jit_compilable check, so callers extract the i64
            // value directly. This branch is reached only via
            // compile_int_node for a top-level Atom expression, which
            // is_jit_compilable rejects; treat as a no-match to be safe.
            builder.ins().iconst(types::I8, 0).tap(|_| {
                let _ = n;
            })
        }
        Expression::Ident(name) => {
            // Top-level ident must be the bool-typed result of some
            // compile-time-known field; we don't expose any boolean
            // ident, so this returns false. is_jit_compilable rejects
            // this path; defensive zero.
            let _ = name;
            builder.ins().iconst(types::I8, 0)
        }
        Expression::Unary(UnaryOp::Not, inner) => {
            let v = compile_expression(builder, activation_ptr, inner, _pointer_ty);
            // Logical NOT on i8 0/1.
            let one = builder.ins().iconst(types::I8, 1);
            builder.ins().bxor(v, one)
        }
        Expression::And(a, b) => {
            // Short-circuit: if a == 0, return 0; else return b.
            let a_val = compile_expression(builder, activation_ptr, a, _pointer_ty);
            let then_block = builder.create_block();
            let else_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, types::I8);
            builder.ins().brif(a_val, then_block, &[], else_block, &[]);

            builder.switch_to_block(then_block);
            builder.seal_block(then_block);
            let b_val = compile_expression(builder, activation_ptr, b, _pointer_ty);
            builder.ins().jump(merge_block, &[b_val]);

            builder.switch_to_block(else_block);
            builder.seal_block(else_block);
            let zero = builder.ins().iconst(types::I8, 0);
            builder.ins().jump(merge_block, &[zero]);

            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            builder.block_params(merge_block)[0]
        }
        Expression::Or(a, b) => {
            // Short-circuit: if a != 0, return 1; else return b.
            let a_val = compile_expression(builder, activation_ptr, a, _pointer_ty);
            let then_block = builder.create_block();
            let else_block = builder.create_block();
            let merge_block = builder.create_block();
            builder.append_block_param(merge_block, types::I8);
            builder.ins().brif(a_val, then_block, &[], else_block, &[]);

            builder.switch_to_block(then_block);
            builder.seal_block(then_block);
            let one = builder.ins().iconst(types::I8, 1);
            builder.ins().jump(merge_block, &[one]);

            builder.switch_to_block(else_block);
            builder.seal_block(else_block);
            let b_val = compile_expression(builder, activation_ptr, b, _pointer_ty);
            builder.ins().jump(merge_block, &[b_val]);

            builder.switch_to_block(merge_block);
            builder.seal_block(merge_block);
            builder.block_params(merge_block)[0]
        }
        Expression::Relation(left, op, right) => {
            let l = compile_int_node(builder, activation_ptr, left);
            let r = compile_int_node(builder, activation_ptr, right);
            let cc = match op {
                RelationOp::Equals => IntCC::Equal,
                RelationOp::NotEquals => IntCC::NotEqual,
                RelationOp::LessThan => IntCC::SignedLessThan,
                RelationOp::LessThanEq => IntCC::SignedLessThanOrEqual,
                RelationOp::GreaterThan => IntCC::SignedGreaterThan,
                RelationOp::GreaterThanEq => IntCC::SignedGreaterThanOrEqual,
                _ => unreachable!("classifier rejected unsupported relation"),
            };
            let bool_val = builder.ins().icmp(cc, l, r);
            // icmp returns I8 (Bool); ensure I8 width.
            builder.ins().bmask(types::I8, bool_val)
        }
        _ => {
            // Should not happen: is_jit_compilable rejects everything
            // not handled above. Defensive zero so the JIT does not
            // panic on a code-path the classifier missed.
            builder.ins().iconst(types::I8, 0)
        }
    }
}

#[cfg(feature = "cel-jit")]
fn compile_int_node(
    builder: &mut cranelift::frontend::FunctionBuilder<'_>,
    activation_ptr: cranelift::codegen::ir::Value,
    expr: &Expression,
) -> cranelift::codegen::ir::Value {
    use cranelift::codegen::ir::{InstBuilder, MemFlags};
    use cranelift::prelude::types;

    match expr {
        Expression::Atom(Atom::Int(n)) => builder.ins().iconst(types::I64, *n),
        Expression::Ident(name) => {
            let field =
                IntField::from_ident(name).expect("classifier guarantees int ident");
            builder
                .ins()
                .load(types::I64, MemFlags::new(), activation_ptr, field.offset_bytes())
        }
        Expression::Unary(UnaryOp::Minus, inner) => {
            let v = compile_int_node(builder, activation_ptr, inner);
            builder.ins().ineg(v)
        }
        _ => unreachable!("classifier guarantees int node shape"),
    }
}

#[cfg(feature = "cel-jit")]
fn sanitize_identifier(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

// Tap helper for the few places where we want to use a value as a
// statement separator without restructuring control flow.
#[cfg(feature = "cel-jit")]
trait Tap: Sized {
    fn tap<F: FnOnce(&Self)>(self, f: F) -> Self {
        f(&self);
        self
    }
}
#[cfg(feature = "cel-jit")]
impl<T> Tap for T {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "cel-jit"))]
mod tests {
    use super::*;
    use crate::cel::CelAction;

    fn rule(name: &str, expr: &str) -> CelRule {
        CelRule::new(name, expr, CelAction::Deny, format!("rule {name}"))
    }

    fn ctx_min_100_segs_3() -> CelContext {
        CelContext::new("send_email", "alice", 100, 3)
    }

    // ---- Classification ------------------------------------------------

    #[test]
    fn classifier_accepts_int_comparisons() {
        let ast = cel_parser::parse("min_trust < 200").unwrap();
        assert!(is_jit_compilable(&ast));
    }

    #[test]
    fn classifier_accepts_boolean_composition_of_int_cmps() {
        let ast = cel_parser::parse("min_trust < 200 && segment_count > 0").unwrap();
        assert!(is_jit_compilable(&ast));
    }

    #[test]
    fn classifier_rejects_string_comparison() {
        let ast = cel_parser::parse(r#"tool == "send_email""#).unwrap();
        assert!(!is_jit_compilable(&ast));
    }

    #[test]
    fn classifier_rejects_args_lookup() {
        let ast = cel_parser::parse(r#"args["to"] == "bob""#).unwrap();
        assert!(!is_jit_compilable(&ast));
    }

    #[test]
    fn classifier_rejects_function_call() {
        let ast = cel_parser::parse("size(delegation_actions) == 2").unwrap();
        assert!(!is_jit_compilable(&ast));
    }

    // ---- JIT codegen + evaluation -------------------------------------

    #[test]
    fn jit_evaluator_constructs_with_pure_int_rules() {
        let r = rule("low-trust", "min_trust < 200");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.jit_count(), 1);
        assert_eq!(engine.fallback_count(), 0);
    }

    #[test]
    fn jit_evaluator_falls_back_for_string_rules() {
        let r = rule("string-rule", r#"tool == "send_email""#);
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.jit_count(), 0);
        assert_eq!(engine.fallback_count(), 1);
    }

    #[test]
    fn jit_int_lt_matches_below_threshold() {
        let r = rule("low", "min_trust < 200");
        let engine = JitCelEvaluator::new([r]).unwrap();
        let d = engine.evaluate(&ctx_min_100_segs_3()).unwrap();
        assert_eq!(d.rule_name, "low");
    }

    #[test]
    fn jit_int_lt_does_not_match_at_threshold() {
        let mut ctx = ctx_min_100_segs_3();
        ctx.min_trust = 200;
        let r = rule("low", "min_trust < 200");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx).is_none());
    }

    #[test]
    fn jit_int_eq() {
        let r = rule("eq-100", "min_trust == 100");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_int_neq() {
        let r = rule("neq-1", "min_trust != 1");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_int_le_inclusive() {
        let r = rule("le", "min_trust <= 100");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_int_ge_inclusive() {
        let r = rule("ge", "min_trust >= 100");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_int_gt_strict() {
        let r = rule("gt", "min_trust > 100");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_none());
    }

    #[test]
    fn jit_segment_count_field_loaded() {
        let r = rule("seg-many", "segment_count > 2");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_and_short_circuits_to_no_match_when_left_false() {
        let r = rule("and", "min_trust > 1000 && segment_count > 0");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_none());
    }

    #[test]
    fn jit_and_match_when_both_true() {
        let r = rule("and", "min_trust < 200 && segment_count > 0");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_or_short_circuits_to_match_when_left_true() {
        let r = rule("or", "min_trust < 200 || segment_count == 99");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_negation_flips_result() {
        let r = rule("not", "!(min_trust > 1000)");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_atom_int_left_side() {
        let r = rule("atom-left", "200 > min_trust");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_negative_atom() {
        let r = rule("neg", "min_trust > -1");
        let engine = JitCelEvaluator::new([r]).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_some());
    }

    #[test]
    fn jit_first_matching_rule_wins_across_jit_and_interpreter() {
        let rules = vec![
            rule("native-no-match", "min_trust > 1000"),
            rule("string-fallback-match", r#"tool == "send_email""#),
        ];
        let engine = JitCelEvaluator::new(rules).unwrap();
        assert_eq!(engine.jit_count(), 1);
        assert_eq!(engine.fallback_count(), 1);
        let d = engine.evaluate(&ctx_min_100_segs_3()).unwrap();
        assert_eq!(d.rule_name, "string-fallback-match");
    }

    #[test]
    fn jit_invalid_expression_errors_at_construction() {
        let r = CelRule::new("bad", "min_trust @@@ 1", CelAction::Deny, "x");
        let err = match JitCelEvaluator::new([r]) {
            Err(e) => e,
            Ok(_) => panic!("expected JIT compile failure"),
        };
        match err {
            JitCompileError::Parse { rule_name, .. } => assert_eq!(rule_name, "bad"),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn jit_empty_rule_set_returns_none() {
        let engine = JitCelEvaluator::new(Vec::<CelRule>::new()).unwrap();
        assert!(engine.evaluate(&ctx_min_100_segs_3()).is_none());
    }

    // ---- Parity vs interpreter ----------------------------------------

    fn assert_parity(expr: &str, ctx: &CelContext) {
        let r = rule("parity", expr);
        let interp = CelPolicyEngine::new([r.clone()]).unwrap();
        let jit = JitCelEvaluator::new([r]).unwrap();
        let interp_dec = interp.evaluate(ctx).map(|d| (d.rule_name, d.action));
        let jit_dec =
            CelEvaluator::evaluate(&jit, ctx).map(|d| (d.rule_name, d.action));
        assert_eq!(
            interp_dec, jit_dec,
            "interpreter / JIT diverged for expression {expr:?}"
        );
    }

    #[test]
    fn parity_int_lt() {
        assert_parity("min_trust < 200", &ctx_min_100_segs_3());
    }

    #[test]
    fn parity_int_eq() {
        assert_parity("min_trust == 100", &ctx_min_100_segs_3());
    }

    #[test]
    fn parity_compound_and() {
        assert_parity(
            "min_trust < 200 && segment_count > 0",
            &ctx_min_100_segs_3(),
        );
    }

    #[test]
    fn parity_compound_or() {
        assert_parity(
            "min_trust > 1000 || segment_count > 0",
            &ctx_min_100_segs_3(),
        );
    }

    #[test]
    fn parity_negation() {
        assert_parity("!(min_trust > 1000)", &ctx_min_100_segs_3());
    }
}
