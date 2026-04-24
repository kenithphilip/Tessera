//! PyO3 bindings for the Tessera Rust workspace.
//!
//! Distribution name (`tessera-rs` on PyPI), import name
//! (`tessera_rs` in Python). The underscore in the import name
//! keeps this disjoint from the existing `tessera` Python package
//! so the two can coexist in the same environment.
//!
//! Phase 3 surface (alpha.3): the most useful zero-dependency
//! primitives. The Python adapter authors who wanted a fast path
//! get it for `Policy.evaluate`, the canonical-JSON audit log,
//! `injection_score`, the unicode tag scanner, the SSRF guard, and
//! URL-rules evaluation. Later phases expand the surface as more
//! primitives stabilize.
//!
//! Submodule layout in Python:
//!
//! ```python
//! from tessera_rs.policy import Policy
//! from tessera_rs.context import Context, make_segment
//! from tessera_rs.scanners import injection_score, scan_unicode_tags
//! from tessera_rs.audit import canonical_json, JsonlHashchainSink
//! from tessera_rs.ssrf import SsrfGuard
//! from tessera_rs.url_rules import UrlRulesEngine
//! ```

use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

use tessera_audit::{canonical_json, AppendEntry, JsonlHashchainSink, ReplayEnvelope};
use tessera_core::context::{make_segment as core_make_segment, Context as CoreContext};
use tessera_core::labels::{HmacSigner, Origin, TrustLevel};
use tessera_policy::cel::{
    CelAction, CelContext, CelDecision, CelPolicyEngine, CelRule,
};
use tessera_policy::ratelimit::{CallRateStatus, ToolCallRateLimit};
use tessera_policy::{Policy as PolicyImpl, ResourceRequirement, SsrfGuard as SsrfGuardImpl,
                     UrlRule as UrlRuleImpl, UrlRulesEngine as UrlRulesEngineImpl, RuleAction,
                     PatternKind};
use tessera_scanners::{
    heuristic::injection_score as heuristic_injection_score,
    unicode::scan_unicode_tags as unicode_scan_tags,
};

// ---- Helpers -------------------------------------------------------------

fn json_to_pyobject(py: Python<'_>, v: &Value) -> PyObject {
    match v {
        Value::Null => py.None(),
        Value::Bool(b) => b.into_py(py),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_py(py)
            } else if let Some(f) = n.as_f64() {
                f.into_py(py)
            } else {
                py.None()
            }
        }
        Value::String(s) => s.into_py(py),
        Value::Array(arr) => {
            let items: Vec<PyObject> = arr.iter().map(|x| json_to_pyobject(py, x)).collect();
            items.into_py(py)
        }
        Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, val) in map {
                let _ = dict.set_item(k, json_to_pyobject(py, val));
            }
            dict.into()
        }
    }
}

// ---- Audit submodule -----------------------------------------------------

/// Canonical JSON for any JSON-serializable Python value (matches
/// Python's `json.dumps(sort_keys=True, separators=(",", ":"))`).
#[pyfunction]
fn audit_canonical_json(py: Python<'_>, value: &str) -> PyResult<String> {
    let _ = py;
    let parsed: Value =
        serde_json::from_str(value).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(canonical_json(&parsed))
}

/// Hash-chained JSONL audit-log sink (Rust-backed).
#[pyclass(name = "JsonlHashchainSink", module = "tessera_rs.audit")]
struct PyJsonlHashchainSink {
    inner: JsonlHashchainSink,
}

#[pymethods]
impl PyJsonlHashchainSink {
    #[new]
    #[pyo3(signature = (path, fsync_every=1, seal_key=None))]
    fn new(path: &str, fsync_every: u64, seal_key: Option<Vec<u8>>) -> PyResult<Self> {
        let sink = JsonlHashchainSink::new(path, fsync_every, seal_key)
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))?;
        Ok(Self { inner: sink })
    }

    #[pyo3(signature = (timestamp, kind, principal, detail_json, correlation_id=None, trace_id=None))]
    fn append(
        &self,
        timestamp: &str,
        kind: &str,
        principal: &str,
        detail_json: &str,
        correlation_id: Option<String>,
        trace_id: Option<String>,
    ) -> PyResult<u64> {
        let detail: Value = serde_json::from_str(detail_json)
            .map_err(|e| PyValueError::new_err(format!("malformed detail JSON: {e}")))?;
        let entry = AppendEntry {
            timestamp: timestamp.to_string(),
            kind: kind.to_string(),
            principal: principal.to_string(),
            detail,
            correlation_id,
            trace_id,
        };
        let record = self
            .inner
            .append(entry)
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))?;
        Ok(record.seq)
    }

    /// Block until the writer thread has drained every queued append
    /// to disk. Mirrors the Rust `JsonlHashchainSink::flush` method.
    /// Useful in tests that read the file immediately after append.
    fn flush(&self) -> PyResult<()> {
        self.inner
            .flush()
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }
}

/// Build the `replay` detail dict from envelope fields. Matches
/// Python's `tessera.audit_log.make_replay_detail`.
#[pyfunction]
#[pyo3(signature = (
    trajectory_id,
    tool_name,
    args_json,
    user_prompt=None,
    segments_json=None,
    sensitivity_hwm=None,
    decision_allowed=None,
    decision_source=None,
    decision_reason=None,
))]
fn make_replay_detail(
    py: Python<'_>,
    trajectory_id: &str,
    tool_name: &str,
    args_json: &str,
    user_prompt: Option<&str>,
    segments_json: Option<&str>,
    sensitivity_hwm: Option<&str>,
    decision_allowed: Option<bool>,
    decision_source: Option<&str>,
    decision_reason: Option<&str>,
) -> PyResult<PyObject> {
    let args: serde_json::Map<String, Value> = serde_json::from_str(args_json)
        .map_err(|e| PyValueError::new_err(format!("malformed args JSON: {e}")))?;
    let segments: Vec<Value> = match segments_json {
        Some(s) => serde_json::from_str(s)
            .map_err(|e| PyValueError::new_err(format!("malformed segments JSON: {e}")))?,
        None => Vec::new(),
    };
    let env = ReplayEnvelope {
        trajectory_id: trajectory_id.to_string(),
        tool_name: tool_name.to_string(),
        args,
        user_prompt: user_prompt.unwrap_or("").to_string(),
        segments,
        sensitivity_hwm: sensitivity_hwm.unwrap_or("PUBLIC").to_string(),
        decision_allowed: decision_allowed.unwrap_or(true),
        decision_source: decision_source.unwrap_or("").to_string(),
        decision_reason: decision_reason.unwrap_or("").to_string(),
    };
    let detail = env.to_detail(serde_json::Map::new());
    Ok(json_to_pyobject(py, &detail))
}

// ---- Context + labels ----------------------------------------------------

/// Context wrapper. Internal min_trust state is what drives
/// `Policy.evaluate`.
#[pyclass(name = "Context", module = "tessera_rs.context")]
struct PyContext {
    inner: CoreContext,
    signer: HmacSigner,
}

#[pymethods]
impl PyContext {
    #[new]
    #[pyo3(signature = (signing_key=None))]
    fn new(signing_key: Option<Vec<u8>>) -> Self {
        let key = signing_key.unwrap_or_else(|| b"\x00".repeat(32));
        Self {
            inner: CoreContext::new(),
            signer: HmacSigner::new(key),
        }
    }

    fn add_segment(
        &mut self,
        content: &str,
        origin: &str,
        principal: &str,
        trust_level: i64,
    ) -> PyResult<()> {
        let origin_enum = match origin.to_ascii_lowercase().as_str() {
            "user" => Origin::User,
            "system" => Origin::System,
            "tool" => Origin::Tool,
            "memory" => Origin::Memory,
            "web" => Origin::Web,
            other => return Err(PyValueError::new_err(format!("unknown origin: {other}"))),
        };
        let level = TrustLevel::from_int(trust_level)
            .ok_or_else(|| PyValueError::new_err(format!("invalid trust_level: {trust_level}")))?;
        let segment =
            core_make_segment(content, origin_enum, principal, &self.signer, Some(level));
        self.inner.add(segment);
        Ok(())
    }

    #[getter]
    fn min_trust(&self) -> i64 {
        self.inner.min_trust().as_int()
    }

    #[getter]
    fn segment_count(&self) -> usize {
        self.inner.len()
    }
}

// ---- Policy --------------------------------------------------------------

#[pyclass(name = "Policy", module = "tessera_rs.policy")]
struct PyPolicy {
    inner: PolicyImpl,
}

#[pymethods]
impl PyPolicy {
    #[new]
    fn new() -> Self {
        Self {
            inner: PolicyImpl::new(),
        }
    }

    fn require_tool(&mut self, name: &str, level: i64) -> PyResult<()> {
        let level = TrustLevel::from_int(level)
            .ok_or_else(|| PyValueError::new_err(format!("invalid trust_level: {level}")))?;
        self.inner.require(ResourceRequirement::new_tool(name, level));
        Ok(())
    }

    fn evaluate(&self, py: Python<'_>, context: &PyContext, tool_name: &str) -> PyObject {
        let decision = self.inner.evaluate(&context.inner, tool_name);
        decision_dict(py, &decision)
    }

    /// Evaluate with the optional CEL deny-rule layer.
    ///
    /// Mirrors `tessera.policy.Policy.evaluate(ctx, tool, args, ...)`.
    /// When no CEL engine is installed via `set_cel_engine`, this is
    /// equivalent to `evaluate(context, tool_name)`.
    #[pyo3(signature = (
        context,
        tool_name,
        args=None,
        principal="",
        delegation_subject=None,
        delegation_actions=None,
    ))]
    fn evaluate_with_cel(
        &self,
        py: Python<'_>,
        context: &PyContext,
        tool_name: &str,
        args: Option<HashMap<String, String>>,
        principal: &str,
        delegation_subject: Option<String>,
        delegation_actions: Option<Vec<String>>,
    ) -> PyObject {
        let args = args.unwrap_or_default();
        let actions = delegation_actions.unwrap_or_default();
        let decision = self.inner.evaluate_with_cel(
            &context.inner,
            tool_name,
            &args,
            principal,
            delegation_subject.as_deref(),
            &actions,
        );
        decision_dict(py, &decision)
    }

    /// Install a CEL deny-rule engine. Mirrors Python
    /// `Policy.cel_engine = engine`. Pass `None` to clear.
    #[pyo3(signature = (engine=None))]
    fn set_cel_engine(&mut self, engine: Option<&PyCelPolicyEngine>) {
        match engine {
            Some(e) => self.inner.set_cel_engine(e.inner.clone()),
            None => self.inner.clear_cel_engine(),
        }
    }
}

fn decision_dict(py: Python<'_>, decision: &tessera_policy::policy::Decision) -> PyObject {
    let dict = PyDict::new_bound(py);
    let _ = dict.set_item(
        "allowed",
        matches!(decision.kind, tessera_policy::DecisionKind::Allow),
    );
    let _ = dict.set_item(
        "kind",
        match decision.kind {
            tessera_policy::DecisionKind::Allow => "allow",
            tessera_policy::DecisionKind::Deny => "deny",
            tessera_policy::DecisionKind::RequireApproval => "require_approval",
        },
    );
    let _ = dict.set_item("reason", decision.reason.as_ref());
    let _ = dict.set_item("tool", &decision.tool);
    let _ = dict.set_item("required_trust", decision.required_trust.as_int());
    let _ = dict.set_item("observed_trust", decision.observed_trust.as_int());
    dict.into()
}

// ---- CEL deny rules ------------------------------------------------------

/// One CEL deny rule. Mirrors `tessera_policy::cel::CelRule`.
#[pyclass(name = "CelRule", module = "tessera_rs.cel")]
#[derive(Clone)]
struct PyCelRule {
    inner: CelRule,
}

#[pymethods]
impl PyCelRule {
    #[new]
    #[pyo3(signature = (name, expression, action, message))]
    fn new(name: &str, expression: &str, action: &str, message: &str) -> PyResult<Self> {
        let action = parse_cel_action(action)?;
        Ok(Self {
            inner: CelRule::new(name, expression, action, message),
        })
    }

    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }

    #[getter]
    fn expression(&self) -> &str {
        &self.inner.expression
    }

    #[getter]
    fn action(&self) -> &'static str {
        self.inner.action.as_str()
    }

    #[getter]
    fn message(&self) -> &str {
        &self.inner.message
    }

    fn __repr__(&self) -> String {
        format!(
            "CelRule(name={:?}, expression={:?}, action={:?}, message={:?})",
            self.inner.name, self.inner.expression, self.inner.action.as_str(),
            self.inner.message
        )
    }
}

fn parse_cel_action(s: &str) -> PyResult<CelAction> {
    match s.to_ascii_lowercase().as_str() {
        "deny" => Ok(CelAction::Deny),
        "require_approval" => Ok(CelAction::RequireApproval),
        other => Err(PyValueError::new_err(format!(
            "unknown CEL action {other:?}; expected \"deny\" or \"require_approval\""
        ))),
    }
}

/// CEL evaluator engine. Mirrors
/// `tessera_policy::cel::CelPolicyEngine`. Compiled once; evaluate
/// many.
#[pyclass(name = "CelPolicyEngine", module = "tessera_rs.cel")]
struct PyCelPolicyEngine {
    inner: std::sync::Arc<CelPolicyEngine>,
}

#[pymethods]
impl PyCelPolicyEngine {
    #[new]
    fn new(rules: Vec<PyCelRule>) -> PyResult<Self> {
        let engine = CelPolicyEngine::new(rules.into_iter().map(|r| r.inner))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner: std::sync::Arc::new(engine),
        })
    }

    fn rule_count(&self) -> usize {
        self.inner.rule_count()
    }

    /// Return the rules in registration order. AgentMesh
    /// (`proxy._policy.cel_engine._rules`) introspects this list to
    /// surface the active policy on `/v1/policy`.
    fn rules(&self) -> Vec<PyCelRule> {
        self.inner.rules().cloned().map(|r| PyCelRule { inner: r }).collect()
    }

    /// Evaluate against a context dict. Returns a dict
    /// `{rule_name, action, message}` when a rule fires, or `None`
    /// when no rule matches.
    #[pyo3(signature = (
        tool,
        principal,
        min_trust,
        segment_count,
        args=None,
        delegation_subject=None,
        delegation_actions=None,
    ))]
    fn evaluate(
        &self,
        py: Python<'_>,
        tool: &str,
        principal: &str,
        min_trust: i64,
        segment_count: i64,
        args: Option<HashMap<String, String>>,
        delegation_subject: Option<String>,
        delegation_actions: Option<Vec<String>>,
    ) -> PyObject {
        let ctx = CelContext {
            tool: tool.to_owned(),
            args: args.unwrap_or_default(),
            min_trust,
            principal: principal.to_owned(),
            segment_count,
            delegation_subject,
            delegation_actions: delegation_actions.unwrap_or_default(),
        };
        match self.inner.evaluate(&ctx) {
            Some(d) => decision_to_dict(py, &d).into(),
            None => py.None(),
        }
    }
}

fn decision_to_dict<'py>(py: Python<'py>, d: &CelDecision) -> Bound<'py, PyDict> {
    let dict = PyDict::new_bound(py);
    let _ = dict.set_item("rule_name", &d.rule_name);
    let _ = dict.set_item("action", d.action.as_str());
    let _ = dict.set_item("message", &d.message);
    dict
}

// ---- Rate limiter --------------------------------------------------------

/// Per-session tool-call rate limit. Mirrors
/// `tessera_policy::ratelimit::ToolCallRateLimit` and its Python
/// counterpart `tessera.ratelimit.ToolCallRateLimit`.
///
/// Three independent caps:
/// 1. Window rate: `max_calls` per rolling `window_seconds`.
/// 2. Burst: `burst_threshold` calls within `burst_window_seconds`
///    triggers a `cooldown_seconds` denial.
/// 3. Session lifetime: `session_lifetime_max` total calls
///    (omit / pass `None` to disable).
#[pyclass(name = "ToolCallRateLimit", module = "tessera_rs.ratelimit")]
struct PyToolCallRateLimit {
    inner: ToolCallRateLimit,
}

#[pymethods]
impl PyToolCallRateLimit {
    #[new]
    #[pyo3(signature = (
        max_calls=50,
        window_seconds=300.0,
        burst_threshold=10,
        burst_window_seconds=5.0,
        cooldown_seconds=30.0,
        session_lifetime_max=Some(500),
    ))]
    fn new(
        max_calls: usize,
        window_seconds: f64,
        burst_threshold: usize,
        burst_window_seconds: f64,
        cooldown_seconds: f64,
        session_lifetime_max: Option<usize>,
    ) -> Self {
        Self {
            inner: ToolCallRateLimit::new(
                max_calls,
                chrono::Duration::milliseconds((window_seconds * 1000.0) as i64),
                burst_threshold,
                chrono::Duration::milliseconds((burst_window_seconds * 1000.0) as i64),
                chrono::Duration::milliseconds((cooldown_seconds * 1000.0) as i64),
                session_lifetime_max,
            ),
        }
    }

    /// Check (and on success, record) a tool call. Returns
    /// `(allowed: bool, reason: str | None)`.
    #[pyo3(signature = (session_id, tool_name=""))]
    fn check(&self, session_id: &str, tool_name: &str) -> (bool, Option<String>) {
        self.inner.check(session_id, tool_name)
    }

    /// Convenience: returns just the allowed bool.
    #[pyo3(signature = (session_id, tool_name=""))]
    fn allow(&self, session_id: &str, tool_name: &str) -> bool {
        self.inner.allow(session_id, tool_name)
    }

    /// Current status as a dict
    /// `{session_id, calls_in_window, calls_remaining, max_calls,
    /// window_seconds, exceeded}`.
    fn status(&self, py: Python<'_>, session_id: &str) -> PyObject {
        rate_status_dict(py, &self.inner.status(session_id))
    }

    /// Drop call history. Pass `None` to reset every session.
    #[pyo3(signature = (session_id=None))]
    fn reset(&self, session_id: Option<&str>) {
        self.inner.reset(session_id)
    }

    fn total_calls(&self, session_id: &str) -> usize {
        self.inner.total_calls(session_id)
    }

    fn burst_alerts(&self, session_id: &str) -> usize {
        self.inner.burst_alerts(session_id)
    }
}

fn rate_status_dict<'py>(py: Python<'py>, s: &CallRateStatus) -> PyObject {
    let dict = PyDict::new_bound(py);
    let _ = dict.set_item("session_id", &s.session_id);
    let _ = dict.set_item("calls_in_window", s.calls_in_window);
    let _ = dict.set_item("calls_remaining", s.calls_remaining);
    let _ = dict.set_item("max_calls", s.max_calls);
    let _ = dict.set_item("window_seconds", s.window_seconds);
    let _ = dict.set_item("exceeded", s.exceeded);
    dict.into()
}

// ---- SSRF guard ----------------------------------------------------------

#[pyclass(name = "SsrfGuard", module = "tessera_rs.ssrf")]
struct PySsrfGuard {
    inner: SsrfGuardImpl,
}

#[pymethods]
impl PySsrfGuard {
    #[new]
    fn new() -> Self {
        Self {
            inner: SsrfGuardImpl::with_defaults(),
        }
    }

    fn check_url(&self, py: Python<'_>, url: &str) -> PyObject {
        let decision = self.inner.check_url(url);
        let dict = PyDict::new_bound(py);
        let _ = dict.set_item("allowed", decision.allowed);
        let _ = dict.set_item(
            "findings",
            decision
                .findings
                .iter()
                .map(|f| f.rule_id.clone())
                .collect::<Vec<_>>(),
        );
        dict.into()
    }
}

// ---- URL rules -----------------------------------------------------------

#[pyclass(name = "UrlRulesEngine", module = "tessera_rs.url_rules")]
struct PyUrlRulesEngine {
    inner: UrlRulesEngineImpl,
}

#[pymethods]
impl PyUrlRulesEngine {
    #[new]
    fn new() -> Self {
        Self {
            inner: UrlRulesEngineImpl::default(),
        }
    }

    /// Add a prefix-match rule. `action` is `"allow"` or `"deny"`.
    fn add_prefix(&mut self, name: &str, prefix: &str, action: &str) -> PyResult<()> {
        let action = match action.to_ascii_lowercase().as_str() {
            "allow" => RuleAction::Allow,
            "deny" => RuleAction::Deny,
            other => return Err(PyValueError::new_err(format!("unknown action: {other}"))),
        };
        self.inner.add(
            UrlRuleImpl::new(name, prefix)
                .kind(PatternKind::Prefix)
                .action(action),
        );
        Ok(())
    }

    fn evaluate(&self, py: Python<'_>, url: &str, method: &str) -> PyObject {
        let decision = self.inner.evaluate(url, method);
        let dict = PyDict::new_bound(py);
        let _ = dict.set_item(
            "verdict",
            match decision.verdict {
                tessera_policy::RuleVerdict::Allow => "allow",
                tessera_policy::RuleVerdict::Deny => "deny",
                tessera_policy::RuleVerdict::NoMatch => "no_match",
            },
        );
        let _ = dict.set_item("rule_id", decision.rule_id);
        let _ = dict.set_item("method", decision.method);
        let _ = dict.set_item("url", decision.url);
        dict.into()
    }
}

// ---- Scanners ------------------------------------------------------------

/// Heuristic injection score (0.0 to 1.0).
#[pyfunction]
fn injection_score(text: &str) -> f64 {
    heuristic_injection_score(text)
}

// ---- PyScanner callback bridge ------------------------------------------
//
// Tessera's "hard" scanners (PromptGuard, Perplexity, PDFInspector,
// ImageInspector, CodeShield) are not ported to Rust because they
// depend on Python ML / PIL / sandboxed-PDF stacks. Instead, this
// bridge lets a host process register a Python callable under a
// stable name, then invoke it from any consumer (the Rust gateway,
// AgentMesh, or another Python module) via `tessera_rs.scanners.scan`.
//
// The registered callable signature is `def scan(text: str) -> dict`
// where the dict contains at minimum `{detected: bool, score: float,
// reason: str}`. Additional fields are passed through unchanged so
// scanner-specific telemetry rides along without schema changes here.

static PY_SCANNER_REGISTRY: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, Py<PyAny>>>> =
    std::sync::OnceLock::new();

fn registry() -> &'static parking_lot::Mutex<HashMap<String, Py<PyAny>>> {
    PY_SCANNER_REGISTRY.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// Register a Python scanner under a stable name.
///
/// Once registered, callers (Rust gateway, AgentMesh, host Python)
/// invoke via `tessera_rs.scanners.scan(name, text)`. Replaces any
/// existing registration with the same name and logs a warning.
#[pyfunction]
fn register_scanner(_py: Python<'_>, name: &str, callable: Py<PyAny>) -> PyResult<()> {
    let mut g = registry().lock();
    if g.insert(name.to_owned(), callable).is_some() {
        eprintln!(
            "[tessera_rs.scanners] register_scanner: overwrote previous \
             registration for {name:?}"
        );
    }
    Ok(())
}

/// Drop a registered scanner. Returns True if a registration was
/// removed, False if the name was not registered.
#[pyfunction]
fn unregister_scanner(name: &str) -> bool {
    registry().lock().remove(name).is_some()
}

/// List all registered scanner names. Useful for ops/health checks.
#[pyfunction]
fn registered_scanners() -> Vec<String> {
    let g = registry().lock();
    let mut names: Vec<String> = g.keys().cloned().collect();
    names.sort();
    names
}

/// Invoke a registered scanner. Returns the dict the Python callable
/// returned. Raises ValueError when no scanner is registered under
/// `name`, or when the callable raises.
#[pyfunction]
fn scan(py: Python<'_>, name: &str, text: &str) -> PyResult<PyObject> {
    let callable = {
        let g = registry().lock();
        match g.get(name) {
            Some(c) => c.clone_ref(py),
            None => {
                return Err(PyValueError::new_err(format!(
                    "no scanner registered under {name:?}; \
                     call register_scanner({name:?}, ...) first"
                )));
            }
        }
    };
    let result = callable.call1(py, (text,))?;
    Ok(result)
}

/// Hidden Unicode tag scanner. Returns a dict
/// `{detected: bool, hidden_payload: str, tag_count: int, positions: [int]}`.
#[pyfunction]
fn scan_unicode_tags(py: Python<'_>, text: &str) -> PyObject {
    let r = unicode_scan_tags(text);
    let dict = PyDict::new_bound(py);
    let _ = dict.set_item("detected", r.detected);
    let _ = dict.set_item("hidden_payload", r.hidden_payload);
    let _ = dict.set_item("tag_count", r.tag_count);
    let _ = dict.set_item("positions", r.positions);
    dict.into()
}

// ---- Module wiring -------------------------------------------------------

#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let _ = py;
    // Top-level functions live on the native module; the Python
    // shim re-exports them under `tessera_rs.<submodule>`.
    m.add_function(wrap_pyfunction!(audit_canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(make_replay_detail, m)?)?;
    m.add_function(wrap_pyfunction!(injection_score, m)?)?;
    m.add_function(wrap_pyfunction!(scan_unicode_tags, m)?)?;
    m.add_function(wrap_pyfunction!(register_scanner, m)?)?;
    m.add_function(wrap_pyfunction!(unregister_scanner, m)?)?;
    m.add_function(wrap_pyfunction!(registered_scanners, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_class::<PyJsonlHashchainSink>()?;
    m.add_class::<PyContext>()?;
    m.add_class::<PyPolicy>()?;
    m.add_class::<PyCelRule>()?;
    m.add_class::<PyCelPolicyEngine>()?;
    m.add_class::<PyToolCallRateLimit>()?;
    m.add_class::<PySsrfGuard>()?;
    m.add_class::<PyUrlRulesEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
