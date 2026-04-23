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

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

use tessera_audit::{canonical_json, AppendEntry, JsonlHashchainSink, ReplayEnvelope};
use tessera_core::context::{make_segment as core_make_segment, Context as CoreContext};
use tessera_core::labels::{HmacSigner, Origin, TrustLevel};
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
}

/// Build the `replay` detail dict from envelope fields. Matches
/// Python's `tessera.audit_log.make_replay_detail`.
#[pyfunction]
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
        let dict = PyDict::new_bound(py);
        let _ = dict.set_item("allowed", matches!(decision.kind, tessera_policy::DecisionKind::Allow));
        let _ = dict.set_item("reason", &decision.reason);
        let _ = dict.set_item("tool", &decision.tool);
        let _ = dict.set_item("required_trust", decision.required_trust.as_int());
        let _ = dict.set_item("observed_trust", decision.observed_trust.as_int());
        dict.into()
    }
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
    m.add_class::<PyJsonlHashchainSink>()?;
    m.add_class::<PyContext>()?;
    m.add_class::<PyPolicy>()?;
    m.add_class::<PySsrfGuard>()?;
    m.add_class::<PyUrlRulesEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
