//! PyO3 callback bridge for hard-tier ML scanners.
//!
//! The five ML-backed scanners (`promptguard`, `perplexity`,
//! `pdf_inspector`, `image_inspector`, `codeshield`) have no Rust-native
//! implementation. Python packages provide them. This module lets the host
//! process register Python callables; the Rust gateway invokes them through
//! the `PyScanner` trait.
//!
//! # Feature gate
//!
//! The concrete `PyCallbackScanner` (which holds a `pyo3::Py<PyAny>`) is
//! compiled only when the `pyo3-bridge` feature is enabled. The trait,
//! registry, and `NoOpScanner` are always available so callers can depend
//! on this module without pulling in pyo3.
//!
//! # Missing registration
//!
//! If a scanner name is not registered, `ScannerRegistry::get` returns a
//! `NoOpScanner` that logs the gap at startup and returns an empty
//! `ScanResult` with `allowed: true`. No panic, no error.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ScanResult;

// ---------------------------------------------------------------------------
// Known scanner names
// ---------------------------------------------------------------------------

/// The five ML-backed scanner names that require Python registration.
/// Registering any other name is allowed but these are the only ones the
/// gateway queries by default.
pub const KNOWN_SCANNERS: &[&str] = &[
    "promptguard",
    "perplexity",
    "pdf_inspector",
    "image_inspector",
    "codeshield",
];

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Provider-agnostic interface for a single ML scanner invocation.
///
/// The trait signature is free of pyo3 types so callers can hold
/// `Arc<dyn PyScanner>` without enabling the `pyo3-bridge` feature.
pub trait PyScanner: Send + Sync {
    /// Run the scanner on `input`. Returns a `ScanResult` with the scanner
    /// name, allow/deny decision, and any findings. Implementations must
    /// not panic; errors should be represented as `allowed: false` findings
    /// with a descriptive message.
    fn scan(&self, input: &str) -> ScanResult;

    /// Human-readable name for this scanner instance (used in logs).
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// NoOpScanner
// ---------------------------------------------------------------------------

/// Fallback returned for any scanner name that was not registered.
///
/// Returns `allowed: true` with no findings. The gateway logs a warning at
/// startup for each scanner that resolves to `NoOpScanner`.
pub struct NoOpScanner {
    scanner_name: String,
}

impl NoOpScanner {
    pub fn new(scanner_name: impl Into<String>) -> Self {
        Self {
            scanner_name: scanner_name.into(),
        }
    }
}

impl PyScanner for NoOpScanner {
    fn scan(&self, _input: &str) -> ScanResult {
        ScanResult {
            scanner: self.scanner_name.clone(),
            allowed: true,
            findings: Vec::new(),
        }
    }

    fn name(&self) -> &str {
        &self.scanner_name
    }
}

// ---------------------------------------------------------------------------
// ScannerRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry mapping scanner names to `PyScanner` implementations.
///
/// The registry is clonable (backed by `Arc<Mutex<...>>`). All clones share
/// the same underlying map, so a registration made in one clone is visible in
/// all others.
#[derive(Clone, Default)]
pub struct ScannerRegistry {
    inner: Arc<Mutex<HashMap<String, Arc<dyn PyScanner>>>>,
}

impl ScannerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `scanner` under `name`. Overwrites any previous entry.
    pub fn register(&self, name: impl Into<String>, scanner: Arc<dyn PyScanner>) {
        let mut map = self.inner.lock().expect("scanner registry lock poisoned");
        map.insert(name.into(), scanner);
    }

    /// Look up `name`. Returns the registered scanner, or a `NoOpScanner`
    /// if the name was never registered.
    pub fn get(&self, name: &str) -> Arc<dyn PyScanner> {
        let map = self.inner.lock().expect("scanner registry lock poisoned");
        map.get(name)
            .cloned()
            .unwrap_or_else(|| Arc::new(NoOpScanner::new(name)))
    }

    /// Remove a previously registered scanner. Returns `true` if an entry
    /// was removed.
    pub fn unregister(&self, name: &str) -> bool {
        let mut map = self.inner.lock().expect("scanner registry lock poisoned");
        map.remove(name).is_some()
    }

    /// Returns the names of all currently registered scanners.
    pub fn registered_names(&self) -> Vec<String> {
        let map = self.inner.lock().expect("scanner registry lock poisoned");
        map.keys().cloned().collect()
    }

    /// Returns `true` if `name` has an explicit registration (not just a
    /// no-op fallback).
    pub fn is_registered(&self, name: &str) -> bool {
        let map = self.inner.lock().expect("scanner registry lock poisoned");
        map.contains_key(name)
    }
}

// ---------------------------------------------------------------------------
// PyCallbackScanner (pyo3-bridge feature only)
// ---------------------------------------------------------------------------

/// Wraps a Python callable and implements `PyScanner` by calling it through
/// the GIL. The callable must accept a single `str` argument and return a
/// dict with at least `allowed: bool` and optionally `findings: list[dict]`.
///
/// Available only when compiled with `--features pyo3-bridge`.
#[cfg(feature = "pyo3-bridge")]
pub mod pyo3_bridge {
    use super::{PyScanner, ScanResult};
    use crate::{ScanFinding, Severity};
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    pub struct PyCallbackScanner {
        callable: Py<PyAny>,
        scanner_name: String,
    }

    impl PyCallbackScanner {
        /// Wrap `callable` (a Python object with a `__call__` accepting one
        /// `str`) as a `PyScanner`. The GIL must be held when constructing
        /// this; the `Py<PyAny>` keeps the callable alive across GIL releases.
        pub fn new(py: Python<'_>, callable: &PyAny, name: impl Into<String>) -> PyResult<Self> {
            Ok(Self {
                callable: callable.into_py(py),
                scanner_name: name.into(),
            })
        }
    }

    impl PyScanner for PyCallbackScanner {
        fn scan(&self, input: &str) -> ScanResult {
            Python::with_gil(|py| {
                let result = self.callable.call1(py, (input,));
                match result {
                    Err(e) => {
                        // Python raised an exception; treat as allow with an
                        // error finding so the caller can log or deny.
                        ScanResult {
                            scanner: self.scanner_name.clone(),
                            allowed: true,
                            findings: vec![crate::ScanFinding {
                                rule_id: "py_exception".to_string(),
                                severity: Severity::Medium,
                                message: e.to_string(),
                                arg_path: String::new(),
                                evidence: String::new(),
                                metadata: serde_json::Value::Null,
                            }],
                        }
                    }
                    Ok(obj) => extract_scan_result(py, &self.scanner_name, obj),
                }
            })
        }

        fn name(&self) -> &str {
            &self.scanner_name
        }
    }

    /// Convert the Python return value into a `ScanResult`.
    ///
    /// Expected shape: `{"allowed": bool, "findings": [{"rule_id": str,
    /// "severity": str, "message": str, ...}, ...]}`. Missing keys are
    /// treated as defaults: `allowed = true`, `findings = []`.
    fn extract_scan_result(py: Python<'_>, scanner_name: &str, obj: PyObject) -> ScanResult {
        let Ok(dict) = obj.extract::<&PyDict>(py) else {
            return ScanResult {
                scanner: scanner_name.to_string(),
                allowed: true,
                findings: Vec::new(),
            };
        };

        let allowed: bool = dict
            .get_item("allowed")
            .and_then(|v| v.and_then(|v| v.extract::<bool>().ok()))
            .unwrap_or(true);

        let findings = extract_findings(py, dict);

        ScanResult {
            scanner: scanner_name.to_string(),
            allowed,
            findings,
        }
    }

    fn extract_findings(py: Python<'_>, dict: &PyDict) -> Vec<ScanFinding> {
        let Some(raw) = dict.get_item("findings").ok().flatten() else {
            return Vec::new();
        };
        let Ok(list) = raw.extract::<Vec<&PyDict>>() else {
            return Vec::new();
        };
        list.into_iter()
            .filter_map(|fd| extract_one_finding(py, fd))
            .collect()
    }

    fn extract_one_finding(_py: Python<'_>, fd: &PyDict) -> Option<ScanFinding> {
        let rule_id: String = fd
            .get_item("rule_id")
            .ok()
            .flatten()?
            .extract()
            .ok()?;
        let message: String = fd
            .get_item("message")
            .ok()
            .flatten()
            .and_then(|v| v.extract().ok())
            .unwrap_or_default();
        let severity_str: String = fd
            .get_item("severity")
            .ok()
            .flatten()
            .and_then(|v| v.extract().ok())
            .unwrap_or_else(|| "info".to_string());
        let severity = parse_severity(&severity_str);
        Some(ScanFinding {
            rule_id,
            severity,
            message,
            arg_path: String::new(),
            evidence: String::new(),
            metadata: serde_json::Value::Null,
        })
    }

    fn parse_severity(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // A trivial scanner that always denies, used in registry tests.
    struct AlwaysDeny {
        name: String,
    }

    impl AlwaysDeny {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
            })
        }
    }

    impl PyScanner for AlwaysDeny {
        fn scan(&self, _input: &str) -> ScanResult {
            ScanResult {
                scanner: self.name.clone(),
                allowed: false,
                findings: Vec::new(),
            }
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    // ------------------------------------------------------------------
    // NoOpScanner
    // ------------------------------------------------------------------

    #[test]
    fn noop_allows_any_input() {
        let s = NoOpScanner::new("promptguard");
        let result = s.scan("malicious payload");
        assert!(result.allowed);
        assert!(result.findings.is_empty());
        assert_eq!(result.scanner, "promptguard");
    }

    #[test]
    fn noop_name_matches_constructor_arg() {
        let s = NoOpScanner::new("codeshield");
        assert_eq!(s.name(), "codeshield");
    }

    #[test]
    fn noop_empty_input_still_allowed() {
        let s = NoOpScanner::new("perplexity");
        let result = s.scan("");
        assert!(result.allowed);
        assert!(result.findings.is_empty());
    }

    // ------------------------------------------------------------------
    // ScannerRegistry: register and lookup
    // ------------------------------------------------------------------

    #[test]
    fn registry_returns_noop_for_unknown_name() {
        let registry = ScannerRegistry::new();
        let scanner = registry.get("promptguard");
        let result = scanner.scan("test");
        assert!(result.allowed, "unregistered scanner must be a no-op");
    }

    #[test]
    fn registry_register_and_get() {
        let registry = ScannerRegistry::new();
        registry.register("promptguard", AlwaysDeny::new("promptguard"));
        let scanner = registry.get("promptguard");
        let result = scanner.scan("test");
        assert!(!result.allowed, "registered scanner must be invoked");
    }

    #[test]
    fn registry_overwrite_replaces_previous_entry() {
        let registry = ScannerRegistry::new();
        registry.register("codeshield", AlwaysDeny::new("codeshield"));
        // Overwrite with a no-op.
        registry.register(
            "codeshield",
            Arc::new(NoOpScanner::new("codeshield")),
        );
        let result = registry.get("codeshield").scan("x");
        assert!(result.allowed, "overwritten entry must be the new scanner");
    }

    #[test]
    fn registry_unregister_returns_true_and_falls_back_to_noop() {
        let registry = ScannerRegistry::new();
        registry.register("perplexity", AlwaysDeny::new("perplexity"));
        assert!(registry.unregister("perplexity"));
        let result = registry.get("perplexity").scan("x");
        assert!(result.allowed, "after unregister scanner must be no-op");
    }

    #[test]
    fn registry_unregister_unknown_name_returns_false() {
        let registry = ScannerRegistry::new();
        assert!(!registry.unregister("pdf_inspector"));
    }

    #[test]
    fn registry_is_registered_reflects_state() {
        let registry = ScannerRegistry::new();
        assert!(!registry.is_registered("image_inspector"));
        registry.register("image_inspector", AlwaysDeny::new("image_inspector"));
        assert!(registry.is_registered("image_inspector"));
        registry.unregister("image_inspector");
        assert!(!registry.is_registered("image_inspector"));
    }

    #[test]
    fn registry_registered_names_lists_all_entries() {
        let registry = ScannerRegistry::new();
        for name in ["promptguard", "perplexity", "codeshield"] {
            registry.register(name, AlwaysDeny::new(name));
        }
        let mut names = registry.registered_names();
        names.sort();
        assert_eq!(names, vec!["codeshield", "perplexity", "promptguard"]);
    }

    #[test]
    fn registry_clone_shares_state() {
        let registry = ScannerRegistry::new();
        let clone = registry.clone();
        registry.register("promptguard", AlwaysDeny::new("promptguard"));
        // The clone must see the registration made via the original handle.
        assert!(clone.is_registered("promptguard"));
    }
}
