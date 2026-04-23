# tessera-scanners

Content-aware scanners. 13 scanners total: 9 trivial, 4 moderate,
plus a PyO3 callback bridge for the 5 ML scanners that the wheel
deliberately does not reimplement in Rust.

## What lives here

Trivial tier (Phase 2):

- `unicode`: hidden Unicode tag block (U+E0000..U+E007F)
  detection.
- `tool_shadow`: cross-server tool-name confusion via Levenshtein
  distance.
- `directive`: imperative-mood prompt-injection patterns
  (13 regex rules).
- `heuristic`: Aho-Corasick + RegexSet, cartesian-product injection
  scoring.
- `intent`: regex + cross-check against the user's prompt.
- `tool_descriptions`: malicious-pattern scanning of MCP tool
  descriptions.
- `tool_output_schema`: glob-based tool output schema enforcement.
- `prompt_screen`: composes heuristic + directive + unicode.
- `canary`: HMAC-bound canary tokens. Wire-format interop with
  Python.

Moderate tier (Phase 3):

- `pii`: regex-based PII detector. (Presidio backend deferred.)
- `binary_content`: magic-byte + 9 threat-category detection.
- `rag`: RAG retrieval guard, pattern tracker, embedding anomaly
  checker (anomaly path documented as gap, ships without baseline
  stats).
- `supply_chain`: typosquat + confusables + lockfile + install
  patterns. 25 tests.

Hard tier (Phase 4, callback only):

- `py_callback`: `PyScanner` trait + `ScannerRegistry` +
  `NoOpScanner`. The Rust crate does NOT ship implementations of
  `promptguard`, `perplexity`, `pdf_inspector`,
  `image_inspector`, or `codeshield`. Operators register Python
  implementations from a host process via the optional
  `pyo3-bridge` feature.

## Shared types

`Severity`, `ScanFinding`, `ScanResult`, `combine`,
`severity_rank`, `ScannerResult` (marker trait) live at the crate
root. Structured scanners (supply_chain, codeshield) emit
`ScanResult`; lightweight scanners emit module-specific result
types.

## Cross-language interop

Canary tokens have format-compatibility tests against Python at
`crates/tessera-scanners/tests/python_canary_interop.rs`.

## Tests

266 unit tests + 4 canary interop tests.

## Feature flags

- `pyo3-bridge`: compiles the `PyCallbackScanner` adapter that
  wraps a `pyo3::Py<PyAny>` callable. Off by default so plain
  `cargo build` does not require the Python toolchain. Enable
  with `--features pyo3-bridge`.
