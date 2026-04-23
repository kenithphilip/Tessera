//! Tessera scanners (Phase 2).
//!
//! Each module mirrors a `tessera.scanners.*` module from the Python
//! reference. Wire formats (canary tokens) match Python byte-for-byte
//! so a scanner result produced by Rust verifies in Python and vice
//! versa.
//!
//! Scanners are independent functions, not methods on a trait: the
//! input shape varies (string, JSON value, tool list, ...) and a
//! single trait would not pay for itself in Rust the way the Python
//! Protocol does. The `Scanner` marker trait below exists for the
//! few callers that want to hold a heterogeneous list of scanners,
//! but most code calls `scan_*` functions directly.
//!
//! Phase 2 deliverables in this crate:
//! - `unicode`: hidden Unicode tag block (U+E0000..U+E007F) detection
//! - `tool_shadow`: Levenshtein-based confusable tool-name detection
//! - `directive`: imperative-mood prompt-injection patterns
//! - `heuristic`: cartesian-product injection scoring
//! - `intent`: cross-checked intent vs user prompt
//! - `tool_descriptions`: malicious-pattern scanning of MCP tool descriptions
//! - `tool_output_schema`: glob-based tool output schema enforcement
//! - `prompt_screen`: composes heuristic + directive + unicode
//! - `canary`: HMAC-bound canary tokens (cross-language interop)

pub mod canary;
pub mod directive;
pub mod heuristic;
pub mod intent;
pub mod prompt_screen;
pub mod tool_descriptions;
pub mod tool_output_schema;
pub mod tool_shadow;
pub mod unicode;

/// Marker trait for scanner result types. Implementations carry the
/// detection flag and a scanner-specific detail payload via
/// `serde::Serialize` so callers can ship the result to a SIEM or
/// SecurityEvent without knowing the concrete type.
pub trait ScannerResult: serde::Serialize {
    fn detected(&self) -> bool;
    fn scanner_name(&self) -> &'static str;
}
