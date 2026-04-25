//! MCP behavioral drift scanner plugin shaped for upstream
//! agentgateway. In-tree under the Tessera repo until the upstream
//! PR to ``solo-io/agentgateway`` merges.
//!
//! Mirrors :class:`tessera.mcp.drift.DriftMonitor` from the Python
//! tree: tracks response shape stability and latency p99 across a
//! rolling window per upstream MCP server.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// One observed response sample.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Hash of the sorted top-level JSON keys present in the
    /// response. Stable across orderings; mutates when the shape
    /// changes.
    pub key_set_hash: [u8; 32],
    /// Wire latency in microseconds.
    pub latency_us: u64,
}

/// Drift alert kind. Mirrors the Python event kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftAlert {
    /// Response key-set changed from the established baseline.
    Shape,
    /// p99 latency jumped > 50% from the rolling baseline p99.
    Latency,
}

/// Drift scanner instance. One per upstream MCP server.
#[derive(Debug)]
pub struct DriftScanner {
    window: VecDeque<Observation>,
    capacity: usize,
    baseline_key_set: Option<[u8; 32]>,
    baseline_p99_us: Option<u64>,
}

impl Default for DriftScanner {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl DriftScanner {
    /// Build a scanner with a rolling window of ``capacity``
    /// observations.
    pub fn new(capacity: usize) -> Self {
        Self {
            window: VecDeque::with_capacity(capacity),
            capacity: capacity.max(8),
            baseline_key_set: None,
            baseline_p99_us: None,
        }
    }

    /// Record one response observation.
    pub fn observe(&mut self, obs: Observation) {
        if self.window.len() == self.capacity {
            self.window.pop_front();
        }
        if self.baseline_key_set.is_none() {
            self.baseline_key_set = Some(obs.key_set_hash);
        }
        self.window.push_back(obs);
        // Establish baseline p99 once we have 16 samples.
        if self.baseline_p99_us.is_none() && self.window.len() >= 16 {
            self.baseline_p99_us = Some(self.compute_p99());
        }
    }

    /// Check the current window for drift; return the first alert
    /// found (Shape preferred over Latency when both apply).
    pub fn check(&self) -> Option<DriftAlert> {
        if let Some(latest) = self.window.back() {
            if let Some(baseline) = self.baseline_key_set {
                if latest.key_set_hash != baseline {
                    return Some(DriftAlert::Shape);
                }
            }
        }
        if let Some(baseline_p99) = self.baseline_p99_us {
            let current_p99 = self.compute_p99();
            if current_p99 > baseline_p99 * 3 / 2 {
                return Some(DriftAlert::Latency);
            }
        }
        None
    }

    fn compute_p99(&self) -> u64 {
        if self.window.is_empty() {
            return 0;
        }
        let mut latencies: Vec<u64> =
            self.window.iter().map(|o| o.latency_us).collect();
        latencies.sort_unstable();
        let idx = ((latencies.len() as f64) * 0.99).floor() as usize;
        latencies[idx.min(latencies.len() - 1)]
    }
}

/// Hash a sorted set of top-level JSON keys to produce a stable
/// shape fingerprint.
pub fn shape_hash(keys: &[String]) -> [u8; 32] {
    let mut sorted: Vec<&str> = keys.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    for k in sorted {
        hasher.update(k.as_bytes());
        hasher.update(b"\x00");
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(keys: &[&str], latency: u64) -> Observation {
        Observation {
            key_set_hash: shape_hash(
                &keys.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            ),
            latency_us: latency,
        }
    }

    #[test]
    fn clean_stream_no_alert() {
        let mut s = DriftScanner::new(64);
        for _ in 0..32 {
            s.observe(obs(&["a", "b", "c"], 1000));
        }
        assert!(s.check().is_none());
    }

    #[test]
    fn shape_change_emits_shape_alert() {
        let mut s = DriftScanner::new(64);
        for _ in 0..16 {
            s.observe(obs(&["a", "b", "c"], 1000));
        }
        s.observe(obs(&["a", "b", "c", "d"], 1000));
        assert_eq!(s.check(), Some(DriftAlert::Shape));
    }

    #[test]
    fn latency_jump_emits_latency_alert() {
        let mut s = DriftScanner::new(64);
        for _ in 0..32 {
            s.observe(obs(&["a", "b"], 1000));
        }
        for _ in 0..32 {
            s.observe(obs(&["a", "b"], 5000));
        }
        assert_eq!(s.check(), Some(DriftAlert::Latency));
    }
}
