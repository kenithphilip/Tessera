//! Mixed workload: 60% evaluate, 30% label, 10% audit-verify.
//! Picks one of the three on each call by hashing an atomic counter
//! to a deterministic distribution. Avoids per-call RNG cost.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use super::{evaluate::EvaluateWorkload, label::LabelWorkload, verify::AuditVerifyWorkload, Workload};

pub struct MixedWorkload {
    counter: AtomicU64,
    evaluate: EvaluateWorkload,
    label: LabelWorkload,
    verify: AuditVerifyWorkload,
}

impl MixedWorkload {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            evaluate: EvaluateWorkload::new(),
            label: LabelWorkload::new(),
            verify: AuditVerifyWorkload::new(),
        }
    }
}

impl Default for MixedWorkload {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Workload for MixedWorkload {
    fn name(&self) -> &'static str {
        "mixed"
    }

    async fn execute(&self, target: &str) -> Result<(), String> {
        // Modulo 10 across the counter: 0..5 evaluate, 6..8 label,
        // 9 verify. Deterministic distribution at the cost of one
        // atomic increment per call.
        let n = self.counter.fetch_add(1, Ordering::Relaxed) % 10;
        match n {
            0..=5 => self.evaluate.execute(target).await,
            6..=8 => self.label.execute(target).await,
            _ => self.verify.execute(target).await,
        }
    }
}
