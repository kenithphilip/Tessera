//! Long-duration soak workload. Identical wire shape to the mixed
//! workload but exists as a separate name so the runner reports it
//! distinctly. Use for end-to-end checks (no FD leaks, no memory
//! growth, audit log keeps draining).

use async_trait::async_trait;

use super::{mixed::MixedWorkload, Workload};

pub struct SustainedWorkload {
    inner: MixedWorkload,
}

impl SustainedWorkload {
    pub fn new() -> Self {
        Self {
            inner: MixedWorkload::new(),
        }
    }
}

impl Default for SustainedWorkload {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Workload for SustainedWorkload {
    fn name(&self) -> &'static str {
        "sustained"
    }

    async fn execute(&self, target: &str) -> Result<(), String> {
        self.inner.execute(target).await
    }
}
