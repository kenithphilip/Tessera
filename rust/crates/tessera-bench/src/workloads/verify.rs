//! `GET /v1/audit/verify` workload. Walks the JSONL hash chain.

use async_trait::async_trait;
use reqwest::Client;

use super::{build_client, Workload};

pub struct AuditVerifyWorkload {
    client: Client,
}

impl AuditVerifyWorkload {
    pub fn new() -> Self {
        Self {
            client: build_client(),
        }
    }
}

impl Default for AuditVerifyWorkload {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Workload for AuditVerifyWorkload {
    fn name(&self) -> &'static str {
        "audit-verify"
    }

    async fn execute(&self, target: &str) -> Result<(), String> {
        let url = format!("{target}/v1/audit/verify");
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        let _ = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
