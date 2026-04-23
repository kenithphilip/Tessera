//! `POST /v1/label` workload. Adds a tool output to a session
//! context.

use async_trait::async_trait;
use reqwest::Client;

use super::{build_client, label_body, Workload};

pub struct LabelWorkload {
    client: Client,
    tool: String,
    session_id: String,
    text_template: String,
}

impl LabelWorkload {
    pub fn new() -> Self {
        Self {
            client: build_client(),
            tool: "fetch_url".to_string(),
            session_id: "bench-session".to_string(),
            text_template: "search result for query".to_string(),
        }
    }
}

impl Default for LabelWorkload {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Workload for LabelWorkload {
    fn name(&self) -> &'static str {
        "label"
    }

    async fn execute(&self, target: &str) -> Result<(), String> {
        let url = format!("{target}/v1/label");
        let resp = self
            .client
            .post(&url)
            .json(&label_body(&self.text_template, &self.tool, &self.session_id))
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
