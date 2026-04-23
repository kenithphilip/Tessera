//! `POST /v1/evaluate` workload. Hits the headline taint-tracking
//! policy decision.

use async_trait::async_trait;
use reqwest::Client;

use super::{build_client, evaluate_body, Workload};

pub struct EvaluateWorkload {
    client: Client,
    tool: String,
    session_id: String,
}

impl EvaluateWorkload {
    pub fn new() -> Self {
        Self {
            client: build_client(),
            tool: "send_email".to_string(),
            session_id: "bench-session".to_string(),
        }
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = tool.into();
        self
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }
}

impl Default for EvaluateWorkload {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Workload for EvaluateWorkload {
    fn name(&self) -> &'static str {
        "evaluate"
    }

    async fn execute(&self, target: &str) -> Result<(), String> {
        let url = format!("{target}/v1/evaluate");
        let resp = self
            .client
            .post(&url)
            .json(&evaluate_body(&self.tool, &self.session_id))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("status {}", resp.status()));
        }
        // Drain the body so connection pooling reuses the socket.
        let _ = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
