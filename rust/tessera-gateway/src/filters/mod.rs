//! Composable filter pipeline for the Tessera gateway.
//!
//! Modeled on agentgateway's filter architecture. Each filter can
//! inspect and modify the request context, or short-circuit with
//! a direct response.

use async_trait::async_trait;
use axum::response::Response;
use std::sync::Arc;

pub mod identity_verification;
pub mod label_verification;
pub mod policy_evaluation;
pub mod upstream;

use crate::{
    AppState, ChatRequest, DelegationHeaderModel, GatewayConfig, RuntimeControlState,
    TransportPeerIdentity, VerifiedIdentity,
};

/// Context shared across all filters in the pipeline for one request.
pub struct RequestContext {
    pub request: ChatRequest,
    pub state: AppState,
    pub headers: axum::http::HeaderMap,
    pub method: axum::http::Method,
    pub uri: axum::http::Uri,
    pub immediate_client_host: Option<String>,
    pub transport_identity: Option<TransportPeerIdentity>,
    pub transport_error: Option<String>,
    pub verified_identity: Option<VerifiedIdentity>,
    pub peer_identity: Option<TransportPeerIdentity>,
    pub delegation: Option<DelegationHeaderModel>,
    pub provenance_verified: bool,
    pub runtime: Option<RuntimeControlState>,
    pub rendered_messages: Vec<serde_json::Value>,
    pub upstream_payload: Option<serde_json::Value>,
}

/// Result of a filter execution.
pub enum FilterResult {
    /// Continue to the next filter.
    Continue,
    /// Short-circuit the pipeline with a direct response.
    ShortCircuit(Response),
}

/// A composable request/response filter.
#[async_trait]
pub trait Filter: Send + Sync {
    /// Process the inbound request. Return Continue to pass to next
    /// filter, or ShortCircuit to respond immediately.
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult;

    /// Process the outbound response. Default is passthrough.
    async fn on_response(
        &self,
        ctx: &mut RequestContext,
        response: &mut serde_json::Value,
    ) -> FilterResult {
        let _ = ctx;
        let _ = response;
        FilterResult::Continue
    }
}

/// Ordered list of filters executed in sequence.
pub struct FilterChain {
    filters: Vec<Box<dyn Filter>>,
}

impl FilterChain {
    pub fn new(filters: Vec<Box<dyn Filter>>) -> Self {
        Self { filters }
    }

    pub async fn execute_request(&self, ctx: &mut RequestContext) -> Option<Response> {
        for filter in &self.filters {
            match filter.on_request(ctx).await {
                FilterResult::Continue => continue,
                FilterResult::ShortCircuit(response) => return Some(response),
            }
        }
        None
    }

    pub async fn execute_response(
        &self,
        ctx: &mut RequestContext,
        response: &mut serde_json::Value,
    ) {
        for filter in &self.filters {
            if let FilterResult::ShortCircuit(_) = filter.on_response(ctx, response).await {
                break;
            }
        }
    }
}
