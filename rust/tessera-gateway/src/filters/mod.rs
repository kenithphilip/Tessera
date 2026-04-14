//! Composable filter pipeline for the Tessera gateway.
//!
//! Modeled on agentgateway's filter architecture. Each filter can
//! inspect and modify the request context, or short-circuit with
//! a direct response.

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub mod a2a;
pub mod identity_verification;
pub mod label_verification;
pub mod policy_evaluation;
pub mod upstream;

use crate::{
    AppState, ChatRequest, DelegationHeaderModel, RuntimeControlState, TransportPeerIdentity,
    VerifiedIdentity,
};

/// Context shared across all filters in the pipeline for one request.
pub(crate) struct RequestContext {
    pub(crate) request: ChatRequest,
    pub(crate) state: AppState,
    pub(crate) headers: axum::http::HeaderMap,
    pub(crate) method: axum::http::Method,
    pub(crate) uri: axum::http::Uri,
    pub(crate) immediate_client_host: Option<String>,
    pub(crate) transport_identity: Option<TransportPeerIdentity>,
    pub(crate) transport_error: Option<String>,
    pub(crate) verified_identity: Option<VerifiedIdentity>,
    pub(crate) peer_identity: Option<TransportPeerIdentity>,
    pub(crate) delegation: Option<DelegationHeaderModel>,
    pub(crate) provenance_verified: bool,
    pub(crate) runtime: Option<RuntimeControlState>,
    pub(crate) rendered_messages: Vec<serde_json::Value>,
    pub(crate) upstream_payload: Option<serde_json::Value>,
}

/// Result of a filter execution.
pub(crate) enum FilterResult {
    /// Continue to the next filter.
    Continue,
    /// Short-circuit the pipeline with a direct response.
    ShortCircuit(Response),
}

/// A composable request/response filter.
#[async_trait]
pub(crate) trait Filter: Send + Sync {
    /// Process the inbound request. Return Continue to pass to next
    /// filter, or ShortCircuit to respond immediately.
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult;

    /// Process the outbound response. Default is passthrough.
    #[allow(dead_code)]
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
pub(crate) struct FilterChain {
    filters: Vec<Box<dyn Filter>>,
}

impl FilterChain {
    pub(crate) fn new(filters: Vec<Box<dyn Filter>>) -> Self {
        Self { filters }
    }

    /// Execute all filters on the inbound request and return a response.
    ///
    /// Each filter either continues to the next or short-circuits with
    /// a direct response. If all filters pass through without producing
    /// a response, returns 500 (should not happen when UpstreamFilter
    /// is in the chain).
    pub(crate) async fn execute_request(&self, ctx: &mut RequestContext) -> Response {
        for filter in &self.filters {
            match filter.on_request(ctx).await {
                FilterResult::Continue => continue,
                FilterResult::ShortCircuit(response) => return response,
            }
        }
        (StatusCode::INTERNAL_SERVER_ERROR, "no filter produced a response").into_response()
    }

    #[allow(dead_code)]
    pub(crate) async fn execute_response(
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
