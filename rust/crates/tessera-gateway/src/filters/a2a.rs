//! A2A JSON-RPC filter pipeline.
//!
//! Mirrors the chat FilterChain pattern but carries A2A-specific context:
//! a JSON-RPC request ID, A2A task params, and the verified security context
//! populated by A2ASecurityContextFilter.
//!
//! Pipeline:
//!   A2AIdentityFilter
//!     -> A2ASecurityContextFilter
//!     -> A2APolicyFilter
//!     -> A2AUpstreamFilter

use async_trait::async_trait;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::{
    error_response, evaluate_intent_outcome, forward_upstream, jsonrpc_error_response,
    min_envelope_trust, request_url, require_verified_a2a_security_context, verify_identity_headers,
    verify_transport_identity, A2ATaskParamsModel, AppState, Decision, TransportPeerIdentity,
    VerifiedA2ASecurityContext,
};

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Request context shared across all A2A filters for one request.
pub(crate) struct A2ARequestContext {
    /// Shared gateway state (config, client, replay cache).
    pub(crate) state: AppState,
    /// JSON-RPC request ID, echoed in error and success responses.
    pub(crate) req_id: Value,
    /// Parsed and validated A2A task parameters.
    pub(crate) params: A2ATaskParamsModel,
    /// Inbound HTTP headers (for identity and transport verification).
    pub(crate) headers: HeaderMap,
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) immediate_client_host: Option<String>,
    pub(crate) transport_identity: Option<TransportPeerIdentity>,
    pub(crate) transport_error: Option<String>,
    // Populated by filters:
    /// Verified transport peer identity (set by A2AIdentityFilter).
    pub(crate) peer_identity: Option<TransportPeerIdentity>,
    /// Verified A2A security context (set by A2ASecurityContextFilter).
    pub(crate) security_context: Option<VerifiedA2ASecurityContext>,
    /// Minimum envelope trust level (set by A2ASecurityContextFilter).
    pub(crate) observed_trust: i64,
}

// ---------------------------------------------------------------------------
// Filter trait and chain
// ---------------------------------------------------------------------------

pub(crate) enum A2AFilterResult {
    Continue,
    ShortCircuit(Response),
}

#[async_trait]
pub(crate) trait A2AFilter: Send + Sync {
    async fn on_request(&self, ctx: &mut A2ARequestContext) -> A2AFilterResult;
}

pub(crate) struct A2AFilterChain {
    filters: Vec<Box<dyn A2AFilter>>,
}

impl A2AFilterChain {
    pub(crate) fn new(filters: Vec<Box<dyn A2AFilter>>) -> Self {
        Self { filters }
    }

    pub(crate) async fn execute_request(&self, ctx: &mut A2ARequestContext) -> Response {
        for filter in &self.filters {
            match filter.on_request(ctx).await {
                A2AFilterResult::Continue => continue,
                A2AFilterResult::ShortCircuit(response) => return response,
            }
        }
        (StatusCode::INTERNAL_SERVER_ERROR, "no A2A filter produced a response").into_response()
    }
}

// ---------------------------------------------------------------------------
// Filter 1: identity verification
// ---------------------------------------------------------------------------

/// Verifies transport identity and workload identity headers.
///
/// Reuses the same verification functions as the chat IdentityVerificationFilter.
/// On success, stores the peer identity in ctx.peer_identity.
pub(crate) struct A2AIdentityFilter;

#[async_trait]
impl A2AFilter for A2AIdentityFilter {
    async fn on_request(&self, ctx: &mut A2ARequestContext) -> A2AFilterResult {
        let identity_header = ctx
            .headers
            .get("ASM-Agent-Identity")
            .and_then(|v| v.to_str().ok());
        let proof_header = ctx
            .headers
            .get("ASM-Agent-Proof")
            .and_then(|v| v.to_str().ok());

        let peer_identity = match verify_transport_identity(
            &ctx.state.config,
            ctx.headers
                .get("x-forwarded-client-cert")
                .and_then(|v| v.to_str().ok()),
            ctx.immediate_client_host.clone(),
            ctx.transport_identity.clone(),
            ctx.transport_error.clone(),
        ) {
            Ok(identity) => identity,
            Err(response) => return A2AFilterResult::ShortCircuit(response),
        };

        if let Err(response) = verify_identity_headers(
            identity_header,
            proof_header,
            &ctx.state.config,
            &ctx.method,
            &request_url(&ctx.headers, &ctx.uri),
            &ctx.state.proof_replay_cache,
            peer_identity.as_ref(),
        ) {
            return A2AFilterResult::ShortCircuit(response);
        }

        ctx.peer_identity = peer_identity;
        A2AFilterResult::Continue
    }
}

// ---------------------------------------------------------------------------
// Filter 2: A2A security context verification
// ---------------------------------------------------------------------------

/// Extracts and verifies the tessera_security_context from the A2A task metadata.
///
/// Populates ctx.security_context and ctx.observed_trust on success.
pub(crate) struct A2ASecurityContextFilter;

#[async_trait]
impl A2AFilter for A2ASecurityContextFilter {
    async fn on_request(&self, ctx: &mut A2ARequestContext) -> A2AFilterResult {
        match require_verified_a2a_security_context(&ctx.params, &ctx.state.config) {
            Ok(security_context) => {
                ctx.observed_trust = min_envelope_trust(&security_context.envelopes);
                ctx.security_context = Some(security_context);
                A2AFilterResult::Continue
            }
            Err(response) => A2AFilterResult::ShortCircuit(response),
        }
    }
}

// ---------------------------------------------------------------------------
// Filter 3: intent policy evaluation
// ---------------------------------------------------------------------------

/// Evaluates the A2A intent against local trust policy and optional OPA backend.
///
/// Returns a JSON-RPC -32003 error on deny. Requires A2ASecurityContextFilter
/// to have already populated ctx.security_context.
pub(crate) struct A2APolicyFilter;

#[async_trait]
impl A2AFilter for A2APolicyFilter {
    async fn on_request(&self, ctx: &mut A2ARequestContext) -> A2AFilterResult {
        let security_context = ctx
            .security_context
            .as_ref()
            .expect("A2ASecurityContextFilter must run before A2APolicyFilter");
        let required_trust = ctx.state.config.a2a_required_trust(&ctx.params.intent);
        let outcome = evaluate_intent_outcome(
            &ctx.state,
            &ctx.params,
            security_context,
            ctx.observed_trust,
            required_trust,
        )
        .await;

        if let Decision::Deny {
            reason,
            required_trust,
            observed_trust,
        } = outcome.decision
        {
            return A2AFilterResult::ShortCircuit(jsonrpc_error_response(
                ctx.req_id.clone(),
                -32003,
                &reason,
                Some(json!({
                    "intent": ctx.params.intent,
                    "required_trust": required_trust,
                    "observed_trust": observed_trust,
                    "backend": outcome.backend,
                    "backend_metadata": outcome.backend_metadata,
                })),
            ));
        }

        A2AFilterResult::Continue
    }
}

// ---------------------------------------------------------------------------
// Filter 4: upstream forwarding
// ---------------------------------------------------------------------------

/// Forwards the allowed A2A task to the configured upstream A2A service.
///
/// Always short-circuits (either with the upstream response or an error).
pub(crate) struct A2AUpstreamFilter;

#[async_trait]
impl A2AFilter for A2AUpstreamFilter {
    async fn on_request(&self, ctx: &mut A2ARequestContext) -> A2AFilterResult {
        let upstream_url = match &ctx.state.config.a2a_upstream_url {
            Some(url) => url.clone(),
            None => {
                return A2AFilterResult::ShortCircuit(jsonrpc_error_response(
                    ctx.req_id.clone(),
                    -32004,
                    "A2A transport is not configured on this gateway",
                    None,
                ))
            }
        };
        let client = match &ctx.state.client {
            Some(client) => client.clone(),
            None => {
                return A2AFilterResult::ShortCircuit(error_response(
                    StatusCode::BAD_GATEWAY,
                    "A2A forwarding is configured but no HTTP client is available",
                ))
            }
        };
        let upstream_payload = json!({
            "jsonrpc": "2.0",
            "id": ctx.req_id,
            "method": "tasks.send",
            "params": ctx.params,
        });
        match forward_upstream(&client, &upstream_url, &upstream_payload).await {
            Ok(response) => {
                A2AFilterResult::ShortCircuit((response.status, Json(response.body)).into_response())
            }
            Err(response) => A2AFilterResult::ShortCircuit(response),
        }
    }
}
