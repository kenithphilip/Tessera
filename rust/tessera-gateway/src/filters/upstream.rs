use async_trait::async_trait;
use axum::{response::IntoResponse, Json};
use serde_json::json;

use super::{Filter, FilterResult, RequestContext};
use crate::{
    echo_response, error_response, evaluate_call_outcome, extract_tool_calls, forward_upstream,
    min_trust, Decision, StatusCode,
};

/// Forwards the request to the upstream LLM, evaluates proposed
/// tool calls against the trust policy, and annotates the response
/// with allow/deny verdicts.
pub struct UpstreamFilter;

#[async_trait]
impl Filter for UpstreamFilter {
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult {
        let upstream_url = match &ctx.state.config.upstream_url {
            Some(value) => value.clone(),
            None => {
                return FilterResult::ShortCircuit(echo_response(
                    ctx.request.model.clone(),
                    ctx.rendered_messages.clone(),
                    ctx.provenance_verified,
                ))
            }
        };
        let client = match &ctx.state.client {
            Some(value) => value,
            None => {
                return FilterResult::ShortCircuit(error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream forwarding is configured but no HTTP client is available",
                ))
            }
        };

        let upstream_payload = match &ctx.upstream_payload {
            Some(payload) => payload.clone(),
            None => {
                return FilterResult::ShortCircuit(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "upstream payload was not prepared by prior filter",
                ))
            }
        };

        let mut upstream_response = match forward_upstream(client, &upstream_url, &upstream_payload).await
        {
            Ok(response) => response,
            Err(response) => return FilterResult::ShortCircuit(response),
        };

        let proposed_calls = extract_tool_calls(&upstream_response.body);
        if proposed_calls.is_empty() {
            return FilterResult::ShortCircuit(
                (upstream_response.status, Json(upstream_response.body)).into_response(),
            );
        }

        let observed_trust = min_trust(&ctx.request.messages);
        let runtime = ctx
            .runtime
            .as_ref()
            .expect("runtime must be populated by PolicyEvaluationFilter");
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for call in &proposed_calls {
            let outcome = evaluate_call_outcome(
                &ctx.state,
                &ctx.request,
                call,
                observed_trust,
                ctx.delegation.as_ref(),
                runtime,
            )
            .await;
            match outcome.decision {
                Decision::Allow => {
                    allowed.push(json!({
                        "name": call.name,
                        "arguments": call.arguments,
                    }));
                }
                Decision::Deny {
                    reason,
                    required_trust,
                    observed_trust,
                } => {
                    denied.push(json!({
                        "tool": call.name,
                        "denied": true,
                        "reason": reason,
                        "required_trust": required_trust,
                        "observed_trust": observed_trust,
                        "backend": outcome.backend,
                        "backend_metadata": outcome.backend_metadata,
                    }));
                }
            }
        }

        let response = match upstream_response.body.as_object_mut() {
            Some(body) => {
                body.insert(
                    "tessera".to_string(),
                    json!({
                        "allowed": allowed,
                        "denied": denied,
                    }),
                );
                (upstream_response.status, Json(upstream_response.body)).into_response()
            }
            None => error_response(
                StatusCode::BAD_GATEWAY,
                "upstream response must be a JSON object",
            ),
        };
        FilterResult::ShortCircuit(response)
    }
}
