use async_trait::async_trait;
use serde_json::json;

use super::{Filter, FilterResult, RequestContext};
use crate::{echo_response, render_for_upstream};

/// Renders messages for upstream, evaluates tool calls against
/// trust policy, and produces the final annotated response.
///
/// If upstream forwarding is disabled, returns an echo response
/// containing the rendered messages.
pub struct PolicyEvaluationFilter;

#[async_trait]
impl Filter for PolicyEvaluationFilter {
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult {
        let runtime = ctx.state.runtime_control.read().await.clone();
        ctx.runtime = Some(runtime);

        let rendered_messages: Vec<serde_json::Value> = ctx
            .request
            .messages
            .iter()
            .map(|message| {
                json!({
                    "role": message.role,
                    "content": render_for_upstream(message),
                })
            })
            .collect();
        let upstream_payload = json!({
            "model": ctx.request.model,
            "messages": rendered_messages,
        });

        ctx.rendered_messages = rendered_messages;
        ctx.upstream_payload = Some(upstream_payload);

        if !ctx.state.config.chat_forwarding_enabled() {
            return FilterResult::ShortCircuit(echo_response(
                ctx.request.model.clone(),
                ctx.rendered_messages.clone(),
                ctx.provenance_verified,
            ));
        }

        FilterResult::Continue
    }
}
