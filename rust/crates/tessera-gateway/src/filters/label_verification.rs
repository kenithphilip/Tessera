use async_trait::async_trait;

use super::{Filter, FilterResult, RequestContext};
use crate::{not_implemented, validate_declared_tools, verify_labels};

/// Verifies HMAC signatures on all message labels and validates
/// the declared tool surface before passing to downstream filters.
pub struct LabelVerificationFilter;

#[async_trait]
impl Filter for LabelVerificationFilter {
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult {
        if !ctx.state.config.chat_enforcement_enabled() {
            return FilterResult::ShortCircuit(not_implemented(
                "Rust gateway scaffold exists, chat mediation is not implemented yet",
            ));
        }
        let label_key = match ctx.state.config.label_hmac_key.as_ref() {
            Some(key) => key.as_slice(),
            None => {
                return FilterResult::ShortCircuit(not_implemented(
                    "Rust gateway scaffold exists, chat mediation is not implemented yet",
                ))
            }
        };

        if let Err(response) = verify_labels(&ctx.request.messages, label_key) {
            return FilterResult::ShortCircuit(response);
        }
        if let Err(response) = validate_declared_tools(&ctx.request.tools) {
            return FilterResult::ShortCircuit(response);
        }
        FilterResult::Continue
    }
}
