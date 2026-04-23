use async_trait::async_trait;

use super::{Filter, FilterResult, RequestContext};
use crate::{
    request_url, verify_delegation_header, verify_identity_headers, verify_prompt_provenance,
    verify_transport_identity,
};

/// Verifies transport identity, workload identity (JWT+PoP),
/// delegation tokens, and prompt provenance headers.
pub struct IdentityVerificationFilter;

#[async_trait]
impl Filter for IdentityVerificationFilter {
    async fn on_request(&self, ctx: &mut RequestContext) -> FilterResult {
        let identity_header = ctx
            .headers
            .get("ASM-Agent-Identity")
            .and_then(|v| v.to_str().ok());
        let proof_header = ctx
            .headers
            .get("ASM-Agent-Proof")
            .and_then(|v| v.to_str().ok());
        let delegation_header = ctx
            .headers
            .get("ASM-Agent-Delegation")
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
            Err(response) => return FilterResult::ShortCircuit(response),
        };

        let verified_identity = match verify_identity_headers(
            identity_header,
            proof_header,
            &ctx.state.config,
            &ctx.method,
            &request_url(&ctx.headers, &ctx.uri),
            &ctx.state.proof_replay_cache,
            peer_identity.as_ref(),
        ) {
            Ok(identity) => identity,
            Err(response) => return FilterResult::ShortCircuit(response),
        };

        let delegation = match verify_delegation_header(delegation_header, &ctx.state.config) {
            Ok(token) => token,
            Err(response) => return FilterResult::ShortCircuit(response),
        };

        let provenance_header = ctx
            .headers
            .get("ASM-Prompt-Provenance")
            .and_then(|v| v.to_str().ok());
        if let Err(response) = verify_prompt_provenance(
            provenance_header,
            &ctx.request.messages,
            ctx.state.config.provenance_key(),
        ) {
            return FilterResult::ShortCircuit(response);
        }

        ctx.peer_identity = peer_identity;
        ctx.verified_identity = verified_identity;
        ctx.delegation = delegation;
        ctx.provenance_verified = provenance_header.is_some();
        FilterResult::Continue
    }
}
