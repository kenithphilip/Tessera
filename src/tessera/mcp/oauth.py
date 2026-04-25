"""OAuth 2.1 Resource Server semantics for MCP audience binding.

RFC 8707 (Resource Indicators) requires that an OAuth client
specify the resource it intends to access at token request time, so
the issued access token's ``aud`` claim binds the token to that
resource. AgentMesh acting as a Resource Server in front of an MCP
upstream MUST:

1. Reject any incoming bearer token whose ``aud`` does not name
   AgentMesh's own resource indicator (or is missing entirely).
2. When proxying a downstream tool call to an upstream MCP server,
   request a NEW access token with ``resource=<upstream MCP URI>``
   so the upstream can verify the token was minted for it. Token
   pass-through (re-using the inbound token for an upstream call)
   is structurally rejected by this module.

The companion :func:`token_audience_check` helper enforces the
inbound check; :func:`mint_upstream_token_request` builds the
RFC 8707 token request body for the upstream call. RFC 9728
``/.well-known/oauth-protected-resource`` discovery is exposed
via :func:`resource_metadata_document` so OAuth clients can
discover AgentMesh's resource indicator.

Reference
---------

- RFC 8707 Resource Indicators for OAuth 2.0
- RFC 9728 OAuth 2.0 Protected Resource Metadata
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.5
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from tessera.events import EventKind, SecurityEvent, emit as emit_event


@dataclass(frozen=True, slots=True)
class TokenAudienceCheck:
    """Result of an inbound bearer-token audience check."""

    valid: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.valid


def token_audience_check(
    token_audience: str | list[str] | None,
    *,
    expected_resource: str,
    principal: str | None = None,
    correlation_id: str | None = None,
) -> TokenAudienceCheck:
    """Check that a bearer token's ``aud`` claim names this resource.

    Args:
        token_audience: The token's ``aud`` claim value. Per RFC 9068
            this MAY be a string or a list of strings; the function
            handles both.
        expected_resource: The resource indicator AgentMesh
            advertises via :func:`resource_metadata_document`.
            Typically a fully-qualified URL.
        principal: Subject of the audit event when the check fails.
        correlation_id: Forwarded into the audit event.

    Returns:
        :class:`TokenAudienceCheck`. Failures emit
        :attr:`tessera.events.EventKind.MCP_TOKEN_AUDIENCE_MISMATCH`.
    """
    audiences: list[str]
    if token_audience is None:
        audiences = []
    elif isinstance(token_audience, str):
        audiences = [token_audience]
    else:
        audiences = list(token_audience)

    if expected_resource not in audiences:
        result = TokenAudienceCheck(
            valid=False,
            reason=(
                f"token aud={audiences!r} does not include "
                f"expected resource={expected_resource!r}"
            ),
        )
        emit_event(
            SecurityEvent.now(
                kind=EventKind.MCP_TOKEN_AUDIENCE_MISMATCH,
                principal=principal,
                detail={
                    "expected_resource": expected_resource,
                    "token_audiences": audiences,
                },
                correlation_id=correlation_id,
            )
        )
        return result
    return TokenAudienceCheck(valid=True, reason="aud match")


def mint_upstream_token_request(
    upstream_resource: str,
    *,
    scope: str | None = None,
    audience: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Build the RFC 8707 token request body for an upstream MCP call.

    The returned dict is the form-encoded body the AgentMesh proxy
    POSTs to the authorization server's token endpoint. Includes
    the mandatory ``resource`` parameter; the upstream's bound
    token is then verifiable by the upstream MCP server.

    Args:
        upstream_resource: The upstream MCP server's resource
            indicator. The audience claim of the returned token
            will be set to this value by the AS.
        scope: Optional space-delimited scope list.
        audience: Optional explicit ``audience`` parameter (some
            ASes accept it alongside ``resource``).
        extra: Additional form parameters merged in last.

    Returns:
        A dict suitable for ``urllib.parse.urlencode`` or httpx's
        ``data=`` parameter.
    """
    body: dict[str, str] = {
        "grant_type": "client_credentials",
        "resource": upstream_resource,
    }
    if scope is not None:
        body["scope"] = scope
    if audience is not None:
        body["audience"] = audience
    if extra:
        for k, v in extra.items():
            body[k] = str(v)
    return body


def reject_token_passthrough(
    inbound_token: str | None,
    upstream_token: str | None,
    *,
    principal: str | None = None,
    correlation_id: str | None = None,
) -> TokenAudienceCheck:
    """Refuse to pass an inbound token through to an upstream call.

    AgentMesh proxies that pass an inbound bearer token through to
    an upstream MCP server defeat the audience-binding control:
    the upstream sees a token that may or may not have been minted
    for it. This function returns a failed check whenever inbound
    and upstream tokens are the SAME string (the structural
    indicator of pass-through). Always call before sending an
    upstream request.
    """
    if inbound_token is not None and inbound_token == upstream_token:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.MCP_TOKEN_AUDIENCE_MISMATCH,
                principal=principal,
                detail={
                    "violation": "token_passthrough",
                    "remediation": (
                        "request a new token with "
                        "resource=<upstream> via mint_upstream_token_request"
                    ),
                },
                correlation_id=correlation_id,
            )
        )
        return TokenAudienceCheck(
            valid=False,
            reason="inbound token reused for upstream call (pass-through forbidden)",
        )
    return TokenAudienceCheck(valid=True)


def resource_metadata_document(
    *,
    resource_indicator: str,
    authorization_servers: list[str],
    bearer_methods_supported: tuple[str, ...] = ("header",),
    resource_documentation: str | None = None,
    scopes_supported: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build the RFC 9728 protected-resource metadata document.

    Returned dict is what AgentMesh serves at
    ``/.well-known/oauth-protected-resource``. Clients use it to
    discover the resource indicator they MUST request when minting
    a token for AgentMesh.
    """
    doc: dict[str, Any] = {
        "resource": resource_indicator,
        "authorization_servers": list(authorization_servers),
        "bearer_methods_supported": list(bearer_methods_supported),
    }
    if resource_documentation is not None:
        doc["resource_documentation"] = resource_documentation
    if scopes_supported:
        doc["scopes_supported"] = list(scopes_supported)
    return doc


def www_authenticate_challenge(resource_metadata_url: str) -> str:
    """Return the ``WWW-Authenticate`` header value for a 401 response.

    Per RFC 9728 ``resource_metadata`` parameter, the value points
    OAuth clients at the resource metadata document so they can
    discover which audience to request.
    """
    return f'Bearer resource_metadata="{resource_metadata_url}"'


__all__ = [
    "TokenAudienceCheck",
    "mint_upstream_token_request",
    "reject_token_passthrough",
    "resource_metadata_document",
    "token_audience_check",
    "www_authenticate_challenge",
]
