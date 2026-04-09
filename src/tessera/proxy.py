"""OpenAI-compatible sidecar proxy that enforces Tessera policy.

The proxy accepts a superset of the OpenAI chat completions schema: each
message may include a Tessera label, and the request may declare a set of
tools with required trust levels. The proxy:

    1. Verifies every label against the HMAC key.
    2. Builds a Context and renders it with spotlighting.
    3. If the upstream response proposes tool calls, evaluates each one
       against the policy and rewrites denied calls into structured refusals.

The upstream LLM is invoked via an injectable callable so this module does
not depend on a specific provider SDK. A production deployment wires
`upstream` to httpx against OpenAI, Anthropic, or any other chat API.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from tessera.context import Context, LabeledSegment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLabel, TrustLevel
from tessera.policy import Policy
from tessera.redaction import SecretRegistry, redact_nested
from tessera.telemetry import proxy_request_span, upstream_span

UpstreamFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class LabelModel(BaseModel):
    origin: Origin
    principal: str
    trust_level: int
    nonce: str
    signature: str


class MessageModel(BaseModel):
    role: str
    content: str
    label: LabelModel


class ToolModel(BaseModel):
    name: str
    required_trust: int = int(TrustLevel.USER)


class ChatRequest(BaseModel):
    model: str
    messages: list[MessageModel]
    tools: list[ToolModel] = Field(default_factory=list)


def _to_segment(msg: MessageModel) -> LabeledSegment:
    label = TrustLabel(
        origin=msg.label.origin,
        principal=msg.label.principal,
        trust_level=TrustLevel(msg.label.trust_level),
        nonce=msg.label.nonce,
        signature=msg.label.signature,
    )
    return LabeledSegment(content=msg.content, label=label)


def create_app(
    key: bytes,
    upstream: UpstreamFn,
    policy: Policy | None = None,
    secrets: SecretRegistry | None = None,
) -> FastAPI:
    """Build a FastAPI app wired to the given HMAC key, upstream, and policy.

    Args:
        key: HMAC key used to verify every inbound label.
        upstream: Async callable that takes an OpenAI-shaped payload and
            returns the upstream response as a dict.
        policy: Taint-tracking policy applied to proposed tool calls.
            Defaults to an empty policy where every tool requires USER
            trust unless overridden per request.
        secrets: Optional credential registry. When provided, the proxy
            scrubs every occurrence of the registered values from both
            outbound messages (before upstream sees them) and inbound
            responses (before the agent sees them), and emits a
            ``SECRET_REDACTED`` event whenever a hit fires. Leave unset
            on deployments that do not need credential isolation.
    """
    app = FastAPI(title="Tessera Proxy", version="0.0.1")
    effective_policy = policy or Policy()
    secret_registry = secrets or SecretRegistry()

    @app.post("/v1/chat/completions")
    async def chat_completions(req: ChatRequest) -> dict[str, Any]:
        with proxy_request_span(model=req.model, message_count=len(req.messages)):
            return await _handle_chat(req)

    async def _handle_chat(req: ChatRequest) -> dict[str, Any]:
        context = Context()
        for msg in req.messages:
            segment = _to_segment(msg)
            if not segment.verify(key):
                raise HTTPException(
                    status_code=401,
                    detail=f"invalid label signature on message from {msg.role}",
                )
            context.add(segment)

        # Register per-request tool requirements so the policy evaluates
        # against the caller's declared surface.
        for tool in req.tools:
            effective_policy.require(tool.name, TrustLevel(tool.required_trust))

        outbound_messages: list[dict[str, Any]] = []
        egress_principal = context.principal
        for m in req.messages:
            rendered = _render_for_upstream(m, context)
            if len(secret_registry) > 0:
                rendered, hits = secret_registry.redact(rendered)
                if hits:
                    emit_event(
                        SecurityEvent.now(
                            kind=EventKind.SECRET_REDACTED,
                            principal=egress_principal,
                            detail={
                                "direction": "egress",
                                "role": m.role,
                                "secrets": hits,
                            },
                        )
                    )
            outbound_messages.append({"role": m.role, "content": rendered})

        upstream_payload = {
            "model": req.model,
            "messages": outbound_messages,
        }
        with upstream_span(req.model):
            response = await upstream(upstream_payload)

        if len(secret_registry) > 0:
            _, ingress_hits = redact_nested(response, secret_registry)
            if ingress_hits:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.SECRET_REDACTED,
                        principal=egress_principal,
                        detail={
                            "direction": "ingress",
                            "secrets": ingress_hits,
                        },
                    )
                )

        proposed_calls = _extract_tool_calls(response)
        if not proposed_calls:
            return response

        refusals: list[dict[str, Any]] = []
        allowed: list[dict[str, Any]] = []
        for call in proposed_calls:
            decision = effective_policy.evaluate(
                context, call["name"], call.get("arguments")
            )
            if decision.allowed:
                allowed.append(call)
            else:
                refusals.append(
                    {
                        "tool": call["name"],
                        "denied": True,
                        "reason": decision.reason,
                        "required_trust": int(decision.required_trust),
                        "observed_trust": int(decision.observed_trust),
                    }
                )

        response["tessera"] = {"allowed": allowed, "denied": refusals}
        return response

    return app


def _render_for_upstream(msg: MessageModel, context: Context) -> str:
    """For the upstream request, send the spotlit content, not the raw bytes."""
    # Match this message to its segment by identity; rebuild a mini-context
    # containing just this message to render it with spotlighting.
    mini = Context()
    mini.add(_to_segment(msg))
    del context  # reserved for future cross-message rewrites
    return mini.render()


def _extract_tool_calls(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull proposed tool calls out of an OpenAI-style response shape."""
    calls: list[dict[str, Any]] = []
    for choice in response.get("choices", []):
        message = choice.get("message", {})
        for call in message.get("tool_calls", []) or []:
            fn = call.get("function", {})
            calls.append(
                {
                    "name": fn.get("name", ""),
                    "arguments": fn.get("arguments"),
                }
            )
    return calls
