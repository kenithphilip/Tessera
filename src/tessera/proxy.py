"""OpenAI-compatible sidecar proxy that enforces Tessera policy.

The proxy accepts a superset of the OpenAI chat completions schema: each
message may include a Tessera label, and the request may declare a set of
tools with required trust levels. The proxy:

    1. Verifies every label against either an HMAC key or a LabelVerifier.
    2. Builds a Context and renders it with spotlighting.
    3. If the upstream response proposes tool calls, evaluates each one
       against the policy and rewrites denied calls into structured refusals.

The upstream LLM is invoked via an injectable callable so this module does
not depend on a specific provider SDK. A production deployment wires
`upstream` to httpx against OpenAI, Anthropic, or any other chat API.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
import json
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from tessera.a2a import (
    A2APromptSegment,
    A2ASecurityContext,
    A2ATaskRequest,
    A2AVerificationError,
    extract_security_context,
)
from tessera.context import Context, LabeledSegment
from tessera.delegation import DelegationToken, verify_delegation
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.identity import AgentIdentity, AgentProofReplayCache, AgentProofVerifier
from tessera.labels import Origin, TrustLabel, TrustLevel
from tessera.mtls import MTLSPeerIdentity, MTLSPeerVerificationError, extract_peer_identity
from tessera.approval import AsyncApprovalGate
from tessera.policy import DecisionKind, Policy, ToolRequirement
from tessera.provenance import (
    ContextSegmentEnvelope,
    ManifestSegmentRef,
    PromptProvenanceManifest,
)
from tessera.redaction import SecretRegistry, redact_nested
from tessera.telemetry import proxy_request_span, record_upstream_usage, upstream_span

if TYPE_CHECKING:
    from tessera.identity import AgentIdentityVerifier
    from tessera.signing import LabelVerifier

UpstreamFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
A2AHandlerFn = Callable[[A2ATaskRequest], Awaitable[dict[str, Any]]]


class LabelModel(BaseModel):
    origin: Origin
    principal: str
    trust_level: TrustLevel
    nonce: str
    signature: str


class MessageModel(BaseModel):
    role: str
    content: str
    label: LabelModel


class ToolModel(BaseModel):
    name: str
    required_trust: TrustLevel = TrustLevel.USER


class ChatRequest(BaseModel):
    model: str
    messages: list[MessageModel]
    tools: list[ToolModel] = Field(default_factory=list)


class JSONRPCRequest(BaseModel):
    jsonrpc: str
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class A2AInputSegmentModel(BaseModel):
    segment_id: str
    role: str
    content: str


class A2ATaskParamsModel(BaseModel):
    task_id: str
    intent: str
    input_segments: list[A2AInputSegmentModel]
    metadata: dict[str, Any] = Field(default_factory=dict)


class DiscoveryConfig(BaseModel):
    """User-facing discovery metadata for the proxy surface."""

    agent_id: str | None = None
    agent_name: str = "Tessera Proxy"
    description: str | None = None
    url: str | None = None


class MTLSConfig(BaseModel):
    """Transport identity settings for peer certificate enforcement."""

    required: bool = False
    trust_xfcc: bool = False
    trusted_proxy_hosts: tuple[str, ...] = ()
    trust_domains: tuple[str, ...] = ()


def _to_segment(msg: MessageModel) -> LabeledSegment:
    label = TrustLabel(
        origin=msg.label.origin,
        principal=msg.label.principal,
        trust_level=msg.label.trust_level,
        nonce=msg.label.nonce,
        signature=msg.label.signature,
    )
    return LabeledSegment(content=msg.content, label=label)


def create_app(
    key: bytes | bytearray | None = None,
    *,
    verifier: "LabelVerifier | None" = None,
    identity_verifier: "AgentIdentityVerifier | None" = None,
    provenance_key: bytes | bytearray | None = None,
    delegation_key: bytes | bytearray | None = None,
    identity_audience: str | None = None,
    delegation_audience: str = "proxy://tessera",
    agent_id: str | None = None,
    agent_name: str = "Tessera Proxy",
    agent_description: str | None = None,
    agent_url: str | None = None,
    require_identity: bool | None = None,
    require_identity_proof: bool | None = None,
    proof_max_age: timedelta = timedelta(minutes=5),
    require_mtls: bool = False,
    trust_xfcc: bool = False,
    trusted_proxy_hosts: tuple[str, ...] = (),
    mtls_trust_domains: tuple[str, ...] | None = None,
    upstream: UpstreamFn,
    policy: Policy | None = None,
    secrets: SecretRegistry | None = None,
    a2a_handler: A2AHandlerFn | None = None,
    approval_gate: AsyncApprovalGate | None = None,
) -> FastAPI:
    """Build a FastAPI app wired to a label verifier, upstream, and policy."""
    app = FastAPI(title="Tessera Proxy", version="0.0.1")
    if (key is None) == (verifier is None):
        raise ValueError(
            "create_app requires exactly one of `key` (HMAC) or `verifier`"
        )
    label_verifier = bytes(key) if key is not None else verifier
    hmac_key = bytes(key) if key is not None else None
    effective_provenance_key = (
        bytes(provenance_key) if provenance_key is not None else hmac_key
    )
    effective_delegation_key = (
        bytes(delegation_key) if delegation_key is not None else hmac_key
    )
    base_policy = policy or Policy()
    effective_identity_audience = identity_audience or agent_id or delegation_audience
    effective_require_identity = (
        identity_verifier is not None
        if require_identity is None
        else require_identity
    )
    effective_require_identity_proof = (
        identity_verifier is not None
        if require_identity_proof is None
        else require_identity_proof
    )
    if (effective_require_identity or effective_require_identity_proof) and identity_verifier is None:
        raise ValueError("identity_verifier is required when inbound workload identity is enforced")
    proof_verifier = (
        AgentProofVerifier(
            max_age=proof_max_age,
            replay_cache=AgentProofReplayCache(),
        )
        if identity_verifier is not None
        else None
    )
    if trust_xfcc and not trusted_proxy_hosts:
        raise ValueError("trusted_proxy_hosts is required when trust_xfcc is enabled")
    if mtls_trust_domains is None and agent_id is not None:
        parsed = urlparse(agent_id)
        effective_mtls_trust_domains = (parsed.netloc,) if parsed.netloc else ()
    else:
        effective_mtls_trust_domains = mtls_trust_domains or ()
    if require_mtls and not effective_mtls_trust_domains:
        raise ValueError(
            "mtls_trust_domains or agent_id is required when mTLS enforcement is enabled"
        )
    mtls = MTLSConfig(
        required=require_mtls,
        trust_xfcc=trust_xfcc,
        trusted_proxy_hosts=trusted_proxy_hosts,
        trust_domains=effective_mtls_trust_domains,
    )
    discovery = DiscoveryConfig(
        agent_id=agent_id,
        agent_name=agent_name,
        description=agent_description,
        url=agent_url,
    )
    _validate_discovery_config(discovery)
    secret_registry = secrets or SecretRegistry()

    @app.get("/.well-known/agent.json")
    async def agent_card() -> dict[str, Any]:
        return _discovery_document(
            discovery,
            label_mode="hmac" if hmac_key is not None else "verifier",
            prompt_provenance_enabled=effective_provenance_key is not None,
            delegation_enabled=effective_delegation_key is not None,
            delegation_audience=delegation_audience,
            workload_identity_enabled=identity_verifier is not None,
            workload_identity_required=effective_require_identity,
            workload_identity_audience=effective_identity_audience,
            proof_of_possession_enabled=effective_require_identity_proof,
            mtls=mtls,
            a2a_supported=a2a_handler is not None,
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        req: ChatRequest,
        asm_agent_identity: str | None = Header(
            default=None, alias="ASM-Agent-Identity"
        ),
        asm_agent_proof: str | None = Header(
            default=None, alias="ASM-Agent-Proof"
        ),
        asm_agent_delegation: str | None = Header(
            default=None, alias="ASM-Agent-Delegation"
        ),
        asm_prompt_provenance: str | None = Header(
            default=None, alias="ASM-Prompt-Provenance"
        ),
    ) -> dict[str, Any]:
        with proxy_request_span(
            model=req.model,
            message_count=len(req.messages),
            operation_name="chat",
            agent_name=discovery.agent_name,
            agent_id=discovery.agent_id,
        ):
            return await _handle_chat(
                req,
                request=request,
                identity_header=asm_agent_identity,
                proof_header=asm_agent_proof,
                delegation_header=asm_agent_delegation,
                provenance_header=asm_prompt_provenance,
            )

    @app.post("/a2a/jsonrpc")
    async def a2a_jsonrpc(
        request: Request,
        req: JSONRPCRequest,
        asm_agent_identity: str | None = Header(
            default=None, alias="ASM-Agent-Identity"
        ),
        asm_agent_proof: str | None = Header(
            default=None, alias="ASM-Agent-Proof"
        ),
    ) -> dict[str, Any]:
        if req.jsonrpc != "2.0":
            raise HTTPException(status_code=400, detail="A2A requests must use JSON-RPC 2.0")
        if req.method != "tasks.send":
            return _jsonrpc_error(req.id, code=-32601, message="method not found")
        if a2a_handler is None:
            return _jsonrpc_error(
                req.id,
                code=-32004,
                message="A2A transport is not configured on this proxy",
            )
        try:
            params = A2ATaskParamsModel.model_validate(req.params)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc

        with proxy_request_span(
            model="a2a",
            message_count=len(params.input_segments),
            operation_name="invoke_agent",
            agent_name=discovery.agent_name,
            agent_id=discovery.agent_id,
        ):
            _verify_identity_headers(
                request=request,
                identity_header=asm_agent_identity,
                proof_header=asm_agent_proof,
                verifier=identity_verifier,
                proof_verifier=proof_verifier,
                audience=effective_identity_audience,
                require_identity=effective_require_identity,
                require_proof=effective_require_identity_proof,
                mtls=mtls,
            )
            security_context = _require_verified_a2a_security_context(
                {
                    "task_id": params.task_id,
                    "intent": params.intent,
                    "input_segments": [
                        {
                            "segment_id": segment.segment_id,
                            "role": segment.role,
                            "content": segment.content,
                        }
                        for segment in params.input_segments
                    ],
                    "metadata": params.metadata,
                },
                delegation_key=effective_delegation_key,
                provenance_key=effective_provenance_key,
                delegation_audience=delegation_audience,
                expected_delegate=discovery.agent_id,
            )
            task = A2ATaskRequest(
                task_id=params.task_id,
                intent=params.intent,
                input_segments=tuple(
                    A2APromptSegment(
                        segment_id=segment.segment_id,
                        role=segment.role,
                        content=segment.content,
                    )
                    for segment in params.input_segments
                ),
                metadata=params.metadata,
                security_context=security_context,
            )
            context = _context_from_a2a_task(task, security_context)
            decision = base_policy.evaluate(
                context,
                task.intent,
                delegation=security_context.delegation,
                expected_delegate=discovery.agent_id,
            )
            if not decision.allowed:
                return _jsonrpc_error(
                    req.id,
                    code=-32003,
                    message=decision.reason,
                    data={
                        "intent": task.intent,
                        "required_trust": int(decision.required_trust),
                        "observed_trust": int(decision.observed_trust),
                    },
                )
            return {
                "jsonrpc": "2.0",
                "id": req.id,
                "result": await a2a_handler(task),
            }

    async def _handle_chat(
        req: ChatRequest,
        *,
        request: Request,
        identity_header: str | None,
        proof_header: str | None,
        delegation_header: str | None,
        provenance_header: str | None,
    ) -> dict[str, Any]:
        _verify_identity_headers(
            request=request,
            identity_header=identity_header,
            proof_header=proof_header,
            verifier=identity_verifier,
            proof_verifier=proof_verifier,
            audience=effective_identity_audience,
            require_identity=effective_require_identity,
            require_proof=effective_require_identity_proof,
            mtls=mtls,
        )
        context = Context()
        for msg in req.messages:
            segment = _to_segment(msg)
            if not segment.verify(label_verifier):
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.LABEL_VERIFY_FAILURE,
                        principal=None,
                        detail={
                            "role": msg.role,
                            "claimed_principal": msg.label.principal,
                            "origin": str(msg.label.origin),
                        },
                    )
                )
                raise HTTPException(
                    status_code=401,
                    detail=f"invalid label signature on message from {msg.role}",
                )
            context.add(segment)

        delegation = _verify_delegation_header(
            delegation_header,
            key=effective_delegation_key,
            audience=delegation_audience,
            expected_delegate=discovery.agent_id,
        )
        _verify_provenance_header(
            provenance_header,
            messages=req.messages,
            key=effective_provenance_key,
        )
        request_policy = _policy_for_request(base_policy, req.tools)
        # Evaluate against the caller's declared surface without mutating
        # the shared base policy held by the app.
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

        usage = response.get("usage") or {}
        choices = response.get("choices") or []
        record_upstream_usage(
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            finish_reason=choices[0].get("finish_reason") if choices else None,
            response_model=response.get("model"),
        )

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
        pending_approval: list[dict[str, Any]] = []
        for call in proposed_calls:
            decision = request_policy.evaluate(
                context,
                call["name"],
                call.get("arguments"),
                delegation=delegation,
                expected_delegate=discovery.agent_id,
            )
            if decision.requires_approval:
                if approval_gate is not None:
                    resolved = await approval_gate.request_approval(
                        decision,
                        principal=context.principal or "unknown",
                        context_summary=f"{len(context.segments)} segments, min_trust={int(context.min_trust)}",
                    )
                    if resolved.allowed:
                        allowed.append(call)
                    else:
                        refusals.append(
                            {
                                "tool": call["name"],
                                "denied": True,
                                "reason": resolved.reason,
                                "required_trust": int(resolved.required_trust),
                                "observed_trust": int(resolved.observed_trust),
                            }
                        )
                else:
                    # No approval gate configured: fail closed.
                    refusals.append(
                        {
                            "tool": call["name"],
                            "denied": True,
                            "reason": "requires human approval but no approval gate configured",
                            "required_trust": int(decision.required_trust),
                            "observed_trust": int(decision.observed_trust),
                        }
                    )
                pending_approval.append(
                    {
                        "tool": call["name"],
                        "reason": decision.reason,
                        "required_trust": int(decision.required_trust),
                        "observed_trust": int(decision.observed_trust),
                    }
                )
            elif decision.allowed:
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

        response["tessera"] = {
            "allowed": allowed,
            "denied": refusals,
            "pending_approval": pending_approval,
        }
        return response

    return app


def _validate_discovery_config(config: DiscoveryConfig) -> None:
    if config.agent_id is None:
        return
    if not config.agent_id.startswith("spiffe://"):
        raise ValueError("agent_id must use a SPIFFE ID, for example spiffe://...")
    parsed = urlparse(config.agent_id)
    if not parsed.netloc or not parsed.path or parsed.path == "/":
        raise ValueError("agent_id must include a SPIFFE trust domain and path")


def _discovery_document(
    config: DiscoveryConfig,
    *,
    label_mode: str,
    prompt_provenance_enabled: bool,
    delegation_enabled: bool,
    delegation_audience: str,
    workload_identity_enabled: bool,
    workload_identity_required: bool,
    workload_identity_audience: str,
    proof_of_possession_enabled: bool,
    mtls: MTLSConfig,
    a2a_supported: bool,
) -> dict[str, Any]:
    if config.agent_id is None:
        identity = {
            "configured": False,
            "scheme": None,
            "trust_domain": None,
            "path": None,
        }
    else:
        parsed = urlparse(config.agent_id)
        identity = {
            "configured": True,
            "scheme": parsed.scheme,
            "trust_domain": parsed.netloc,
            "path": parsed.path,
        }
    return {
        "id": config.agent_id,
        "name": config.agent_name,
        "description": config.description,
        "url": config.url,
        "version": "0.0.1",
        "identity": identity,
        "protocols": {
            "openai_chat_completions": {
                "supported": True,
                "path": "/v1/chat/completions",
            },
            "mcp": {
                "supported": False,
                "reason": "the reference proxy does not expose MCP transports",
            },
            "a2a": {
                "supported": a2a_supported,
                "path": "/a2a/jsonrpc" if a2a_supported else None,
                "reason": (
                    None
                    if a2a_supported
                    else "agent discovery is exposed before A2A task exchange is implemented"
                ),
            },
        },
        "security": {
            "label_verification": label_mode,
            "workload_identity": {
                "enabled": workload_identity_enabled,
                "required": workload_identity_required if workload_identity_enabled else False,
                "audience": workload_identity_audience if workload_identity_enabled else None,
                "proof_of_possession": proof_of_possession_enabled
                if workload_identity_enabled
                else False,
                "header": "ASM-Agent-Identity" if workload_identity_enabled else None,
                "proof_header": "ASM-Agent-Proof" if workload_identity_enabled else None,
            },
            "mtls": {
                "enabled": mtls.required or mtls.trust_xfcc,
                "required": mtls.required,
                "transport_source": "asgi_tls_extension",
                "trust_xfcc": mtls.trust_xfcc,
                "xfcc_header": "X-Forwarded-Client-Cert" if mtls.trust_xfcc else None,
                "trust_domains": list(mtls.trust_domains),
            },
            "prompt_provenance": prompt_provenance_enabled,
            "delegation": {
                "enabled": delegation_enabled,
                "audience": delegation_audience if delegation_enabled else None,
            },
            "quarantined_execution": False,
        },
    }


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
                    "arguments": _normalize_arguments(fn.get("arguments")),
                }
            )
    return calls


def _normalize_arguments(raw_arguments: Any) -> dict[str, Any] | None:
    """Parse OpenAI-style stringified tool args into a dict when possible."""
    if raw_arguments is None:
        return None
    if isinstance(raw_arguments, dict):
        return raw_arguments
    if isinstance(raw_arguments, str):
        try:
            parsed = json.loads(raw_arguments)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _require_verified_a2a_security_context(
    payload: dict[str, Any],
    *,
    delegation_key: bytes | None,
    provenance_key: bytes | None,
    delegation_audience: str,
    expected_delegate: str | None,
) -> A2ASecurityContext:
    try:
        security_context = extract_security_context(
            payload,
            delegation_key=delegation_key,
            provenance_key=provenance_key,
            delegation_audience=delegation_audience,
            expected_delegate=expected_delegate,
        )
    except A2AVerificationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if security_context is None:
        raise HTTPException(
            status_code=401,
            detail="A2A requests require verified tessera_security_context metadata",
        )
    return security_context


def _context_from_a2a_task(
    task: A2ATaskRequest,
    security_context: A2ASecurityContext,
) -> Context:
    context = Context()
    envelopes_by_id = {
        envelope.segment_id: envelope for envelope in security_context.segment_envelopes
    }
    for segment in task.input_segments:
        envelope = envelopes_by_id[segment.segment_id]
        context.add(
            LabeledSegment(
                content=segment.content,
                label=TrustLabel(
                    origin=envelope.origin,
                    principal=envelope.principal,
                    trust_level=envelope.trust_level,
                    nonce=f"a2a:{segment.segment_id}",
                    signature="verified-provenance-envelope",
                ),
            )
        )
    return context


def _jsonrpc_error(
    request_id: str | int | None,
    *,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        error["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": error,
    }


def _policy_for_request(base_policy: Policy, tools: list[ToolModel]) -> Policy:
    """Copy the base policy, then apply the caller's declared tool surface."""
    request_policy = Policy(
        requirements=deepcopy(base_policy.requirements),
        default_required_trust=base_policy.default_required_trust,
        backend=base_policy.backend,
        fail_closed_backend_errors=base_policy.fail_closed_backend_errors,
        base_requirements=deepcopy(base_policy.requirements),
        _human_approval_tools=set(base_policy._human_approval_tools),
    )
    for tool in tools:
        request_policy.require(tool.name, tool.required_trust)
        request_policy.request_requirements[tool.name] = ToolRequirement(
            name=tool.name,
            required_trust=tool.required_trust,
        )
    return request_policy


def _verify_identity_headers(
    *,
    request: Request,
    identity_header: str | None,
    proof_header: str | None,
    verifier: "AgentIdentityVerifier | None",
    proof_verifier: AgentProofVerifier | None,
    audience: str,
    require_identity: bool,
    require_proof: bool,
    mtls: MTLSConfig,
) -> AgentIdentity | None:
    peer_identity = _verify_transport_identity(request, mtls=mtls)
    if identity_header is None and proof_header is None:
        if not require_identity:
            return None
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=None,
                detail={"error": "missing required agent identity"},
            )
        )
        raise HTTPException(status_code=401, detail="missing required agent identity")
    if identity_header is None and proof_header is not None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROOF_VERIFY_FAILURE,
                principal=None,
                detail={"error": "agent proof provided without agent identity"},
            )
        )
        raise HTTPException(status_code=401, detail="agent proof requires agent identity")
    if verifier is None:
        error = (
            "agent proof header provided but no proof verifier configured"
            if proof_header is not None
            else "agent identity header provided but no verifier configured"
        )
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=None,
                detail={"error": error},
            )
        )
        raise HTTPException(
            status_code=400,
            detail=error,
        )

    identity = verifier.verify(identity_header, audience=audience)
    if identity is None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=None,
                detail={"audience": audience},
            )
        )
        raise HTTPException(status_code=401, detail="invalid agent identity")

    if not require_proof and proof_header is None:
        return identity
    if proof_verifier is None:
        raise HTTPException(status_code=400, detail="agent proof verifier is not configured")
    if proof_header is None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROOF_VERIFY_FAILURE,
                principal=identity.agent_id,
                detail={"error": "missing required agent proof"},
            )
        )
        raise HTTPException(status_code=401, detail="missing required agent proof")
    if identity.key_binding is None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROOF_VERIFY_FAILURE,
                principal=identity.agent_id,
                detail={"error": "agent identity token is missing proof-of-possession binding"},
            )
        )
        raise HTTPException(
            status_code=401,
            detail="agent identity token is missing proof-of-possession binding",
        )
    if not proof_verifier.verify(
        proof_header,
        identity_token=identity_header,
        expected_method=request.method,
        expected_url=str(request.url),
        expected_key_binding=identity.key_binding,
    ):
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROOF_VERIFY_FAILURE,
                principal=identity.agent_id,
                detail={"method": request.method, "url": str(request.url)},
            )
        )
        raise HTTPException(status_code=401, detail="invalid agent proof")
    if peer_identity is not None and peer_identity.agent_id != identity.agent_id:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=identity.agent_id,
                detail={
                    "error": "transport identity does not match agent identity",
                    "transport_agent_id": peer_identity.agent_id,
                    "identity_agent_id": identity.agent_id,
                },
            )
        )
        raise HTTPException(
            status_code=401,
            detail="transport identity does not match agent identity",
        )
    return identity


def _verify_transport_identity(
    request: Request,
    *,
    mtls: MTLSConfig,
) -> MTLSPeerIdentity | None:
    try:
        peer_identity = extract_peer_identity(
            scope=request.scope,
            headers=request.headers,
            trusted_proxy_hosts=mtls.trusted_proxy_hosts,
            trust_xfcc=mtls.trust_xfcc,
            allowed_trust_domains=mtls.trust_domains,
        )
    except MTLSPeerVerificationError as exc:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=None,
                detail={"error": str(exc)},
            )
        )
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if peer_identity is None and mtls.required:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.IDENTITY_VERIFY_FAILURE,
                principal=None,
                detail={"error": "missing required transport client certificate identity"},
            )
        )
        raise HTTPException(
            status_code=401,
            detail="missing required transport client certificate identity",
        )
    return peer_identity


def _verify_delegation_header(
    header: str | None,
    *,
    key: bytes | None,
    audience: str,
    expected_delegate: str | None,
) -> DelegationToken | None:
    if header is None:
        return None
    if key is None:
        raise HTTPException(
            status_code=400,
            detail="delegation header provided but no delegation key configured",
        )
    if expected_delegate is None:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.DELEGATION_VERIFY_FAILURE,
                principal=None,
                detail={"error": "delegation header provided but no agent identity configured"},
            )
        )
        raise HTTPException(
            status_code=400,
            detail="delegation header provided but no agent identity configured",
        )
    try:
        payload = json.loads(header)
        token = DelegationToken(
            subject=payload["subject"],
            delegate=payload["delegate"],
            audience=payload["audience"],
            authorized_actions=tuple(payload.get("authorized_actions", [])),
            constraints=payload.get("constraints", {}),
            session_id=payload.get("session_id", ""),
            expires_at=datetime.fromisoformat(payload["expires_at"]),
            signature=payload.get("signature", ""),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.DELEGATION_VERIFY_FAILURE,
                principal=None,
                detail={"error": str(exc)},
            )
        )
        raise HTTPException(status_code=401, detail="invalid delegation token") from exc
    if not verify_delegation(token, key, audience=audience):
        emit_event(
            SecurityEvent.now(
                kind=EventKind.DELEGATION_VERIFY_FAILURE,
                principal=token.subject,
                detail={
                    "delegate": token.delegate,
                    "audience": token.audience,
                },
            )
        )
        raise HTTPException(status_code=401, detail="invalid delegation token")
    if token.delegate != expected_delegate:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.DELEGATION_VERIFY_FAILURE,
                principal=token.subject,
                detail={
                    "delegate": token.delegate,
                    "expected_delegate": expected_delegate,
                    "audience": token.audience,
                },
            )
        )
        raise HTTPException(status_code=401, detail="delegation token bound to a different agent")
    return token


def _verify_provenance_header(
    header: str | None,
    *,
    messages: list[MessageModel],
    key: bytes | None,
) -> None:
    if header is None:
        return
    if key is None:
        raise HTTPException(
            status_code=400,
            detail="provenance header provided but no provenance key configured",
        )
    try:
        payload = json.loads(header)
        envelope_dicts = payload["envelopes"]
        manifest_dict = payload["manifest"]
        envelopes = tuple(_parse_envelope(item) for item in envelope_dicts)
        manifest = _parse_manifest(manifest_dict)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROVENANCE_VERIFY_FAILURE,
                principal=None,
                detail={"error": str(exc)},
            )
        )
        raise HTTPException(status_code=401, detail="invalid prompt provenance") from exc
    if len(envelopes) != len(messages):
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROVENANCE_VERIFY_FAILURE,
                principal=None,
                detail={"error": "envelope count does not match message count"},
            )
        )
        raise HTTPException(status_code=401, detail="invalid prompt provenance")
    for envelope, message in zip(envelopes, messages, strict=True):
        if not envelope.verify(message.content, key):
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.PROVENANCE_VERIFY_FAILURE,
                    principal=envelope.principal,
                    detail={"segment_id": envelope.segment_id},
                )
            )
            raise HTTPException(status_code=401, detail="invalid prompt provenance")
        if (
            envelope.origin != message.label.origin
            or envelope.trust_level != TrustLevel(message.label.trust_level)
            or envelope.principal != message.label.principal
        ):
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.PROVENANCE_VERIFY_FAILURE,
                    principal=envelope.principal,
                    detail={
                        "segment_id": envelope.segment_id,
                        "error": "envelope does not match message label",
                    },
                )
            )
            raise HTTPException(status_code=401, detail="invalid prompt provenance")
    if not manifest.verify(envelopes, key):
        emit_event(
            SecurityEvent.now(
                kind=EventKind.PROVENANCE_VERIFY_FAILURE,
                principal=None,
                detail={"manifest_id": manifest.manifest_id},
            )
        )
        raise HTTPException(status_code=401, detail="invalid prompt provenance")


def _parse_envelope(payload: dict[str, Any]) -> ContextSegmentEnvelope:
    return ContextSegmentEnvelope(
        segment_id=payload["segment_id"],
        origin=Origin(payload["origin"]),
        issuer=payload["issuer"],
        principal=payload["principal"],
        trust_level=TrustLevel(payload["trust_level"]),
        content_sha256=payload["content_sha256"],
        parent_ids=tuple(payload.get("parent_ids", [])),
        delegating_user=payload.get("delegating_user"),
        sensitivity=tuple(payload.get("sensitivity", [])),
        created_at=payload["created_at"],
        schema_version=payload.get("schema_version", 1),
        signature=payload.get("signature", ""),
    )


def _parse_manifest(payload: dict[str, Any]) -> PromptProvenanceManifest:
    return PromptProvenanceManifest(
        manifest_id=payload["manifest_id"],
        session_id=payload["session_id"],
        principal_set=tuple(payload.get("principal_set", [])),
        segments=tuple(
            ManifestSegmentRef(
                segment_id=segment["segment_id"],
                position=segment["position"],
                content_sha256=segment["content_sha256"],
            )
            for segment in payload.get("segments", [])
        ),
        assembled_by=payload["assembled_by"],
        assembled_at=payload["assembled_at"],
        schema_version=payload.get("schema_version", 1),
        signature=payload.get("signature", ""),
    )
