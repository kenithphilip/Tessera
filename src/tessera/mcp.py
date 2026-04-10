"""MCP interceptor that auto-labels tool outputs.

Model Context Protocol tool calls return content that the agent then feeds
back into the model. Without Tessera, that content is trust-laundered: a
`web_search` result flows into the context window with no signal that it's
attacker-controllable. This interceptor fixes that by wrapping an MCP client
and labeling every tool result before it ever reaches the model.

The wrapper is Protocol-based so it works with any MCP client: the real one,
a stub for tests, or a future reimplementation. No hard dependency on the
`mcp` package.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol

from tessera.context import LabeledSegment, make_segment
from tessera.delegation import DelegationToken
from tessera.labels import Origin, TrustLevel
from tessera.provenance import ContextSegmentEnvelope, PromptProvenanceManifest
from tessera.registry import ToolRegistry
from tessera.telemetry import emit_tool_call


class MCPClient(Protocol):
    """Minimal surface this interceptor needs from an MCP client.

    A real `mcp` ClientSession satisfies this shape. Stubs can too.
    """

    async def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> Any: ...


# Signature of a result extractor. MCP results come in a few shapes depending
# on the client version; extractors normalize to plain text.
ResultExtractor = Callable[[Any], str]


@dataclass(frozen=True)
class MCPSecurityContext:
    """Optional provenance and delegation metadata for one MCP call.

    This is the carriage object Tessera uses when an MCP client supports
    metadata-aware or security-context-aware tool invocation. Legacy MCP
    clients can ignore it and still work through the fallback path.
    """

    delegation: DelegationToken | None = None
    provenance_manifest: PromptProvenanceManifest | None = None
    segment_envelopes: tuple[ContextSegmentEnvelope, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "delegation": None if self.delegation is None else _delegation_dict(self.delegation),
            "provenance_manifest": (
                None
                if self.provenance_manifest is None
                else self.provenance_manifest.to_dict()
            ),
            "segment_envelopes": [
                envelope.to_dict() for envelope in self.segment_envelopes
            ],
        }


def _default_extract(result: Any) -> str:
    """Best-effort extraction of text from an MCP tool result.

    Binary content (ImageContent, AudioContent) is NOT passed through
    as text. Dumping base64 into the context window would both blow
    the token budget and hand attackers a channel to smuggle data
    through the model's vision. Instead we emit a structured marker
    like `[binary content: mime=image/png, bytes=1234]` and let the
    caller decide how to surface it to the agent.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, (list, tuple)):
        return "\n".join(_default_extract(item) for item in result)

    # Check for binary content before .text extraction. The real mcp
    # ImageContent type has .type == "image" and carries .data/.mimeType.
    mime = getattr(result, "mimeType", None) or getattr(result, "mime_type", None)
    data = getattr(result, "data", None)
    if mime is not None and data is not None:
        return f"[binary content: mime={mime}, bytes={len(data)}]"

    text = getattr(result, "text", None)
    if text is not None:
        return str(text)

    if isinstance(result, dict):
        if "mimeType" in result and "data" in result:
            return (
                f"[binary content: mime={result['mimeType']}, "
                f"bytes={len(result['data'])}]"
            )
        if "text" in result:
            return str(result["text"])
        if "content" in result:
            return _default_extract(result["content"])

    content = getattr(result, "content", None)
    if content is not None:
        return _default_extract(content)
    return str(result)


@dataclass
class MCPInterceptor:
    """Wrap an MCP client and label every tool result.

    Tools flagged external by either the org-level `registry` or the
    agent-local `external_tools` set are labeled `Origin.WEB` at
    `TrustLevel.UNTRUSTED`. Every other tool is labeled `Origin.TOOL` at
    `TrustLevel.TOOL`. The registry always wins on inclusion: an agent
    cannot drop a tool that the org marks as external. Override per-call
    with `origin_override` if a specific invocation should be treated
    differently.
    """

    client: MCPClient
    key: bytes
    principal: str
    external_tools: set[str] = field(default_factory=set)
    registry: ToolRegistry | None = None
    extract: ResultExtractor = _default_extract

    async def call(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        origin_override: Origin | None = None,
        security_context: MCPSecurityContext | None = None,
    ) -> LabeledSegment:
        """Invoke an MCP tool and return a signed, labeled segment."""
        raw = await _call_tool_with_security_context(
            self.client,
            name,
            arguments,
            security_context,
        )
        content = self.extract(raw)
        origin = origin_override or self._origin_for(name)
        trust = (
            TrustLevel.UNTRUSTED
            if origin in (Origin.WEB, Origin.MEMORY)
            else TrustLevel.TOOL
        )
        emit_tool_call(tool=name, origin=str(origin), principal=self.principal)
        return make_segment(
            content=content,
            origin=origin,
            principal=self.principal,
            key=self.key,
            trust_level=trust,
        )

    def _origin_for(self, tool_name: str) -> Origin:
        effective = (
            self.registry.effective_external(self.external_tools)
            if self.registry is not None
            else frozenset(self.external_tools)
        )
        return Origin.WEB if tool_name in effective else Origin.TOOL


def _delegation_dict(token: DelegationToken) -> dict[str, object]:
    return {
        "subject": token.subject,
        "delegate": token.delegate,
        "audience": token.audience,
        "authorized_actions": list(token.authorized_actions),
        "constraints": token.constraints,
        "session_id": token.session_id,
        "expires_at": token.expires_at.isoformat(),
        "signature": token.signature,
    }


async def _call_tool_with_security_context(
    client: MCPClient,
    name: str,
    arguments: dict[str, Any] | None,
    security_context: MCPSecurityContext | None,
) -> Any:
    """Call the MCP client with the richest supported security carriage.

    Preference order:
    1. explicit `security_context=...`
    2. generic `metadata={"tessera_security_context": ...}`
    3. legacy `(name, arguments)` only
    """
    if security_context is None:
        return await client.call_tool(name, arguments)

    call_tool = client.call_tool
    signature = inspect.signature(call_tool)
    parameters = signature.parameters
    accepts_kwargs = any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )
    if "security_context" in parameters or accepts_kwargs:
        return await call_tool(
            name,
            arguments,
            security_context=security_context.to_dict(),
        )
    if "metadata" in parameters or accepts_kwargs:
        return await call_tool(
            name,
            arguments,
            metadata={"tessera_security_context": security_context.to_dict()},
        )
    return await call_tool(name, arguments)


# Convenience async type so callers can annotate their own wrappers cleanly.
CallTool = Callable[
    [str, dict[str, Any] | None, Origin | None, MCPSecurityContext | None],
    Awaitable[LabeledSegment],
]
