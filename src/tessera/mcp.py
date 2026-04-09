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

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol

from tessera.context import LabeledSegment, make_segment
from tessera.labels import Origin, TrustLevel
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
    ) -> LabeledSegment:
        """Invoke an MCP tool and return a signed, labeled segment."""
        raw = await self.client.call_tool(name, arguments)
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


# Convenience async type so callers can annotate their own wrappers cleanly.
CallTool = Callable[[str, dict[str, Any] | None], Awaitable[LabeledSegment]]
