"""Transparent MCP sidecar proxy with Tessera trust labeling.

An MCPTrustProxy sits between any MCP client and a real MCP server:

    MCP Client  ->  MCPTrustProxy (SSE server)  ->  real MCP server

The proxy is protocol-transparent: the downstream client sees a normal
MCP server and receives normal MCP responses. Tessera's work happens
on the side:

1. Every tool call is evaluated against the configured Policy (optional).
   Denied calls return an MCP error response immediately.
2. Every successful tool response is labeled with a signed TrustLabel
   (same logic as MCPInterceptor) and passed to an optional callback.

The proxy exposes two transport modes:

- ``build_app()`` -- Starlette ASGI app with SSE transport. Mount it
  under uvicorn or compose with an existing FastAPI app.
- ``run_stdio()`` -- stdio-to-SSE proxy for local use (e.g. when a
  local MCP client expects stdio but Tessera is fronting a remote SSE
  server).

Usage::

    from tessera.adapters.mcp_proxy import MCPTrustProxy
    from tessera.policy import Policy
    import uvicorn

    proxy = MCPTrustProxy(
        upstream_url="http://localhost:3000/sse",
        key=b"signing-key",
        principal="alice",
        external_tools=frozenset({"web_search"}),
    )
    uvicorn.run(proxy.build_app(), host="0.0.0.0", port=8080)

Source attribution: transparent proxy pattern from Agent Governance
Toolkit (mcp_proxy.py in the reference implementation).
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable, Awaitable
from dataclasses import dataclass, field
from typing import Any

try:
    import anyio
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client
    from mcp.server import Server
    from mcp.server.sse import SseServerTransport
    import mcp.types as mcp_types
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

from tessera.context import Context, LabeledSegment, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.registry import ToolRegistry
from tessera.telemetry import emit_tool_call


class MCPNotAvailable(RuntimeError):
    """Raised when the mcp package or starlette is not installed."""


# Signature of the labeled-segment callback.
OnSegmentFn = Callable[[str, LabeledSegment], Awaitable[None]]

# Factory that produces an async context manager yielding a ClientSession.
# The default uses sse_client; tests inject a stub.
UpstreamFactory = Callable[[], Any]  # () -> AsyncContextManager[ClientSession]


def _require_mcp() -> None:
    if not _MCP_AVAILABLE:
        raise MCPNotAvailable(
            "mcp and starlette are required for MCPTrustProxy. "
            "Install with: pip install tessera[mcp]"
        )


@dataclass
class MCPTrustProxy:
    """Transparent MCP sidecar proxy with Tessera trust labeling.

    Args:
        upstream_url: SSE endpoint of the real MCP server.
        key: HMAC signing key for TrustLabel generation.
        principal: Principal name for context segments.
        policy: Optional policy to evaluate tool calls against.
            Denied calls return an MCP error and are never forwarded.
        external_tools: Tool names to label as WEB/UNTRUSTED.
            All others are labeled TOOL trust.
        registry: Optional org-level ToolRegistry; wins on inclusion.
        on_segment: Optional async callback invoked with
            (tool_name, LabeledSegment) after each successful call.
        _upstream_factory: Override the upstream connection factory.
            Used for testing. Defaults to an sse_client-based factory.
    """

    upstream_url: str
    key: bytes
    principal: str
    policy: Policy | None = None
    external_tools: frozenset[str] = frozenset()
    registry: ToolRegistry | None = None
    on_segment: OnSegmentFn | None = None
    _upstream_factory: UpstreamFactory | None = None

    # Populated after connecting to upstream.
    _cached_tools: list[Any] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        _require_mcp()

    # ------------------------------------------------------------------
    # Upstream connection
    # ------------------------------------------------------------------

    def _make_upstream_factory(self) -> UpstreamFactory:
        if self._upstream_factory is not None:
            return self._upstream_factory
        url = self.upstream_url

        @contextlib.asynccontextmanager
        async def _factory() -> AsyncIterator[ClientSession]:
            async with sse_client(url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    yield session

        return _factory

    # ------------------------------------------------------------------
    # Core proxy logic (testable without transport)
    # ------------------------------------------------------------------

    def _origin_for(self, tool_name: str) -> Origin:
        """Classify a tool name as WEB (external) or TOOL (internal)."""
        effective = (
            self.registry.effective_external(self.external_tools)
            if self.registry is not None
            else frozenset(self.external_tools)
        )
        return Origin.WEB if tool_name in effective else Origin.TOOL

    async def _handle_call(
        self,
        session: Any,  # ClientSession
        name: str,
        arguments: dict[str, Any] | None,
    ) -> tuple[mcp_types.CallToolResult, LabeledSegment | None]:
        """Evaluate policy, call upstream, label result.

        Returns a tuple of (CallToolResult to send downstream, LabeledSegment or None).
        The CallToolResult is unchanged from upstream on success. On policy deny,
        a synthetic error result is returned and the LabeledSegment is None.
        """
        # Policy gate: build a synthetic context using the tool's effective trust
        # level so that trust requirements can gate calls meaningfully. An
        # external (WEB) tool creates an UNTRUSTED context; an internal tool
        # creates a TOOL-trust context. An empty context would default to SYSTEM
        # and make the policy gate a no-op.
        if self.policy is not None:
            origin = self._origin_for(name)
            tool_trust = TrustLevel.UNTRUSTED if origin in (Origin.WEB, Origin.MEMORY) else TrustLevel.TOOL
            ctx = Context()
            ctx.add(make_segment(
                content=f"tool:{name}",
                origin=origin,
                principal=self.principal,
                key=self.key,
                trust_level=tool_trust,
            ))
            decision = self.policy.evaluate(ctx, name)
            if not decision.allowed:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.POLICY_DENY,
                        principal=self.principal,
                        detail={"tool": name, "reason": decision.reason, "source": "mcp_proxy"},
                    )
                )
                error_result = mcp_types.CallToolResult(
                    content=[mcp_types.TextContent(type="text", text=f"[denied] {decision.reason}")],
                    isError=True,
                )
                return error_result, None

        # Forward to upstream.
        upstream_result: mcp_types.CallToolResult = await session.call_tool(name, arguments)

        # Label the result.
        origin = self._origin_for(name)
        trust = TrustLevel.UNTRUSTED if origin in (Origin.WEB, Origin.MEMORY) else TrustLevel.TOOL
        text = _extract_text(upstream_result)
        segment = make_segment(
            content=text,
            origin=origin,
            principal=self.principal,
            key=self.key,
            trust_level=trust,
        )
        emit_tool_call(tool=name, origin=str(origin), principal=self.principal)
        return upstream_result, segment

    # ------------------------------------------------------------------
    # Tool list management
    # ------------------------------------------------------------------

    async def _fetch_tools(self, session: Any) -> None:
        result = await session.list_tools()
        self._cached_tools = result.tools

    # ------------------------------------------------------------------
    # Server construction
    # ------------------------------------------------------------------

    def _build_mcp_server(self, factory: UpstreamFactory) -> Any:
        """Build the low-level MCP Server with list_tools and call_tool handlers."""
        server = Server("tessera-mcp-proxy")
        proxy = self  # capture for closures

        @server.list_tools()
        async def list_tools() -> list[mcp_types.Tool]:
            return proxy._cached_tools

        @server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any] | None = None) -> mcp_types.CallToolResult:
            async with factory() as session:
                result, segment = await proxy._handle_call(session, name, arguments)
            if segment is not None and proxy.on_segment is not None:
                await proxy.on_segment(name, segment)
            return result

        return server

    # ------------------------------------------------------------------
    # Public: SSE ASGI app
    # ------------------------------------------------------------------

    def build_app(self) -> Any:
        """Build a Starlette ASGI app that speaks MCP over SSE.

        The app exposes two routes:
        - GET  /sse      -- SSE stream for downstream MCP clients
        - POST /messages -- message handler for downstream MCP clients

        Upstream tool discovery happens in the Starlette lifespan.
        """
        _require_mcp()
        factory = self._make_upstream_factory()
        server = self._build_mcp_server(factory)
        sse_transport = SseServerTransport("/messages/")
        proxy = self

        @contextlib.asynccontextmanager
        async def lifespan(app: Any) -> AsyncIterator[None]:
            # Fetch tool list once at startup.
            async with factory() as session:
                await proxy._fetch_tools(session)
            yield

        async def handle_sse(scope: Any, receive: Any, send: Any) -> None:
            async with sse_transport.connect_sse(scope, receive, send) as (read, write):
                await server.run(
                    read,
                    write,
                    server.create_initialization_options(),
                )

        async def handle_messages(scope: Any, receive: Any, send: Any) -> None:
            await sse_transport.handle_post_message(scope, receive, send)

        return Starlette(
            lifespan=lifespan,
            routes=[
                Route("/sse", handle_sse),
                Route("/messages/", handle_messages, methods=["POST"]),
            ],
        )

    # ------------------------------------------------------------------
    # Public: stdio proxy
    # ------------------------------------------------------------------

    async def run_stdio(self) -> None:
        """Run as a stdio MCP server.

        Reads from stdin, writes to stdout. Connects to the upstream SSE
        server on demand (per tool call). Useful when a local MCP client
        expects stdio but Tessera is fronting a remote SSE server.

        Start with:
            asyncio.run(proxy.run_stdio())
        """
        _require_mcp()
        from mcp.server.stdio import stdio_server

        factory = self._make_upstream_factory()
        server = self._build_mcp_server(factory)

        async with factory() as session:
            await self._fetch_tools(session)

        async with stdio_server() as (read, write):
            await server.run(
                read,
                write,
                server.create_initialization_options(),
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_text(result: mcp_types.CallToolResult) -> str:
    """Extract plain text from a CallToolResult for labeling."""
    parts: list[str] = []
    for block in result.content:
        if hasattr(block, "text"):
            parts.append(block.text)
        elif isinstance(block, dict) and "text" in block:
            parts.append(block["text"])
    return "\n".join(parts) if parts else str(result.content)
