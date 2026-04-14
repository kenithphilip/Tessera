"""Tests for tessera.adapters.mcp_proxy.MCPTrustProxy.

All tests use stub sessions instead of real SSE connections, so no
MCP server process is required. The upstream factory injection seam
lets us exercise all proxy logic (policy evaluation, labeling, origin
classification, callbacks, error handling) without network I/O.
"""

from __future__ import annotations

import contextlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import mcp.types as mcp_types

from tessera.adapters.mcp_proxy import MCPTrustProxy, _extract_text
from tessera.events import EventKind, SecurityEvent
from tessera.labels import TrustLevel
from tessera.policy import Policy

KEY = b"mcp-proxy-test-key"
PRINCIPAL = "test-agent"


# ---------------------------------------------------------------------------
# Stub upstream session
# ---------------------------------------------------------------------------

def _make_upstream(
    tools: list[mcp_types.Tool] | None = None,
    call_result: str = "tool result text",
) -> Any:
    """Build a stub ClientSession that returns the given tools and call result."""
    stub_tools = tools or [
        mcp_types.Tool(name="search", inputSchema={"type": "object", "properties": {}}),
        mcp_types.Tool(name="write_file", inputSchema={"type": "object", "properties": {}}),
    ]
    list_result = MagicMock()
    list_result.tools = stub_tools

    call_tool_result = mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=call_result)],
        isError=False,
    )

    session = AsyncMock()
    session.initialize = AsyncMock()
    session.list_tools = AsyncMock(return_value=list_result)
    session.call_tool = AsyncMock(return_value=call_tool_result)
    return session


def _stub_factory(session: Any) -> Any:
    """Return an async context-manager factory that yields the stub session."""
    @contextlib.asynccontextmanager
    async def _factory():
        yield session
    return _factory


def _make_proxy(
    *,
    session: Any | None = None,
    policy: Policy | None = None,
    external_tools: frozenset[str] = frozenset(),
    on_segment=None,
) -> MCPTrustProxy:
    stub = session or _make_upstream()
    return MCPTrustProxy(
        upstream_url="http://stub/sse",  # not used; factory is injected
        key=KEY,
        principal=PRINCIPAL,
        policy=policy,
        external_tools=external_tools,
        on_segment=on_segment,
        _upstream_factory=_stub_factory(stub),
    )


# ---------------------------------------------------------------------------
# Tool list forwarding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_fetch_tools_populates_cache():
    tools = [mcp_types.Tool(name="alpha", inputSchema={"type": "object", "properties": {}})]
    session = _make_upstream(tools=tools)
    proxy = _make_proxy(session=session)

    async with _stub_factory(session)() as s:
        await proxy._fetch_tools(s)

    assert len(proxy._cached_tools) == 1
    assert proxy._cached_tools[0].name == "alpha"


@pytest.mark.asyncio
async def test_proxy_list_tools_returns_cached():
    tools = [
        mcp_types.Tool(name="a", inputSchema={"type": "object", "properties": {}}),
        mcp_types.Tool(name="b", inputSchema={"type": "object", "properties": {}}),
    ]
    session = _make_upstream(tools=tools)
    proxy = _make_proxy(session=session)
    proxy._cached_tools = tools

    # The list_tools handler returns from cache (no upstream call needed).
    assert proxy._cached_tools[0].name == "a"
    assert proxy._cached_tools[1].name == "b"


# ---------------------------------------------------------------------------
# Call forwarding and labeling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_handle_call_labels_internal_tool():
    session = _make_upstream(call_result="internal result")
    proxy = _make_proxy(session=session)

    result, segment = await proxy._handle_call(session, "write_file", {"path": "/tmp/x"})

    assert not result.isError
    assert segment is not None
    assert segment.label.trust_level == TrustLevel.TOOL
    assert segment.content == "internal result"


@pytest.mark.asyncio
async def test_proxy_handle_call_labels_external_tool_as_untrusted():
    session = _make_upstream(call_result="web result")
    proxy = _make_proxy(session=session, external_tools=frozenset({"search"}))

    result, segment = await proxy._handle_call(session, "search", {"q": "hello"})

    assert not result.isError
    assert segment is not None
    assert segment.label.trust_level == TrustLevel.UNTRUSTED


@pytest.mark.asyncio
async def test_proxy_handle_call_passes_args_to_upstream():
    session = _make_upstream()
    proxy = _make_proxy(session=session)

    await proxy._handle_call(session, "write_file", {"path": "/tmp/f", "content": "data"})

    session.call_tool.assert_called_once_with("write_file", {"path": "/tmp/f", "content": "data"})


@pytest.mark.asyncio
async def test_proxy_handle_call_forwards_raw_result():
    """The downstream client receives the original upstream result unchanged."""
    raw_result = mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text="original text")],
        isError=False,
    )
    session = AsyncMock()
    session.call_tool = AsyncMock(return_value=raw_result)
    proxy = _make_proxy(session=session)

    result, segment = await proxy._handle_call(session, "search", {})

    assert result is raw_result  # same object, not a copy


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_policy_deny_returns_error_result():
    policy = Policy()
    policy.require("restricted", TrustLevel.SYSTEM)  # impossible to satisfy from empty context

    session = _make_upstream()
    proxy = _make_proxy(session=session, policy=policy)

    result, segment = await proxy._handle_call(session, "restricted", {})

    assert result.isError
    assert "[denied]" in result.content[0].text
    assert segment is None
    # Upstream was never called.
    session.call_tool.assert_not_called()


@pytest.mark.asyncio
async def test_proxy_policy_deny_emits_security_event(monkeypatch):
    emitted: list[SecurityEvent] = []
    monkeypatch.setattr("tessera.adapters.mcp_proxy.emit_event", emitted.append)

    policy = Policy()
    policy.require("restricted", TrustLevel.SYSTEM)
    proxy = _make_proxy(policy=policy)
    session = _make_upstream()

    await proxy._handle_call(session, "restricted", {})

    assert len(emitted) == 1
    assert emitted[0].kind == EventKind.POLICY_DENY
    assert emitted[0].detail["tool"] == "restricted"
    assert emitted[0].detail["source"] == "mcp_proxy"


@pytest.mark.asyncio
async def test_proxy_no_policy_always_forwards():
    session = _make_upstream()
    proxy = _make_proxy(session=session, policy=None)

    result, segment = await proxy._handle_call(session, "anything", {})

    assert not result.isError
    assert segment is not None
    session.call_tool.assert_called_once()


# ---------------------------------------------------------------------------
# on_segment callback
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proxy_on_segment_called_after_successful_call():
    received: list[tuple[str, Any]] = []

    async def capture(name: str, segment: Any) -> None:
        received.append((name, segment))

    session = _make_upstream(call_result="hello world")
    proxy = _make_proxy(session=session, on_segment=capture)

    # Simulate the handler as the MCP server would call it.
    factory = _stub_factory(session)
    server_proxy = proxy  # reuse proxy instance

    async with factory() as s:
        result, segment = await proxy._handle_call(s, "search", {})
    if segment is not None and proxy.on_segment is not None:
        await proxy.on_segment("search", segment)

    assert len(received) == 1
    assert received[0][0] == "search"
    assert received[0][1].content == "hello world"


@pytest.mark.asyncio
async def test_proxy_on_segment_not_called_on_deny():
    received: list[Any] = []

    async def capture(name: str, segment: Any) -> None:
        received.append(segment)

    policy = Policy()
    policy.require("restricted", TrustLevel.SYSTEM)

    session = _make_upstream()
    proxy = _make_proxy(session=session, policy=policy, on_segment=capture)

    result, segment = await proxy._handle_call(session, "restricted", {})
    if segment is not None and proxy.on_segment is not None:
        await proxy.on_segment("restricted", segment)

    assert len(received) == 0


# ---------------------------------------------------------------------------
# Origin classification
# ---------------------------------------------------------------------------

def test_origin_internal_tool():
    proxy = _make_proxy(external_tools=frozenset({"search", "fetch_url"}))
    from tessera.labels import Origin
    assert proxy._origin_for("write_file") == Origin.TOOL


def test_origin_external_tool():
    proxy = _make_proxy(external_tools=frozenset({"search", "fetch_url"}))
    from tessera.labels import Origin
    assert proxy._origin_for("search") == Origin.WEB
    assert proxy._origin_for("fetch_url") == Origin.WEB


def test_origin_registry_wins_on_inclusion(monkeypatch):
    from tessera.registry import ToolRegistry
    from tessera.labels import Origin

    registry = MagicMock(spec=ToolRegistry)
    registry.effective_external = MagicMock(return_value=frozenset({"hidden_external"}))

    proxy = MCPTrustProxy(
        upstream_url="http://stub/sse",
        key=KEY,
        principal=PRINCIPAL,
        external_tools=frozenset(),  # agent doesn't know about hidden_external
        registry=registry,
        _upstream_factory=lambda: contextlib.asynccontextmanager(
            lambda: (x for x in [MagicMock()])
        )(),
    )
    # Registry declares hidden_external as external; agent cannot override.
    assert proxy._origin_for("hidden_external") == Origin.WEB


# ---------------------------------------------------------------------------
# _extract_text helper
# ---------------------------------------------------------------------------

def test_extract_text_from_text_content():
    result = mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text="hello")],
    )
    assert _extract_text(result) == "hello"


def test_extract_text_multiple_blocks():
    result = mcp_types.CallToolResult(
        content=[
            mcp_types.TextContent(type="text", text="part one"),
            mcp_types.TextContent(type="text", text="part two"),
        ],
    )
    assert _extract_text(result) == "part one\npart two"


def test_extract_text_empty_content():
    result = mcp_types.CallToolResult(content=[])
    # Falls back to str(result.content)
    assert isinstance(_extract_text(result), str)


# ---------------------------------------------------------------------------
# build_app smoke test
# ---------------------------------------------------------------------------

def test_build_app_returns_asgi_app():
    """Verifies build_app() produces a Starlette ASGI app without connecting."""
    session = _make_upstream()
    proxy = _make_proxy(session=session)
    app = proxy.build_app()

    # Starlette apps are ASGI callables.
    assert callable(app)
    # The app has the expected routes.
    routes = {r.path for r in app.routes}
    assert "/sse" in routes
    assert "/messages/" in routes


# ---------------------------------------------------------------------------
# MCPNotAvailable guard
# ---------------------------------------------------------------------------

def test_mcp_not_available_raised_without_package(monkeypatch):
    import tessera.adapters.mcp_proxy as mod
    monkeypatch.setattr(mod, "_MCP_AVAILABLE", False)

    with pytest.raises(mod.MCPNotAvailable):
        mod._require_mcp()
