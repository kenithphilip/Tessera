"""Integration test against the real `mcp` package.

Proves that the MCPInterceptor's Protocol-based client abstraction holds
up against the actual `mcp` ClientSession shape, including real
`CallToolResult` / `TextContent` objects. Skipped if the `mcp` package
is not installed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("mcp")

import mcp.types as mcp_types  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import (  # noqa: E402
    create_connected_server_and_client_session,
)

from tessera.delegation import DelegationToken, sign_delegation  # noqa: E402
from tessera.labels import Origin, TrustLevel  # noqa: E402
from tessera.mcp import MCPInterceptor, MCPSecurityContext  # noqa: E402
from tessera.provenance import (  # noqa: E402
    ContextSegmentEnvelope,
    PromptProvenanceManifest,
)
from tessera.registry import ToolRegistry  # noqa: E402

KEY = b"test-hmac-key-do-not-use-in-prod"


def _build_server() -> FastMCP:
    server = FastMCP("tessera-integration-test")

    @server.tool()
    def query_database(sql: str) -> str:
        return f"rows for: {sql}"

    @server.tool()
    def fetch_url(url: str) -> str:
        return f"<html>scraped from {url}</html>"

    return server


@pytest.mark.asyncio
async def test_real_mcp_tool_output_is_labeled_and_verifiable():
    server = _build_server()
    async with create_connected_server_and_client_session(server) as session:
        mcp = MCPInterceptor(client=session, key=KEY, principal="alice")
        segment = await mcp.call("query_database", {"sql": "select 1"})

    assert segment.label.origin == Origin.TOOL
    assert segment.label.trust_level == TrustLevel.TOOL
    assert "rows for: select 1" in segment.content
    assert segment.verify(KEY)


@pytest.mark.asyncio
async def test_real_mcp_image_content_does_not_leak_base64():
    """Binary content must be marker-ified, not passed as raw base64.

    Dumping base64 into the context would blow the token budget and
    hand attackers a side channel for smuggling data through vision
    inputs.
    """
    server = FastMCP("tessera-integration-test")

    fake_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAAA1BMVEX/AAAZ4gk3AAAAAXRSTlN/gFy0ywAAAApJREFUeJxjYgAAAAYAAzY3fKgAAAAASUVORK5CYII="

    @server.tool()
    def render_chart() -> mcp_types.ImageContent:
        return mcp_types.ImageContent(
            type="image",
            mimeType="image/png",
            data=fake_png_b64,
        )

    async with create_connected_server_and_client_session(server) as session:
        mcp = MCPInterceptor(client=session, key=KEY, principal="alice")
        segment = await mcp.call("render_chart")

    assert "binary content" in segment.content
    assert "mime=image/png" in segment.content
    assert fake_png_b64 not in segment.content
    assert segment.verify(KEY)


@pytest.mark.asyncio
async def test_real_mcp_external_tool_labeled_untrusted_via_registry():
    server = _build_server()
    registry = ToolRegistry(external_tools=frozenset({"fetch_url"}))
    async with create_connected_server_and_client_session(server) as session:
        mcp = MCPInterceptor(
            client=session,
            key=KEY,
            principal="alice",
            registry=registry,
        )
        segment = await mcp.call("fetch_url", {"url": "https://example.com"})

    assert segment.label.origin == Origin.WEB
    assert segment.label.trust_level == TrustLevel.UNTRUSTED
    assert "scraped from https://example.com" in segment.content
    assert segment.verify(KEY)


@pytest.mark.asyncio
async def test_real_mcp_session_still_works_when_security_context_is_supplied():
    server = _build_server()
    delegation = sign_delegation(
        DelegationToken(
            subject="user:alice@example.com",
            delegate="spiffe://example.org/ns/assistants/agent/researcher/i/1234",
            audience="proxy://tessera",
            authorized_actions=("query_database",),
            constraints={},
            session_id="ses_123",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        ),
        KEY,
    )
    envelope = ContextSegmentEnvelope.create(
        content="select 1",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.USER,
        key=KEY,
    )
    manifest = PromptProvenanceManifest.assemble(
        [envelope],
        assembled_by="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
        session_id="ses_123",
    )
    security_context = MCPSecurityContext(
        delegation=delegation,
        provenance_manifest=manifest,
        segment_envelopes=(envelope,),
    )

    async with create_connected_server_and_client_session(server) as session:
        mcp = MCPInterceptor(client=session, key=KEY, principal="alice")
        segment = await mcp.call(
            "query_database",
            {"sql": "select 1"},
            security_context=security_context,
        )

    assert segment.label.origin == Origin.TOOL
    assert "rows for: select 1" in segment.content
