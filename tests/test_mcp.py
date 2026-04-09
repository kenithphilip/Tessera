"""MCP interceptor labels tool outputs correctly."""

import pytest

from tessera.labels import Origin, TrustLevel
from tessera.mcp import MCPInterceptor

KEY = b"test-hmac-key-do-not-use-in-prod"


class StubClient:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[str, dict | None]] = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        return self.result


@pytest.mark.asyncio
async def test_internal_tool_labeled_as_trusted_tool_output():
    client = StubClient("row1,row2,row3")
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")
    seg = await mcp.call("query_database", {"sql": "select 1"})
    assert seg.label.origin == Origin.TOOL
    assert seg.label.trust_level == TrustLevel.TOOL
    assert seg.verify(KEY)
    assert seg.content == "row1,row2,row3"


@pytest.mark.asyncio
async def test_external_fetcher_labeled_as_untrusted_web():
    client = StubClient({"text": "<html>scraped</html>"})
    mcp = MCPInterceptor(
        client=client,
        key=KEY,
        principal="alice",
        external_tools={"fetch_url"},
    )
    seg = await mcp.call("fetch_url", {"url": "https://evil.example"})
    assert seg.label.origin == Origin.WEB
    assert seg.label.trust_level == TrustLevel.UNTRUSTED
    assert seg.verify(KEY)


@pytest.mark.asyncio
async def test_origin_override_takes_precedence():
    client = StubClient("some stuff")
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")
    seg = await mcp.call("query_database", origin_override=Origin.WEB)
    assert seg.label.origin == Origin.WEB
    assert seg.label.trust_level == TrustLevel.UNTRUSTED


@pytest.mark.asyncio
async def test_list_result_joined_into_single_segment():
    client = StubClient([{"text": "alpha"}, {"text": "beta"}])
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")
    seg = await mcp.call("query_database")
    assert seg.content == "alpha\nbeta"
