"""Org-level tool registry enforces external-fetcher labels."""

import json

import pytest

from tessera.labels import Origin
from tessera.mcp import MCPInterceptor
from tessera.registry import ToolRegistry

KEY = b"test-hmac-key-do-not-use-in-prod"


class Stub:
    def __init__(self, result="raw"):
        self.result = result

    async def call_tool(self, name, arguments=None):
        return self.result


def test_registry_from_dict():
    reg = ToolRegistry.from_dict({"external_tools": ["fetch_url", "web_search"]})
    assert reg.is_external("fetch_url")
    assert reg.is_external("web_search")
    assert not reg.is_external("query_database")


def test_registry_from_file(tmp_path):
    path = tmp_path / "registry.json"
    path.write_text(json.dumps({"external_tools": ["fetch_url"]}))
    reg = ToolRegistry.from_file(path)
    assert reg.is_external("fetch_url")


def test_agent_cannot_drop_registry_tool():
    reg = ToolRegistry(external_tools=frozenset({"fetch_url"}))
    # Agent passes no external_tools at all; registry still wins.
    effective = reg.effective_external(set())
    assert "fetch_url" in effective


def test_agent_can_add_local_external_tools():
    reg = ToolRegistry(external_tools=frozenset({"fetch_url"}))
    effective = reg.effective_external({"internal_scraper"})
    assert effective == frozenset({"fetch_url", "internal_scraper"})


@pytest.mark.asyncio
async def test_interceptor_uses_registry_to_mark_external():
    reg = ToolRegistry(external_tools=frozenset({"fetch_url"}))
    mcp = MCPInterceptor(
        client=Stub("scraped html"),
        key=KEY,
        principal="alice",
        registry=reg,
    )
    seg = await mcp.call("fetch_url", {"url": "https://example.com"})
    assert seg.label.origin == Origin.WEB


@pytest.mark.asyncio
async def test_interceptor_without_registry_still_uses_local_set():
    mcp = MCPInterceptor(
        client=Stub("scraped"),
        key=KEY,
        principal="alice",
        external_tools={"fetch_url"},
    )
    seg = await mcp.call("fetch_url")
    assert seg.label.origin == Origin.WEB


@pytest.mark.asyncio
async def test_interceptor_with_both_registry_and_local_merges():
    reg = ToolRegistry(external_tools=frozenset({"web_search"}))
    mcp = MCPInterceptor(
        client=Stub("x"),
        key=KEY,
        principal="alice",
        external_tools={"extra_scraper"},
        registry=reg,
    )
    assert (await mcp.call("web_search")).label.origin == Origin.WEB
    assert (await mcp.call("extra_scraper")).label.origin == Origin.WEB
    assert (await mcp.call("query_database")).label.origin == Origin.TOOL
