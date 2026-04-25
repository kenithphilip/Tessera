"""Wave 2B-iii audit: MCP Security Score wired into tools/list path."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tessera.adapters.mcp_proxy import MCPTrustProxy
from tessera.mcp.score import SecurityScore
from tessera.mcp.tier import TierAssignment, TrustTier


_KEY = b"k" * 32


def _proxy() -> MCPTrustProxy:
    return MCPTrustProxy(
        upstream_url="mcp+ws://upstream.invalid",
        key=_KEY,
        principal="alice",
    )


def _stub_session(tools: list) -> SimpleNamespace:
    async def _list_tools():
        return SimpleNamespace(tools=tools)

    return SimpleNamespace(list_tools=_list_tools)


def test_security_score_recomputed_on_tools_list() -> None:
    proxy = _proxy()
    session = _stub_session(tools=[SimpleNamespace(name="ping")])
    asyncio.run(proxy._fetch_tools(session))
    score = proxy.last_security_score
    assert isinstance(score, SecurityScore)
    assert score.server_id == "mcp+ws://upstream.invalid"
    assert score.breakdown.tier_component == 0.0  # no manifest = COMMUNITY


def test_security_score_reflects_tier_assignment() -> None:
    proxy = _proxy()
    proxy.set_tier_assignment(
        TierAssignment(
            tier=TrustTier.ATTESTED, reason="test", verification=None
        )
    )
    session = _stub_session(tools=[SimpleNamespace(name="ping")])
    asyncio.run(proxy._fetch_tools(session))
    assert proxy.last_security_score.breakdown.tier_component == 40.0


def test_security_score_otel_attributes_exposed() -> None:
    proxy = _proxy()
    proxy.set_tier_assignment(
        TierAssignment(
            tier=TrustTier.VERIFIED, reason="test", verification=None
        )
    )
    session = _stub_session(tools=[SimpleNamespace(name="a"), SimpleNamespace(name="b")])
    asyncio.run(proxy._fetch_tools(session))
    attrs = proxy.last_security_score.to_otel_attributes()
    assert "tessera.mcp.security_score" in attrs
    assert attrs["tessera.mcp.server_id"] == "mcp+ws://upstream.invalid"
