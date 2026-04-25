"""Wave 2C audit: RFC 8707 wiring inside MCPTrustProxy."""

from __future__ import annotations

import pytest

from tessera.adapters.mcp_proxy import MCPTrustProxy
from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)


_KEY = b"k" * 32


@pytest.fixture(autouse=True)
def _capture() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


def _proxy(**kwargs) -> MCPTrustProxy:
    return MCPTrustProxy(
        upstream_url="mcp+ws://upstream.invalid",
        key=_KEY,
        principal="alice",
        **kwargs,
    )


# --- enforce_inbound_audience -----------------------------------------------


def test_enforce_inbound_audience_passes_when_aud_matches() -> None:
    proxy = _proxy(inbound_token_audience="https://mesh.invalid/api")
    assert proxy.enforce_inbound_audience("https://mesh.invalid/api") is True


def test_enforce_inbound_audience_fails_on_mismatch(_capture) -> None:
    proxy = _proxy(inbound_token_audience="https://mesh.invalid/api")
    assert proxy.enforce_inbound_audience("https://other.invalid") is False
    events = [
        e for e in _capture if e.kind == EventKind.MCP_TOKEN_AUDIENCE_MISMATCH
    ]
    assert len(events) == 1


def test_enforce_inbound_audience_skips_when_unconfigured() -> None:
    """When no inbound audience is configured, the check is opt-in
    and short-circuits to True so existing deployments don't break."""
    proxy = _proxy()  # inbound_token_audience=None
    assert proxy.enforce_inbound_audience("anything") is True


# --- upstream_token_request -------------------------------------------------


def test_upstream_token_request_includes_resource() -> None:
    proxy = _proxy(upstream_resource_indicator="https://upstream.invalid/mcp")
    body = proxy.upstream_token_request(scope="mcp.tools.invoke")
    assert body["resource"] == "https://upstream.invalid/mcp"
    assert body["scope"] == "mcp.tools.invoke"


def test_upstream_token_request_raises_when_unconfigured() -> None:
    proxy = _proxy()  # upstream_resource_indicator=None
    with pytest.raises(ValueError, match="resource"):
        proxy.upstream_token_request()


# --- reject_passthrough -----------------------------------------------------


def test_reject_passthrough_when_tokens_match(_capture) -> None:
    proxy = _proxy()
    assert (
        proxy.reject_passthrough(
            inbound_token="tok-abc", upstream_token="tok-abc"
        )
        is False
    )
    events = [
        e for e in _capture if e.kind == EventKind.MCP_TOKEN_AUDIENCE_MISMATCH
    ]
    assert any(e.detail.get("violation") == "token_passthrough" for e in events)


def test_passthrough_check_passes_when_tokens_differ() -> None:
    proxy = _proxy()
    assert (
        proxy.reject_passthrough(inbound_token="A", upstream_token="B")
        is True
    )
