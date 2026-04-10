"""MCP interceptor labels tool outputs correctly."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tessera.delegation import DelegationToken, sign_delegation
from tessera.labels import Origin, TrustLevel
from tessera.mcp import MCPInterceptor, MCPSecurityContext
from tessera.provenance import ContextSegmentEnvelope, PromptProvenanceManifest

KEY = b"test-hmac-key-do-not-use-in-prod"


class StubClient:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[str, dict | None]] = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        return self.result


class SecurityContextClient:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[str, dict | None, dict | None]] = []

    async def call_tool(self, name, arguments=None, *, security_context=None):
        self.calls.append((name, arguments, security_context))
        return self.result


class MetadataClient:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[str, dict | None, dict | None]] = []

    async def call_tool(self, name, arguments=None, *, metadata=None):
        self.calls.append((name, arguments, metadata))
        return self.result


def _security_context() -> MCPSecurityContext:
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
        content="email bob",
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
    return MCPSecurityContext(
        delegation=delegation,
        provenance_manifest=manifest,
        segment_envelopes=(envelope,),
    )


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


@pytest.mark.asyncio
async def test_security_context_passed_to_clients_that_support_it():
    client = SecurityContextClient("rows")
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")

    await mcp.call(
        "query_database",
        {"sql": "select 1"},
        security_context=_security_context(),
    )

    assert client.calls[0][2]["delegation"]["subject"] == "user:alice@example.com"
    assert client.calls[0][2]["provenance_manifest"]["session_id"] == "ses_123"


@pytest.mark.asyncio
async def test_security_context_falls_back_to_metadata_for_metadata_aware_clients():
    client = MetadataClient("rows")
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")

    await mcp.call(
        "query_database",
        {"sql": "select 1"},
        security_context=_security_context(),
    )

    metadata = client.calls[0][2]
    assert metadata is not None
    assert metadata["tessera_security_context"]["delegation"]["subject"] == "user:alice@example.com"


@pytest.mark.asyncio
async def test_security_context_is_ignored_for_legacy_clients_without_breaking_calls():
    client = StubClient("rows")
    mcp = MCPInterceptor(client=client, key=KEY, principal="alice")

    seg = await mcp.call(
        "query_database",
        {"sql": "select 1"},
        security_context=_security_context(),
    )

    assert client.calls == [("query_database", {"sql": "select 1"})]
    assert seg.content == "rows"
