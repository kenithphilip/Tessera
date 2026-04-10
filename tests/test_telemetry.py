"""Telemetry spans emit correctly when OTel is installed.

Uses an in-memory span exporter via a session-scoped TracerProvider.
`opentelemetry.trace.get_tracer` returns a ProxyTracer that forwards to
the current global provider, so we can install the provider once at
session start and every tessera.* module picks it up without any
module reloads.
"""

from __future__ import annotations

import pytest

pytest.importorskip("opentelemetry")

from opentelemetry import trace  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)

from tessera.context import Context, make_segment  # noqa: E402
from tessera.labels import Origin, TrustLevel  # noqa: E402
from tessera.mcp import MCPInterceptor  # noqa: E402
from tessera.policy import Policy  # noqa: E402
from tessera.quarantine import QuarantinedExecutor, WorkerReport  # noqa: E402
from tessera.telemetry import proxy_request_span  # noqa: E402

KEY = b"test-hmac-key-do-not-use-in-prod"


@pytest.fixture(scope="session", autouse=True)
def _provider():
    provider = TracerProvider()
    trace.set_tracer_provider(provider)
    return provider


@pytest.fixture()
def exporter(_provider):
    exp = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exp)
    _provider.add_span_processor(processor)
    try:
        yield exp
    finally:
        processor.shutdown()


def test_policy_evaluate_emits_span_with_attributes(exporter):
    ctx = Context()
    ctx.add(make_segment("hi", Origin.USER, "alice", KEY))
    policy = Policy()
    policy.require("send_email", TrustLevel.USER)
    policy.evaluate(ctx, "send_email")

    spans = exporter.get_finished_spans()
    decision = [s for s in spans if s.name == "tessera.policy.evaluate"]
    assert len(decision) == 1
    attrs = decision[0].attributes
    assert attrs["tessera.tool"] == "send_email"
    assert attrs["tessera.decision"] == "allow"
    assert attrs["tessera.observed_trust"] == int(TrustLevel.USER)


@pytest.mark.asyncio
async def test_mcp_call_emits_tool_call_span(exporter):
    class Stub:
        async def call_tool(self, name, arguments=None):
            return "ok"

    mcp = MCPInterceptor(client=Stub(), key=b"k", principal="alice")
    await mcp.call("query_database")

    tool_spans = [
        s for s in exporter.get_finished_spans() if s.name == "tessera.mcp.tool_call"
    ]
    assert len(tool_spans) == 1
    attrs = tool_spans[0].attributes
    assert attrs["tessera.tool"] == "query_database"
    assert attrs["tessera.origin"] == "tool"
    assert attrs["tessera.principal"] == "alice"


@pytest.mark.asyncio
async def test_mcp_call_emits_genai_attrs_when_opted_in(exporter, monkeypatch):
    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "gen_ai_latest_experimental")

    class Stub:
        async def call_tool(self, name, arguments=None):
            del name, arguments
            return "ok"

    mcp = MCPInterceptor(client=Stub(), key=b"k", principal="alice")
    await mcp.call("query_database")

    tool_spans = [
        s for s in exporter.get_finished_spans() if s.name == "tessera.mcp.tool_call"
    ]
    attrs = tool_spans[0].attributes
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["gen_ai.provider.name"] == "tessera"
    assert attrs["gen_ai.tool.name"] == "query_database"
    assert attrs["gen_ai.tool.type"] == "extension"


def test_proxy_request_span_emits_genai_agent_attrs_when_opted_in(exporter, monkeypatch):
    monkeypatch.setenv("OTEL_SEMCONV_STABILITY_OPT_IN", "gen_ai_latest_experimental")

    with proxy_request_span(
        model="gpt-test",
        message_count=2,
        operation_name="invoke_agent",
        agent_name="Tessera Proxy",
        agent_id="spiffe://example.org/ns/agents/sa/proxy",
    ):
        pass

    spans = [s for s in exporter.get_finished_spans() if s.name == "tessera.proxy.request"]
    attrs = spans[0].attributes
    assert attrs["gen_ai.operation.name"] == "invoke_agent"
    assert attrs["gen_ai.provider.name"] == "tessera"
    assert attrs["gen_ai.request.model"] == "gpt-test"
    assert attrs["gen_ai.agent.name"] == "Tessera Proxy"
    assert attrs["gen_ai.agent.id"] == "spiffe://example.org/ns/agents/sa/proxy"


@pytest.mark.asyncio
async def test_quarantine_run_emits_nested_spans(exporter):
    ctx = Context()
    ctx.add(make_segment("hi", Origin.USER, "alice", KEY))
    ctx.add(make_segment("scraped", Origin.WEB, "alice", KEY))

    async def planner(trusted, report):
        return {"ok": True}

    async def worker(untrusted):
        return WorkerReport(entities=["x"])

    executor = QuarantinedExecutor(planner=planner, worker=worker)
    await executor.run(ctx)

    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert "tessera.quarantine.run" in spans
    assert "tessera.quarantine.worker" in spans
    assert "tessera.quarantine.planner" in spans

    run_span = spans["tessera.quarantine.run"]
    assert run_span.attributes["tessera.trusted_segments"] == 1
    assert run_span.attributes["tessera.untrusted_segments"] == 1
