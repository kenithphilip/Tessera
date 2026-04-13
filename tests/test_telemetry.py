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
from tessera.telemetry import (  # noqa: E402
    proxy_request_span,
    quarantine_planner_span,
    quarantine_worker_span,
    record_upstream_usage,
)

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
async def test_emit_tool_call_sets_gen_ai_tool_name(exporter):
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


def test_proxy_request_span_emits_genai_agent_attrs(exporter):
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


def test_proxy_request_span_emits_gen_ai_attributes(exporter):
    with proxy_request_span(
        model="gpt-4",
        message_count=3,
        system="openai",
        input_tokens=150,
        output_tokens=42,
        finish_reason="stop",
        response_model="gpt-4-0613",
    ):
        pass

    spans = [s for s in exporter.get_finished_spans() if s.name == "tessera.proxy.request"]
    assert len(spans) == 1
    attrs = spans[0].attributes
    assert attrs["gen_ai.system"] == "openai"
    assert attrs["gen_ai.request.model"] == "gpt-4"
    assert attrs["gen_ai.usage.input_tokens"] == 150
    assert attrs["gen_ai.usage.output_tokens"] == 42
    assert attrs["gen_ai.response.finish_reason"] == "stop"
    assert attrs["gen_ai.response.model"] == "gpt-4-0613"


def test_proxy_request_span_omits_none_gen_ai_attributes(exporter):
    with proxy_request_span(model="gpt-4", message_count=1):
        pass

    spans = [s for s in exporter.get_finished_spans() if s.name == "tessera.proxy.request"]
    attrs = spans[0].attributes
    assert attrs["gen_ai.request.model"] == "gpt-4"
    assert "gen_ai.system" not in attrs
    assert "gen_ai.usage.input_tokens" not in attrs
    assert "gen_ai.usage.output_tokens" not in attrs
    assert "gen_ai.response.finish_reason" not in attrs
    assert "gen_ai.response.model" not in attrs


def test_record_upstream_usage_sets_attributes_on_current_span(exporter):
    with proxy_request_span(model="claude-3", message_count=1):
        record_upstream_usage(
            input_tokens=200,
            output_tokens=80,
            finish_reason="tool_calls",
            response_model="claude-3-opus-20240229",
            system="anthropic",
        )

    spans = [s for s in exporter.get_finished_spans() if s.name == "tessera.proxy.request"]
    attrs = spans[0].attributes
    assert attrs["gen_ai.usage.input_tokens"] == 200
    assert attrs["gen_ai.usage.output_tokens"] == 80
    assert attrs["gen_ai.response.finish_reason"] == "tool_calls"
    assert attrs["gen_ai.response.model"] == "claude-3-opus-20240229"
    assert attrs["gen_ai.system"] == "anthropic"


def test_quarantine_spans_include_model(exporter):
    with quarantine_worker_span(model="gpt-4-worker"):
        pass
    with quarantine_planner_span(model="gpt-4-planner"):
        pass

    spans = {s.name: s for s in exporter.get_finished_spans()}
    worker = spans["tessera.quarantine.worker"]
    planner = spans["tessera.quarantine.planner"]
    assert worker.attributes["gen_ai.request.model"] == "gpt-4-worker"
    assert planner.attributes["gen_ai.request.model"] == "gpt-4-planner"


def test_emit_decision_sets_gen_ai_tool_name(exporter):
    ctx = Context()
    ctx.add(make_segment("hi", Origin.USER, "alice", KEY))
    policy = Policy()
    policy.require("send_email", TrustLevel.USER)
    policy.evaluate(ctx, "send_email")

    spans = [s for s in exporter.get_finished_spans() if s.name == "tessera.policy.evaluate"]
    attrs = spans[0].attributes
    assert attrs["gen_ai.tool.name"] == "send_email"


@pytest.mark.asyncio
async def test_quarantine_run_span_emits_gen_ai_attrs(exporter):
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
    run_span = spans["tessera.quarantine.run"]
    assert run_span.attributes["gen_ai.operation.name"] == "invoke_agent"
    assert run_span.attributes["gen_ai.provider.name"] == "tessera"
    assert run_span.attributes["gen_ai.agent.name"] == "tessera.quarantine"
