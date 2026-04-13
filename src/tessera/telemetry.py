"""Optional OpenTelemetry instrumentation for the Tessera pipeline.

OTel is an optional dependency. If it is not installed, every function here
is a no-op. When it is installed, these hooks emit spans that together form
a provenance graph across one agent turn:

    tessera.proxy.request                 (parent)
      +-- tessera.mcp.tool_call
      +-- tessera.policy.evaluate

The proxy span is the parent; tool call and policy spans nest under it via
OTel's context propagation. Combined with any upstream LLM instrumentation
you already have, this gives you end-to-end causal tracing for every tool
call an agent emits.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from tessera.policy import Decision

try:  # pragma: no cover - exercised implicitly when otel is installed
    from opentelemetry import trace

    _tracer: Any = trace.get_tracer("tessera")
    _OTEL = True
except ImportError:  # pragma: no cover
    _tracer = None
    _OTEL = False


def _set_attribute(span: Any, key: str, value: Any) -> None:
    if value is None:
        return
    span.set_attribute(key, value)


def emit_decision(decision: "Decision", *, backend: str | None = None) -> None:
    """Emit a span for a single policy decision."""
    if not _OTEL or _tracer is None:
        return
    with _tracer.start_as_current_span("tessera.policy.evaluate") as span:
        span.set_attribute("tessera.tool", decision.tool)
        span.set_attribute("tessera.required_trust", int(decision.required_trust))
        span.set_attribute("tessera.observed_trust", int(decision.observed_trust))
        span.set_attribute("tessera.decision", str(decision.kind))
        span.set_attribute("tessera.reason", decision.reason)
        _set_attribute(span, "tessera.policy.backend", backend)
        span.set_attribute("gen_ai.tool.name", decision.tool)


def emit_tool_call(tool: str, origin: str, principal: str) -> None:
    """Emit a span for an MCP tool invocation with its labeled origin."""
    if not _OTEL or _tracer is None:
        return
    with _tracer.start_as_current_span("tessera.mcp.tool_call") as span:
        span.set_attribute("tessera.tool", tool)
        span.set_attribute("tessera.origin", origin)
        span.set_attribute("tessera.principal", principal)
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.provider.name", "tessera")
        span.set_attribute("gen_ai.tool.name", tool)
        span.set_attribute("gen_ai.tool.type", "extension")
        span.set_attribute("gen_ai.agent.name", "tessera.mcp")


@contextmanager
def proxy_request_span(
    model: str,
    message_count: int,
    *,
    operation_name: str = "chat",
    agent_name: str | None = None,
    agent_id: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    finish_reason: str | None = None,
    system: str | None = None,
    response_model: str | None = None,
) -> Iterator[None]:
    """Context manager wrapping a single proxy request.

    Tool-call and policy spans emitted inside this block become children
    via OTel's implicit context propagation.
    """
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.proxy.request") as span:
        span.set_attribute("tessera.model", model)
        span.set_attribute("tessera.message_count", message_count)
        span.set_attribute("gen_ai.operation.name", operation_name)
        span.set_attribute("gen_ai.provider.name", "tessera")
        span.set_attribute("gen_ai.request.model", model)
        _set_attribute(span, "gen_ai.agent.name", agent_name)
        _set_attribute(span, "gen_ai.agent.id", agent_id)
        _set_attribute(span, "gen_ai.system", system)
        _set_attribute(span, "gen_ai.usage.input_tokens", input_tokens)
        _set_attribute(span, "gen_ai.usage.output_tokens", output_tokens)
        _set_attribute(span, "gen_ai.response.finish_reason", finish_reason)
        _set_attribute(span, "gen_ai.response.model", response_model)
        yield


@contextmanager
def upstream_span(model: str, *, system: str | None = None) -> Iterator[None]:
    """Context manager around the upstream LLM API call.

    Emits `tessera.proxy.upstream` so incident responders see the full
    causal chain: proxy.request -> upstream -> policy.evaluate.
    """
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.proxy.upstream") as span:
        span.set_attribute("tessera.model", model)
        span.set_attribute("gen_ai.operation.name", "chat")
        span.set_attribute("gen_ai.provider.name", "tessera")
        span.set_attribute("gen_ai.request.model", model)
        _set_attribute(span, "gen_ai.system", system)
        yield


@contextmanager
def quarantine_span(
    trusted_count: int,
    untrusted_count: int,
    *,
    system: str | None = None,
    worker_model: str | None = None,
    planner_model: str | None = None,
) -> Iterator[None]:
    """Parent span for one dual-LLM quarantine run."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.run") as span:
        span.set_attribute("tessera.trusted_segments", trusted_count)
        span.set_attribute("tessera.untrusted_segments", untrusted_count)
        span.set_attribute("gen_ai.operation.name", "invoke_agent")
        span.set_attribute("gen_ai.provider.name", "tessera")
        span.set_attribute("gen_ai.agent.name", "tessera.quarantine")
        _set_attribute(span, "gen_ai.system", system)
        _set_attribute(span, "tessera.worker_model", worker_model)
        _set_attribute(span, "tessera.planner_model", planner_model)
        yield


@contextmanager
def quarantine_worker_span(*, model: str | None = None) -> Iterator[None]:
    """Child span wrapping the worker LLM call."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.worker") as span:
        _set_attribute(span, "gen_ai.request.model", model)
        yield


@contextmanager
def quarantine_planner_span(*, model: str | None = None) -> Iterator[None]:
    """Child span wrapping the planner LLM call."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.planner") as span:
        _set_attribute(span, "gen_ai.request.model", model)
        yield


def record_upstream_usage(
    *,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    finish_reason: str | None = None,
    response_model: str | None = None,
    system: str | None = None,
) -> None:
    """Set GenAI usage attributes on the current span.

    Call this after the upstream LLM response is available to attach
    token counts, finish reason, and model information to the
    enclosing proxy request span.
    """
    if not _OTEL:
        return
    span = trace.get_current_span()
    if span is None or not span.is_recording():
        return
    _set_attribute(span, "gen_ai.usage.input_tokens", input_tokens)
    _set_attribute(span, "gen_ai.usage.output_tokens", output_tokens)
    _set_attribute(span, "gen_ai.response.finish_reason", finish_reason)
    _set_attribute(span, "gen_ai.response.model", response_model)
    _set_attribute(span, "gen_ai.system", system)


def is_enabled() -> bool:
    return _OTEL
