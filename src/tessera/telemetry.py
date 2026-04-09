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


def emit_decision(decision: "Decision") -> None:
    """Emit a span for a single policy decision."""
    if not _OTEL or _tracer is None:
        return
    with _tracer.start_as_current_span("tessera.policy.evaluate") as span:
        span.set_attribute("tessera.tool", decision.tool)
        span.set_attribute("tessera.required_trust", int(decision.required_trust))
        span.set_attribute("tessera.observed_trust", int(decision.observed_trust))
        span.set_attribute("tessera.decision", str(decision.kind))
        span.set_attribute("tessera.reason", decision.reason)


def emit_tool_call(tool: str, origin: str, principal: str) -> None:
    """Emit a span for an MCP tool invocation with its labeled origin."""
    if not _OTEL or _tracer is None:
        return
    with _tracer.start_as_current_span("tessera.mcp.tool_call") as span:
        span.set_attribute("tessera.tool", tool)
        span.set_attribute("tessera.origin", origin)
        span.set_attribute("tessera.principal", principal)


@contextmanager
def proxy_request_span(model: str, message_count: int) -> Iterator[None]:
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
        yield


@contextmanager
def upstream_span(model: str) -> Iterator[None]:
    """Context manager around the upstream LLM API call.

    Emits `tessera.proxy.upstream` so incident responders see the full
    causal chain: proxy.request -> upstream -> policy.evaluate.
    """
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.proxy.upstream") as span:
        span.set_attribute("tessera.model", model)
        yield


@contextmanager
def quarantine_span(trusted_count: int, untrusted_count: int) -> Iterator[None]:
    """Parent span for one dual-LLM quarantine run."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.run") as span:
        span.set_attribute("tessera.trusted_segments", trusted_count)
        span.set_attribute("tessera.untrusted_segments", untrusted_count)
        yield


@contextmanager
def quarantine_worker_span() -> Iterator[None]:
    """Child span wrapping the worker LLM call."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.worker"):
        yield


@contextmanager
def quarantine_planner_span() -> Iterator[None]:
    """Child span wrapping the planner LLM call."""
    if not _OTEL or _tracer is None:
        yield
        return
    with _tracer.start_as_current_span("tessera.quarantine.planner"):
        yield


def is_enabled() -> bool:
    return _OTEL
