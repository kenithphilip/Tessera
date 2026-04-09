"""Structured security events for incident response.

A denied tool call or a worker schema violation is a security-relevant
event, not a soft error. This module gives those events a stable shape,
a pluggable sink system, and a few built-in sinks:

    - `stdout_sink`: writes JSON lines to stdout. Useful for tailing.
    - `otel_log_sink`: attaches the event to the current OTel span.
    - `webhook_sink(url)`: factory returning a sink that POSTs to a URL.

Register sinks at startup:

    from tessera.events import register_sink, stdout_sink, otel_log_sink
    register_sink(stdout_sink)
    register_sink(otel_log_sink)

Sinks are called in registration order. A sink that raises is swallowed:
the security path must not fail closed because of an observability bug.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable


class EventKind(StrEnum):
    """Categories of security event."""

    POLICY_DENY = "policy_deny"
    WORKER_SCHEMA_VIOLATION = "worker_schema_violation"
    LABEL_VERIFY_FAILURE = "label_verify_failure"
    SECRET_REDACTED = "secret_redacted"


@dataclass(frozen=True)
class SecurityEvent:
    """One structured security event."""

    kind: EventKind
    principal: str
    detail: dict[str, Any]
    timestamp: str  # ISO-8601 UTC

    @classmethod
    def now(
        cls,
        kind: EventKind,
        principal: str | None,
        detail: dict[str, Any],
    ) -> "SecurityEvent":
        return cls(
            kind=kind,
            principal=principal or "unknown",
            detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "principal": self.principal,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


EventSink = Callable[[SecurityEvent], None]

_sinks: list[EventSink] = []


def register_sink(sink: EventSink) -> None:
    """Add a sink to the global emission list."""
    _sinks.append(sink)


def unregister_sink(sink: EventSink) -> None:
    """Remove a sink. Silently ignores sinks that were never registered."""
    try:
        _sinks.remove(sink)
    except ValueError:
        pass


def clear_sinks() -> None:
    """Remove all sinks. Intended for tests."""
    _sinks.clear()


def emit(event: SecurityEvent) -> None:
    """Fan out an event to every registered sink.

    Sink exceptions are swallowed so a broken observability path cannot
    take down the security path. Buggy sinks surface via their own
    logging, not by breaking the caller.
    """
    for sink in _sinks:
        try:
            sink(event)
        except Exception:  # noqa: BLE001 - intentional swallow
            pass


def stdout_sink(event: SecurityEvent) -> None:
    """Write the event as a JSON line to stdout."""
    sys.stdout.write(json.dumps(event.to_dict()) + "\n")
    sys.stdout.flush()


def otel_log_sink(event: SecurityEvent) -> None:
    """Attach the event to the current OTel span, if one exists."""
    try:
        from opentelemetry import trace
    except ImportError:
        return
    span = trace.get_current_span()
    if span is None:
        return
    span.add_event(
        name=f"tessera.security.{event.kind}",
        attributes={
            "tessera.principal": event.principal,
            "tessera.detail": json.dumps(event.detail),
            "tessera.timestamp": event.timestamp,
        },
    )


def webhook_sink(url: str, timeout: float = 5.0) -> EventSink:
    """Factory: return a sink that POSTs events as JSON to a URL.

    Uses a short timeout because security events are best-effort
    broadcast; a slow webhook receiver must not stall the agent loop.
    """

    def sink(event: SecurityEvent) -> None:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            client.post(url, json=event.to_dict())

    return sink
