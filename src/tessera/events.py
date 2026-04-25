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
from collections import Counter, deque
from queue import Empty, Full, Queue
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from threading import Event, Lock, Thread
from typing import Any, Callable


class EventKind(StrEnum):
    """Categories of security event."""

    POLICY_DENY = "policy_deny"
    WORKER_SCHEMA_VIOLATION = "worker_schema_violation"
    LABEL_VERIFY_FAILURE = "label_verify_failure"
    SECRET_REDACTED = "secret_redacted"
    IDENTITY_VERIFY_FAILURE = "identity_verify_failure"
    PROOF_VERIFY_FAILURE = "proof_verify_failure"
    PROVENANCE_VERIFY_FAILURE = "provenance_verify_failure"
    DELEGATION_VERIFY_FAILURE = "delegation_verify_failure"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    HUMAN_APPROVAL_RESOLVED = "human_approval_resolved"
    SESSION_EXPIRED = "session_expired"
    CONTENT_INJECTION_DETECTED = "content_injection_detected"
    GUARDRAIL_DECISION = "guardrail_decision"

    # v0.12 Wave 1B-v additions: argument-level provenance telemetry.
    # Emitted from tessera.policy (critical_args enforcement) and
    # tessera.taint (label lifecycle).
    LABEL_JOIN = "label.join"
    LABEL_DECLASSIFY = "label.declassify"
    LABEL_RECOVERY_MATCH = "label.recovery.match"
    LABEL_RECOVERY_FALLBACK_OVERTAINT = "label.recovery.fallback_overtaint"
    CRITICAL_ARGS_DENY = "critical_args.deny"

    # v0.12 Wave 1C-ii additions: Action Critic telemetry.
    # Emitted from tessera.action_critic skeleton; populated in
    # Phase 2 wave 2A with real backend calls.
    CRITIC_ALLOW = "critic.allow"
    CRITIC_DENY = "critic.deny"
    CRITIC_APPROVAL_REQUIRED = "critic.approval_required"
    CRITIC_TIMEOUT = "critic.timeout"
    CRITIC_VALIDATION_FAILURE = "critic.validation_failure"
    CRITIC_INJECTION_SUSPECT = "critic.injection_suspect"

    # v0.12 / Phase 2 MCP signature + drift telemetry. Schema
    # defined now so Phase 2 waves can emit without a second
    # enum extension.
    MCP_MANIFEST_SIG_INVALID = "mcp.manifest.sig_invalid"
    MCP_TOKEN_AUDIENCE_MISMATCH = "mcp.token.audience_mismatch"
    MCP_DRIFT_SHAPE = "mcp.drift.shape"
    MCP_DRIFT_LATENCY = "mcp.drift.latency"
    MCP_DRIFT_DISTRIBUTION = "mcp.drift.distribution"

    # v0.12 migration telemetry (claim_provenance to worker.recovery).
    CLAIM_PROVENANCE_FAIL = "claim_provenance.fail"
    # v0.12 delegation exec telemetry (RFC 8707 + per-MCP audience).
    DELEGATION_EXEC = "delegation.exec"

    # Wave 3B-i: Tier 1 (Solo) runtime isolation violations.
    # RUNTIME_EGRESS_DENY fires when a patched HTTP call targets a host
    # not in the EgressAllowlist. RUNTIME_FS_DENY fires when open() is
    # called in a write mode against a path outside FilesystemGuard's
    # allowed-write prefixes.
    RUNTIME_EGRESS_DENY = "runtime.egress_deny"
    RUNTIME_FS_DENY = "runtime.fs_deny"


@dataclass(frozen=True)
class SecurityEvent:
    """One structured security event."""

    kind: EventKind
    principal: str
    detail: dict[str, Any]
    timestamp: str  # ISO-8601 UTC
    correlation_id: str | None = None
    trace_id: str | None = None

    @classmethod
    def now(
        cls,
        kind: EventKind,
        principal: str | None,
        detail: dict[str, Any],
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> "SecurityEvent":
        resolved_trace = trace_id
        if resolved_trace is None:
            try:
                from opentelemetry import trace

                span = trace.get_current_span()
                ctx = span.get_span_context()
                if ctx and ctx.trace_id:
                    resolved_trace = format(ctx.trace_id, "032x")
            except ImportError:
                pass
        return cls(
            kind=kind,
            principal=principal or "unknown",
            detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
            correlation_id=correlation_id,
            trace_id=resolved_trace,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": str(self.kind),
            "principal": self.principal,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }
        if self.correlation_id is not None:
            d["correlation_id"] = self.correlation_id
        if self.trace_id is not None:
            d["trace_id"] = self.trace_id
        return d


EventSink = Callable[[SecurityEvent], None]

_sinks: list[EventSink] = []
_sinks_lock = Lock()


def register_sink(sink: EventSink) -> None:
    """Add a sink to the global emission list."""
    with _sinks_lock:
        _sinks.append(sink)


def unregister_sink(sink: EventSink) -> None:
    """Remove a sink. Silently ignores sinks that were never registered."""
    with _sinks_lock:
        try:
            _sinks.remove(sink)
        except ValueError:
            pass


def clear_sinks() -> None:
    """Remove all sinks. Intended for tests."""
    with _sinks_lock:
        _sinks.clear()


def emit(event: SecurityEvent) -> None:
    """Fan out an event to every registered sink.

    Sink exceptions are swallowed so a broken observability path cannot
    take down the security path. Buggy sinks surface via their own
    logging, not by breaking the caller.
    """
    with _sinks_lock:
        sinks = tuple(_sinks)
    for sink in sinks:
        try:
            sink(event)
        except Exception:  # noqa: BLE001 - intentional swallow
            pass


def stdout_sink(event: SecurityEvent) -> None:
    """Write the event as a JSON line to stdout."""
    sys.stdout.write(json.dumps(event.to_dict(), default=str) + "\n")
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
            "tessera.detail": json.dumps(event.detail, default=str),
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


class AsyncWebhookSink:
    """Bounded asynchronous webhook sink.

    Events are queued and sent from a background worker thread so slow SIEM
    receivers do not block the security path.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 5.0,
        max_queue: int = 1024,
        poll_interval: float = 0.05,
        client_factory: Any = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self._queue: Queue[dict[str, Any]] = Queue(maxsize=max_queue)
        self._poll_interval = poll_interval
        self._client_factory = client_factory
        self._closed = Event()
        self._lock = Lock()
        self._dropped_events = 0
        self._thread = Thread(target=self._run, name="tessera-webhook-sink", daemon=True)
        self._thread.start()

    @property
    def dropped_events(self) -> int:
        with self._lock:
            return self._dropped_events

    def __call__(self, event: SecurityEvent) -> None:
        payload = event.to_dict()
        try:
            self._queue.put_nowait(payload)
        except Full:
            with self._lock:
                self._dropped_events += 1

    def close(self, *, drain: bool = True, timeout: float | None = None) -> None:
        self._closed.set()
        if drain:
            self._queue.join()
        self._thread.join(timeout)

    def stats(self) -> dict[str, int]:
        return {
            "queued_events": self._queue.qsize(),
            "dropped_events": self.dropped_events,
        }

    def _run(self) -> None:
        import httpx

        factory = self._client_factory or httpx.Client
        with factory(timeout=self.timeout) as client:
            while True:
                try:
                    payload = self._queue.get(timeout=self._poll_interval)
                except Empty:
                    if self._closed.is_set():
                        return
                    continue
                try:
                    client.post(self.url, json=payload).raise_for_status()
                except Exception:  # noqa: BLE001 - best-effort delivery
                    pass
                finally:
                    self._queue.task_done()
                if self._closed.is_set() and self._queue.empty():
                    return


def async_webhook_sink(
    url: str,
    *,
    timeout: float = 5.0,
    max_queue: int = 1024,
    poll_interval: float = 0.05,
    client_factory: Any = None,
) -> AsyncWebhookSink:
    """Factory returning a bounded async webhook sink."""

    return AsyncWebhookSink(
        url,
        timeout=timeout,
        max_queue=max_queue,
        poll_interval=poll_interval,
        client_factory=client_factory,
    )


class EvidenceBuffer:
    """Bounded in-memory evidence recorder for security events."""

    def __init__(self, max_events: int = 1024) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._lock = Lock()
        self._dropped_events = 0

    @property
    def dropped_events(self) -> int:
        with self._lock:
            return self._dropped_events

    def __call__(self, event: SecurityEvent) -> None:
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self._dropped_events += 1
            self._events.append(event.to_dict())

    def export(self) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)
            dropped = self._dropped_events
        return {
            "schema_version": "tessera.evidence.v1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "dropped_events": dropped,
            "counts_by_kind": dict(Counter(event["kind"] for event in events)),
            "events": events,
        }

    def bundle(self) -> Any:
        from tessera.evidence import EvidenceBundle

        return EvidenceBundle.from_dict(self.export())

    def sign(self, signer: Any) -> Any:
        return signer.sign(self.bundle())

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._dropped_events = 0
