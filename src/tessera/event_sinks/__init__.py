"""Tessera event sinks.

This subpackage groups every sink Tessera ships. The flat
``tessera.events`` module continues to export the original sinks
(``stdout_sink``, ``otel_log_sink``, ``webhook_sink``,
``AsyncWebhookSink``) for backwards compatibility; this package
re-exports them under the same names so new code can write::

    from tessera.event_sinks import prometheus_sink, stdout_sink

The Prometheus sink is the first new addition and lives in its
own module because it carries an optional dependency
(``prometheus_client``).
"""

from __future__ import annotations

from tessera.events import (
    AsyncWebhookSink,
    EventSink,
    otel_log_sink,
    register_sink,
    stdout_sink,
    unregister_sink,
    webhook_sink,
)

__all__ = [
    "AsyncWebhookSink",
    "EventSink",
    "otel_log_sink",
    "prometheus_sink",
    "register_sink",
    "stdout_sink",
    "unregister_sink",
    "webhook_sink",
]


def __getattr__(name: str):  # pragma: no cover - small import shim
    """Lazy-import optional sinks to avoid pulling prometheus_client at startup.

    Consumers that ``from tessera.event_sinks import prometheus_sink`` only
    pay the import cost when they actually use the symbol.
    """
    if name == "prometheus_sink":
        from tessera.event_sinks.prometheus_sink import prometheus_sink as _sink

        return _sink
    if name == "install_prometheus":
        from tessera.event_sinks.prometheus_sink import install as _install

        return _install
    raise AttributeError(f"module 'tessera.event_sinks' has no attribute {name!r}")
