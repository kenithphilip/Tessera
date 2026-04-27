"""Prometheus exporter for Tessera ``MCP_DRIFT_*`` events.

Bridges the three drift-monitor SecurityEvents to a Prometheus
metrics surface so operators can scrape MCP-server health from
the same `/metrics` endpoint that already feeds their dashboards
and alerting. The sink is deliberately scoped to the drift
events (TPS-006); other event kinds pass through untouched. A
follow-up can broaden the scope by adding more metric
declarations in this module without rewiring registration.

Optional dependency: install ``prometheus-client`` via
``pip install 'tessera[prometheus]'``. The sink raises
``PrometheusClientNotAvailable`` (a clear ``ImportError``
subclass) if the dep is missing when ``install()`` is called.

Usage::

    from tessera.event_sinks.prometheus_sink import install

    install(port=9300)            # standalone HTTP exporter on :9300
    # or:
    install()                     # sink only, scrape via your own endpoint

After installation, every ``MCP_DRIFT_SHAPE`` /
``MCP_DRIFT_LATENCY`` / ``MCP_DRIFT_DISTRIBUTION`` event emitted
through ``tessera.events.emit`` updates the appropriate
Prometheus collector. The sink ignores other event kinds.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any

from tessera.events import EventKind, SecurityEvent, register_sink

if TYPE_CHECKING:  # pragma: no cover
    from prometheus_client.registry import CollectorRegistry


class PrometheusClientNotAvailable(ImportError):
    """Raised when prometheus_client is not installed.

    The error message names the install command so consumers can act
    on it directly.
    """


# Module-level state for idempotent install. Locked so concurrent
# install() calls (e.g. from multiple threads in a test runner)
# observe a consistent picture.
_install_lock = threading.Lock()
_installed = False
_http_server_thread: threading.Thread | None = None
_metrics: dict[str, Any] = {}


def _require_prometheus_client():
    try:
        import prometheus_client  # noqa: F401
    except ImportError as exc:
        raise PrometheusClientNotAvailable(
            "prometheus_client is not installed. "
            "Install via: pip install 'tessera[prometheus]'"
        ) from exc
    return prometheus_client


def _build_metrics(registry: "CollectorRegistry | None"):
    """Construct the Prometheus collectors. Idempotent: returns the
    same collector objects on repeat calls so a re-install does not
    raise ``Duplicated timeseries in CollectorRegistry``.
    """
    pc = _require_prometheus_client()

    if _metrics:
        return _metrics

    Counter = pc.Counter
    Histogram = pc.Histogram
    Gauge = pc.Gauge
    REGISTRY = registry if registry is not None else pc.REGISTRY

    _metrics["shape_total"] = Counter(
        "tessera_mcp_drift_shape_total",
        "Number of MCP shape-drift events emitted, per server.",
        labelnames=("server_id",),
        registry=REGISTRY,
    )
    _metrics["shape_added_keys_total"] = Counter(
        "tessera_mcp_drift_shape_added_keys_total",
        "Cumulative count of newly observed response keys across "
        "MCP_DRIFT_SHAPE events, per server.",
        labelnames=("server_id",),
        registry=REGISTRY,
    )
    _metrics["shape_removed_keys_total"] = Counter(
        "tessera_mcp_drift_shape_removed_keys_total",
        "Cumulative count of dropped response keys across "
        "MCP_DRIFT_SHAPE events, per server.",
        labelnames=("server_id",),
        registry=REGISTRY,
    )
    _metrics["latency_jump_fraction"] = Histogram(
        "tessera_mcp_drift_latency_jump_fraction",
        "Distribution of latency-jump fractions across "
        "MCP_DRIFT_LATENCY events, per server. A value of 0.5 means "
        "the current p99 is 50%% above the baseline p99.",
        labelnames=("server_id",),
        buckets=(0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0),
        registry=REGISTRY,
    )
    _metrics["distribution_kl"] = Histogram(
        "tessera_mcp_drift_distribution_kl",
        "Distribution of KL divergence values across "
        "MCP_DRIFT_DISTRIBUTION events, per server and field.",
        labelnames=("server_id", "field"),
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0),
        registry=REGISTRY,
    )
    _metrics["last_seen_timestamp"] = Gauge(
        "tessera_mcp_drift_last_seen_timestamp",
        "Unix timestamp of the most recent drift event, per server "
        "and event kind.",
        labelnames=("server_id", "kind"),
        registry=REGISTRY,
    )

    return _metrics


def prometheus_sink(event: SecurityEvent) -> None:
    """``EventSink`` callable: update Prometheus metrics for drift events.

    Non-drift events are a no-op (cheap branch on ``event.kind``).
    Malformed drift events (missing ``server_id`` etc.) are
    silently dropped rather than raised: a broken observability
    path must not break the security path.
    """
    if not _metrics:
        # install() not yet called; act as a no-op so importing the
        # sink before installing doesn't break the event bus.
        return

    detail = event.detail or {}
    server_id = str(detail.get("server_id", "unknown"))
    now = time.time()

    if event.kind == EventKind.MCP_DRIFT_SHAPE:
        try:
            _metrics["shape_total"].labels(server_id=server_id).inc()
            added = detail.get("added_keys", []) or []
            removed = detail.get("removed_keys", []) or []
            if added:
                _metrics["shape_added_keys_total"].labels(server_id=server_id).inc(
                    float(len(added))
                )
            if removed:
                _metrics["shape_removed_keys_total"].labels(server_id=server_id).inc(
                    float(len(removed))
                )
            _metrics["last_seen_timestamp"].labels(
                server_id=server_id, kind="shape"
            ).set(now)
        except Exception:  # noqa: BLE001 - swallow per sink contract
            return
        return

    if event.kind == EventKind.MCP_DRIFT_LATENCY:
        try:
            jump = detail.get("jump_fraction")
            if isinstance(jump, (int, float)):
                _metrics["latency_jump_fraction"].labels(
                    server_id=server_id
                ).observe(float(jump))
            _metrics["last_seen_timestamp"].labels(
                server_id=server_id, kind="latency"
            ).set(now)
        except Exception:  # noqa: BLE001
            return
        return

    if event.kind == EventKind.MCP_DRIFT_DISTRIBUTION:
        try:
            kl = detail.get("kl_divergence")
            field = str(detail.get("field", "unknown"))
            if isinstance(kl, (int, float)):
                _metrics["distribution_kl"].labels(
                    server_id=server_id, field=field
                ).observe(float(kl))
            _metrics["last_seen_timestamp"].labels(
                server_id=server_id, kind="distribution"
            ).set(now)
        except Exception:  # noqa: BLE001
            return
        return

    # Any other event kind: no-op.


def install(
    *,
    port: int | None = None,
    addr: str = "0.0.0.0",
    registry: "CollectorRegistry | None" = None,
) -> None:
    """Register the Prometheus sink with ``tessera.events``.

    Args:
        port: If set, start a Prometheus HTTP exposition server on
            ``addr:port``. If ``None`` (default), only register the
            sink; the caller is responsible for serving ``/metrics``
            (e.g. by mounting ``prometheus_client.make_wsgi_app()``
            on an existing FastAPI app).
        addr: Bind address for the standalone HTTP server.
            Defaults to ``0.0.0.0`` to match Prometheus's default.
        registry: Custom ``CollectorRegistry``. Defaults to the
            process-global registry. Tests should pass a fresh
            registry to avoid polluting subsequent tests.

    Idempotent: subsequent calls do not re-register the sink and
    do not start a second HTTP server.

    Raises:
        PrometheusClientNotAvailable: If ``prometheus_client`` is
            not installed.
    """
    global _installed, _http_server_thread

    with _install_lock:
        if _installed:
            return

        # Build collectors before registering the sink, so the very
        # first event after install() finds a populated _metrics
        # dict.
        _build_metrics(registry)
        register_sink(prometheus_sink)

        if port is not None:
            pc = _require_prometheus_client()
            # start_http_server runs on a background daemon thread;
            # capture it for diagnostic introspection.
            try:
                pc.start_http_server(port=port, addr=addr, registry=registry)
            except OSError as exc:  # pragma: no cover - port in use
                raise RuntimeError(
                    f"failed to bind Prometheus HTTP server to {addr}:{port}: {exc}"
                ) from exc
            _http_server_thread = threading.current_thread()

        _installed = True


def is_installed() -> bool:
    """Return True if ``install()`` has been called this process."""
    return _installed


def _reset_for_tests() -> None:
    """Test-only helper. Clear module-level state so successive tests
    can call ``install()`` against a fresh registry.

    The per-process Prometheus default registry is deliberately
    NOT cleared here (that would break other tests in the same
    process); pass a fresh ``CollectorRegistry`` to ``install()``
    in tests to fully isolate.
    """
    global _installed, _http_server_thread, _metrics

    from tessera.events import unregister_sink

    if _installed:
        unregister_sink(prometheus_sink)
    _installed = False
    _http_server_thread = None
    _metrics = {}
