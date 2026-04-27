"""Tests for the Prometheus exporter sink (TPS-006).

Covers:
- ``install()`` requires prometheus_client; raises a clear
  ImportError subclass when the dep is missing.
- The sink translates each MCP_DRIFT_* event kind into the
  expected Prometheus collector update.
- Non-drift events are a no-op.
- Idempotent install: a second ``install()`` does not re-register
  the sink and does not start a second HTTP server.
- Optional HTTP exposition: ``install(port=...)`` makes
  ``/metrics`` return the expected metric names.
- Sink runs without an installed sink (importing the symbol
  before ``install()`` is a no-op, not a crash).
"""

from __future__ import annotations

import socket
import urllib.request
from datetime import datetime, timezone

import pytest

from tessera.events import EventKind, SecurityEvent, clear_sinks, emit


@pytest.fixture(autouse=True)
def reset_prometheus_sink_state():
    """Each test starts with a clean sink registry and a fresh
    Prometheus collector registry."""
    clear_sinks()
    from tessera.event_sinks.prometheus_sink import _reset_for_tests

    _reset_for_tests()
    yield
    clear_sinks()
    _reset_for_tests()


def _make_event(kind: EventKind, detail: dict) -> SecurityEvent:
    return SecurityEvent(
        kind=kind,
        principal="test",
        detail=detail,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _free_port() -> int:
    """Bind to port 0, read what the kernel allocated, return it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Optional dependency guard
# ---------------------------------------------------------------------------


def test_install_raises_clear_error_without_prometheus_client(monkeypatch):
    import sys

    from tessera.event_sinks.prometheus_sink import (
        PrometheusClientNotAvailable,
        install,
    )

    # Hide prometheus_client from the importer for the duration
    # of this test. Importlib's normal cache must be defeated too
    # because pytest typically already imported it.
    monkeypatch.setitem(sys.modules, "prometheus_client", None)
    with pytest.raises(PrometheusClientNotAvailable) as exc_info:
        install()
    assert "pip install 'tessera[prometheus]'" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Per-event-kind metric translation
# ---------------------------------------------------------------------------


def test_shape_event_increments_counter_and_added_keys():
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import install

    reg = CollectorRegistry()
    install(registry=reg)

    emit(
        _make_event(
            EventKind.MCP_DRIFT_SHAPE,
            {
                "server_id": "billing.example.com",
                "added_keys": ["new_field_a", "new_field_b"],
                "removed_keys": ["old_field"],
            },
        )
    )
    emit(
        _make_event(
            EventKind.MCP_DRIFT_SHAPE,
            {"server_id": "billing.example.com", "added_keys": [], "removed_keys": []},
        )
    )

    # tessera_mcp_drift_shape_total should be 2 for that server.
    val = reg.get_sample_value(
        "tessera_mcp_drift_shape_total",
        labels={"server_id": "billing.example.com"},
    )
    assert val == 2.0
    # Added-keys counter should be 2 (the first event added 2; the second 0).
    added_total = reg.get_sample_value(
        "tessera_mcp_drift_shape_added_keys_total",
        labels={"server_id": "billing.example.com"},
    )
    assert added_total == 2.0
    removed_total = reg.get_sample_value(
        "tessera_mcp_drift_shape_removed_keys_total",
        labels={"server_id": "billing.example.com"},
    )
    assert removed_total == 1.0


def test_latency_event_observes_histogram_bucket():
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import install

    reg = CollectorRegistry()
    install(registry=reg)

    emit(
        _make_event(
            EventKind.MCP_DRIFT_LATENCY,
            {
                "server_id": "search.example.com",
                "baseline_p99": 100.0,
                "current_p99": 170.0,
                "jump_fraction": 0.7,
            },
        )
    )

    # Histogram with buckets (0.25, 0.5, 1.0, ...). 0.7 lands in
    # the "1.0" bucket (cumulative).
    bucket_le_1 = reg.get_sample_value(
        "tessera_mcp_drift_latency_jump_fraction_bucket",
        labels={"server_id": "search.example.com", "le": "1.0"},
    )
    assert bucket_le_1 == 1.0
    bucket_le_05 = reg.get_sample_value(
        "tessera_mcp_drift_latency_jump_fraction_bucket",
        labels={"server_id": "search.example.com", "le": "0.5"},
    )
    assert bucket_le_05 == 0.0


def test_distribution_event_separates_field_label():
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import install

    reg = CollectorRegistry()
    install(registry=reg)

    emit(
        _make_event(
            EventKind.MCP_DRIFT_DISTRIBUTION,
            {
                "server_id": "rag.example.com",
                "field": "content",
                "kl_divergence": 0.4,
                "threshold": 0.3,
            },
        )
    )
    emit(
        _make_event(
            EventKind.MCP_DRIFT_DISTRIBUTION,
            {
                "server_id": "rag.example.com",
                "field": "title",
                "kl_divergence": 0.15,
                "threshold": 0.3,
            },
        )
    )

    content_count = reg.get_sample_value(
        "tessera_mcp_drift_distribution_kl_count",
        labels={"server_id": "rag.example.com", "field": "content"},
    )
    title_count = reg.get_sample_value(
        "tessera_mcp_drift_distribution_kl_count",
        labels={"server_id": "rag.example.com", "field": "title"},
    )
    assert content_count == 1.0
    assert title_count == 1.0


def test_non_drift_event_is_noop():
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import install

    reg = CollectorRegistry()
    install(registry=reg)

    # Use a clearly non-drift event kind.
    emit(_make_event(EventKind.POLICY_DENY, {"reason": "test"}))

    # No drift counter should have been touched.
    val = reg.get_sample_value(
        "tessera_mcp_drift_shape_total", labels={"server_id": "test"}
    )
    # An untouched labelled metric returns None (no series exists).
    assert val is None


def test_sink_does_nothing_before_install():
    """Importing prometheus_sink without calling install() must not
    raise when emit() fires drift events."""
    from tessera.event_sinks.prometheus_sink import prometheus_sink

    # Sink registered manually but install() never called.
    from tessera.events import register_sink

    register_sink(prometheus_sink)

    # Should not raise (the no-op branch covers the missing-metrics
    # case).
    emit(
        _make_event(
            EventKind.MCP_DRIFT_SHAPE,
            {"server_id": "x", "added_keys": [], "removed_keys": []},
        )
    )


# ---------------------------------------------------------------------------
# Idempotent install
# ---------------------------------------------------------------------------


def test_install_is_idempotent():
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import (
        install,
        is_installed,
        prometheus_sink,
    )
    from tessera.events import _sinks  # type: ignore[attr-defined]

    reg = CollectorRegistry()
    install(registry=reg)
    assert is_installed()
    first_count = sum(1 for s in _sinks if s is prometheus_sink)
    install(registry=reg)
    second_count = sum(1 for s in _sinks if s is prometheus_sink)
    assert first_count == 1
    assert second_count == 1


# ---------------------------------------------------------------------------
# HTTP exposition
# ---------------------------------------------------------------------------


def test_install_with_port_serves_metrics_endpoint():
    """install(port=...) starts a Prometheus HTTP exposition server.

    We bind to a free port to avoid races with parallel test runs.
    """
    from prometheus_client import CollectorRegistry

    from tessera.event_sinks.prometheus_sink import install

    reg = CollectorRegistry()
    port = _free_port()
    install(port=port, addr="127.0.0.1", registry=reg)

    # Emit one event so the metric has a recorded sample.
    emit(
        _make_event(
            EventKind.MCP_DRIFT_SHAPE,
            {"server_id": "live", "added_keys": ["x"], "removed_keys": []},
        )
    )

    body = urllib.request.urlopen(
        f"http://127.0.0.1:{port}/metrics", timeout=5
    ).read().decode("utf-8")
    assert "tessera_mcp_drift_shape_total" in body
    assert 'server_id="live"' in body
