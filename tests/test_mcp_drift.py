"""Tests for DriftMonitor in tessera.mcp.drift.

Each test verifies one of the three drift signals:
    - shape change -> MCP_DRIFT_SHAPE
    - p99 latency jump -> MCP_DRIFT_LATENCY
    - character-class distribution shift -> MCP_DRIFT_DISTRIBUTION
"""

from __future__ import annotations

import pytest

from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink
from tessera.mcp.drift import DriftMonitor

# Number of observations required to establish a baseline.
_BASELINE = 10


def _collect_sink(events: list[SecurityEvent]):
    """Return a sink function that appends to events."""
    def sink(event: SecurityEvent) -> None:
        events.append(event)
    return sink


@pytest.fixture(autouse=True)
def clean_sinks():
    """Reset the global sink list before every test."""
    clear_sinks()
    yield
    clear_sinks()


# ---------------------------------------------------------------------------
# Helper: build a baseline for server_id using consistent responses.
# ---------------------------------------------------------------------------

def _establish_baseline(
    monitor: DriftMonitor,
    server_id: str,
    response: dict,
    latency: float = 0.05,
    n: int = _BASELINE,
) -> None:
    for _ in range(n):
        monitor.observe(server_id, response, latency)


# ---------------------------------------------------------------------------
# Shape drift
# ---------------------------------------------------------------------------

def test_shape_change_emits_mcp_drift_shape() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE)
    baseline_response = {"result": "ok", "count": "42"}
    _establish_baseline(monitor, "srv-1", baseline_response)

    changed_response = {"result": "ok", "count": "42", "extra_field": "injected"}
    monitor.observe("srv-1", changed_response, 0.05)
    alerts = monitor.check("srv-1", response=changed_response)

    shape_alerts = [a for a in alerts if a.kind == "shape"]
    assert len(shape_alerts) == 1
    shape_events = [e for e in events if e.kind == EventKind.MCP_DRIFT_SHAPE]
    assert len(shape_events) >= 1
    assert "extra_field" in shape_events[0].detail["added_keys"]


def test_no_shape_alert_when_shape_unchanged() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE)
    baseline_response = {"result": "ok"}
    _establish_baseline(monitor, "srv-stable", baseline_response)

    alerts = monitor.check("srv-stable", response={"result": "ok"})
    assert not any(a.kind == "shape" for a in alerts)
    assert not any(e.kind == EventKind.MCP_DRIFT_SHAPE for e in events)


# ---------------------------------------------------------------------------
# Latency drift
# ---------------------------------------------------------------------------

def test_latency_jump_emits_mcp_drift_latency() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE, latency_jump_threshold=0.50)
    baseline_response = {"data": "hello"}
    _establish_baseline(monitor, "srv-lat", baseline_response, latency=0.04)

    # Inject very slow observations to push p99 well above baseline.
    for _ in range(_BASELINE):
        monitor.observe("srv-lat", baseline_response, 1.5)

    alerts = monitor.check("srv-lat")
    lat_alerts = [a for a in alerts if a.kind == "latency"]
    assert len(lat_alerts) == 1

    lat_events = [e for e in events if e.kind == EventKind.MCP_DRIFT_LATENCY]
    assert len(lat_events) >= 1
    assert lat_events[0].detail["jump_fraction"] > 0.50


def test_clean_latency_emits_no_alert() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE)
    baseline_response = {"data": "hello"}
    _establish_baseline(monitor, "srv-clean-lat", baseline_response, latency=0.05)

    # Observe at the same latency.
    for _ in range(5):
        monitor.observe("srv-clean-lat", baseline_response, 0.05)

    alerts = monitor.check("srv-clean-lat")
    assert not any(a.kind == "latency" for a in alerts)
    assert not any(e.kind == EventKind.MCP_DRIFT_LATENCY for e in events)


# ---------------------------------------------------------------------------
# Distribution drift
# ---------------------------------------------------------------------------

def test_distribution_shift_emits_mcp_drift_distribution() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE, kl_threshold=0.3)
    # Baseline: purely alphabetical content.
    baseline_response = {"payload": "abcdefghijklmnopqrstuvwxyz"}
    _establish_baseline(monitor, "srv-dist", baseline_response)

    # Shifted: base64-like content (lots of digits and mixed chars).
    shifted_response = {"payload": "1234567890" * 10 + "=="}
    monitor.observe("srv-dist", shifted_response, 0.05)

    alerts = monitor.check("srv-dist", response=shifted_response)
    dist_alerts = [a for a in alerts if a.kind == "distribution"]
    assert len(dist_alerts) >= 1

    dist_events = [e for e in events if e.kind == EventKind.MCP_DRIFT_DISTRIBUTION]
    assert len(dist_events) >= 1
    assert dist_events[0].detail["field"] == "payload"
    assert dist_events[0].detail["kl_divergence"] > 0.3


def test_clean_distribution_emits_no_alert() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE)
    baseline_response = {"payload": "hello world"}
    _establish_baseline(monitor, "srv-clean-dist", baseline_response)

    alerts = monitor.check("srv-clean-dist", response={"payload": "hello world"})
    assert not any(a.kind == "distribution" for a in alerts)
    assert not any(e.kind == EventKind.MCP_DRIFT_DISTRIBUTION for e in events)


# ---------------------------------------------------------------------------
# Baseline not ready
# ---------------------------------------------------------------------------

def test_no_alerts_before_baseline_established() -> None:
    events: list[SecurityEvent] = []
    register_sink(_collect_sink(events))

    monitor = DriftMonitor(baseline_min_observations=_BASELINE)
    monitor.observe("srv-new", {"data": "x"}, 0.05)
    alerts = monitor.check("srv-new", response={"data": "x"})
    assert alerts == []
    assert events == []
