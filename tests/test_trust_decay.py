"""Tests for tessera.trust_decay: time-based decay and anomaly degradation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.trust_decay import (
    DecayAwareContext,
    ToolServerTrustTracker,
    TrustDecayPolicy,
    effective_trust,
)


KEY = b"test-key-for-trust-decay"


def _make_label(trust: TrustLevel = TrustLevel.USER):
    """Build a minimal TrustLabel for testing."""
    from tessera.labels import TrustLabel
    return TrustLabel(origin=Origin.USER, principal="alice", trust_level=trust)


class TestEffectiveTrust:
    def test_no_decay_within_max_age(self):
        """Fresh segment keeps original trust level."""
        label = _make_label(TrustLevel.USER)
        result = effective_trust(label, age=timedelta(minutes=10))
        assert result == TrustLevel.USER

    def test_decay_after_max_age(self):
        """Segment past max_age loses trust proportionally."""
        label = _make_label(TrustLevel.USER)
        # 40 minutes old with default 30-minute max_age: 10 minutes overage
        # decay = 10 * 0.5 = 5 points
        result = effective_trust(label, age=timedelta(minutes=40))
        assert result == int(TrustLevel.USER) - 5

    def test_anomaly_penalty_applied(self):
        """Anomaly count reduces trust by penalty per flag."""
        label = _make_label(TrustLevel.TOOL)
        # Within max_age, but 2 anomalies at 10 points each = 20 point penalty
        result = effective_trust(label, age=timedelta(minutes=5), anomaly_count=2)
        assert result == int(TrustLevel.TOOL) - 20

    def test_min_effective_trust_floor(self):
        """Trust never drops below the configured floor."""
        label = _make_label(TrustLevel.TOOL)
        policy = TrustDecayPolicy(min_effective_trust=10)
        # Massive age to push decay way past the floor
        result = effective_trust(
            label, age=timedelta(hours=24), anomaly_count=100, policy=policy
        )
        assert result == 10

    def test_decay_and_anomaly_combine(self):
        """Time decay and anomaly penalties stack."""
        label = _make_label(TrustLevel.USER)
        # 40 min old (10 min overage, 5 point decay) + 1 anomaly (10 points)
        result = effective_trust(
            label, age=timedelta(minutes=40), anomaly_count=1
        )
        assert result == int(TrustLevel.USER) - 15

    def test_zero_age_no_decay(self):
        """Zero-age segment with no anomalies returns exact trust level."""
        label = _make_label(TrustLevel.SYSTEM)
        result = effective_trust(label, age=timedelta(0))
        assert result == TrustLevel.SYSTEM


class TestToolServerTrustTracker:
    def test_server_tracker_accumulates(self):
        """Multiple anomalies accumulate for the same server."""
        tracker = ToolServerTrustTracker()
        tracker.record_anomaly("sketchy-server")
        tracker.record_anomaly("sketchy-server")
        tracker.record_anomaly("sketchy-server")
        assert tracker.anomaly_count("sketchy-server") == 3

    def test_server_tracker_reset(self):
        """Reset clears the anomaly count for a server."""
        tracker = ToolServerTrustTracker()
        tracker.record_anomaly("flaky-server")
        tracker.record_anomaly("flaky-server")
        assert tracker.anomaly_count("flaky-server") == 2
        tracker.reset("flaky-server")
        assert tracker.anomaly_count("flaky-server") == 0

    def test_unknown_server_returns_zero(self):
        """Querying an unrecorded server returns zero anomalies."""
        tracker = ToolServerTrustTracker()
        assert tracker.anomaly_count("unknown") == 0

    def test_effective_server_trust_with_anomalies(self):
        """Server trust degrades with recorded anomalies."""
        tracker = ToolServerTrustTracker()
        tracker.record_anomaly("bad-server")
        result = tracker.effective_server_trust(
            "bad-server", TrustLevel.TOOL, age=timedelta(minutes=5)
        )
        # Within max_age, 1 anomaly at 10 points = TOOL(50) - 10 = 40
        assert result == 40

    def test_reset_does_not_affect_other_servers(self):
        """Resetting one server leaves others untouched."""
        tracker = ToolServerTrustTracker()
        tracker.record_anomaly("server-a")
        tracker.record_anomaly("server-b")
        tracker.reset("server-a")
        assert tracker.anomaly_count("server-a") == 0
        assert tracker.anomaly_count("server-b") == 1


class TestDecayAwareContext:
    def test_decay_aware_context_min_trust(self):
        """Wrapping a context produces lower min_trust when segments are old."""
        ctx = Context()
        ctx.add(make_segment("system prompt", Origin.SYSTEM, "op", key=KEY))
        ctx.add(make_segment("user input", Origin.USER, "alice", key=KEY))

        # Without decay, min_trust is USER (100)
        assert ctx.min_trust == TrustLevel.USER

        # With decay: segment 1 (USER) is 60 minutes old
        # 30 min overage * 0.5 = 15 point decay -> USER(100) - 15 = 85
        decay_ctx = DecayAwareContext(
            ctx, segment_ages={1: timedelta(minutes=60)}
        )
        assert decay_ctx.min_trust < TrustLevel.USER

    def test_no_ages_means_no_decay(self):
        """Without segment_ages, DecayAwareContext matches raw Context."""
        ctx = Context()
        ctx.add(make_segment("hello", Origin.USER, "alice", key=KEY))
        decay_ctx = DecayAwareContext(ctx)
        assert decay_ctx.min_trust == ctx.min_trust

    def test_empty_context_returns_system(self):
        """Empty wrapped context returns TrustLevel.SYSTEM."""
        ctx = Context()
        decay_ctx = DecayAwareContext(ctx)
        assert decay_ctx.min_trust == TrustLevel.SYSTEM

    def test_segments_delegates(self):
        """The segments property delegates to the wrapped context."""
        ctx = Context()
        seg = make_segment("data", Origin.TOOL, "tool-x", key=KEY)
        ctx.add(seg)
        decay_ctx = DecayAwareContext(ctx)
        assert decay_ctx.segments is ctx.segments

    def test_tracker_integration(self):
        """DecayAwareContext uses tracker anomaly counts per principal."""
        ctx = Context()
        ctx.add(make_segment("tool output", Origin.TOOL, "risky-tool", key=KEY))

        tracker = ToolServerTrustTracker()
        tracker.record_anomaly("risky-tool")
        tracker.record_anomaly("risky-tool")

        decay_ctx = DecayAwareContext(ctx, tracker=tracker)
        # TOOL(50) - 2 anomalies * 10 = 30, which is below UNTRUSTED(0)? No,
        # 50 - 20 = 30. TrustLevel mapping: 30 > UNTRUSTED(0) but < TOOL(50).
        assert decay_ctx.min_trust == TrustLevel.UNTRUSTED
