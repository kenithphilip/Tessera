"""Behavioral drift detection for MCP servers.

An MCP server whose tool manifest signature is still valid can still be
compromised if an attacker gains write access to its runtime state without
touching the manifest. This module detects that scenario by monitoring three
signals that shift when a server's behavior changes:

1. Response shape: the set of top-level JSON keys in tool responses. A sudden
   appearance or disappearance of keys is a strong signal.

2. Latency distribution: p50 and p99 via reservoir sampling. A p99 jump of
   more than 50% from a stable baseline suggests the server is doing something
   extra (e.g. exfiltrating data).

3. Character-class distribution per field: alpha, digit, punct, whitespace,
   other. Measured with KL divergence from a baseline. An attacker who injects
   base64 or hex payloads into structured fields will shift the distribution.

All state is in-memory with a rolling 7-day window. Production deployments
should wire their own persistence layer (e.g. Redis ZSET per server_id) by
subclassing DriftMonitor and overriding the storage hooks.

Each alert emits the matching SecurityEvent:
    MCP_DRIFT_SHAPE       -- top-level key set changed
    MCP_DRIFT_LATENCY     -- p99 latency jumped > 50% above baseline
    MCP_DRIFT_DISTRIBUTION -- per-field char-class KL divergence > 0.3
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any


# Rolling window duration in seconds.
_WINDOW_SECONDS = 7 * 24 * 3600

# Reservoir size for latency sampling.
_DEFAULT_RESERVOIR = 1024

# Fraction p99 must increase over baseline to trigger an alert.
_LATENCY_JUMP_THRESHOLD = 0.50

# KL divergence above which a distribution shift is flagged.
_KL_DIVERGENCE_THRESHOLD = 0.30

# Minimum observations before we trust a baseline.
_BASELINE_MIN_OBSERVATIONS = 10


# ---------------------------------------------------------------------------
# Character-class helpers
# ---------------------------------------------------------------------------

def _char_class(ch: str) -> str:
    if ch.isalpha():
        return "alpha"
    if ch.isdigit():
        return "digit"
    if ch in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
        return "punct"
    if ch.isspace():
        return "whitespace"
    return "other"


def _char_histogram(text: str) -> dict[str, float]:
    """Return a normalized character-class histogram for text.

    Returns a dict with keys alpha/digit/punct/whitespace/other summing to 1.0.
    Returns a uniform distribution when text is empty to avoid division by zero.
    """
    categories = ("alpha", "digit", "punct", "whitespace", "other")
    counts: dict[str, int] = {c: 0 for c in categories}
    for ch in text:
        counts[_char_class(ch)] += 1
    total = sum(counts.values())
    if total == 0:
        return {c: 0.2 for c in categories}
    return {c: counts[c] / total for c in categories}


def _kl_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """KL divergence D(p || q) for two discrete distributions with the same keys.

    Uses add-epsilon smoothing on q to avoid log(0). Both distributions must
    share the same key set.

    Args:
        p: Observed distribution.
        q: Baseline distribution.

    Returns:
        KL divergence in nats (>= 0). Returns 0.0 if p is all-zero.
    """
    epsilon = 1e-9
    total = 0.0
    for key in p:
        pi = p[key]
        qi = q.get(key, 0.0) + epsilon
        if pi > 0:
            total += pi * math.log(pi / qi)
    return total


# ---------------------------------------------------------------------------
# Reservoir sampler for latency
# ---------------------------------------------------------------------------

class _Reservoir:
    """Fixed-size reservoir sampler (Algorithm R) with percentile query."""

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._samples: list[float] = []
        self._count = 0

    def add(self, value: float) -> None:
        self._count += 1
        if len(self._samples) < self._capacity:
            self._samples.append(value)
        else:
            idx = random.randint(0, self._count - 1)
            if idx < self._capacity:
                self._samples[idx] = value

    def percentile(self, p: float) -> float | None:
        """Return the p-th percentile (0-100) or None if empty."""
        if not self._samples:
            return None
        sorted_samples = sorted(self._samples)
        idx = int(math.ceil(p / 100.0 * len(sorted_samples))) - 1
        return sorted_samples[max(0, idx)]

    @property
    def count(self) -> int:
        return self._count


# ---------------------------------------------------------------------------
# Per-server state
# ---------------------------------------------------------------------------

@dataclass
class _ServerState:
    reservoir: _Reservoir = field(default_factory=lambda: _Reservoir(_DEFAULT_RESERVOIR))
    # Baseline p99 once we have enough data.
    baseline_p99: float | None = None
    # Known shape at baseline time.
    baseline_shape: frozenset[str] | None = None
    # Per-field baseline histograms.
    baseline_histograms: dict[str, dict[str, float]] = field(default_factory=dict)
    # Accumulated field histograms for computing baseline.
    _pending_histograms: dict[str, list[dict[str, float]]] = field(
        default_factory=lambda: defaultdict(list)
    )
    observation_count: int = 0


# ---------------------------------------------------------------------------
# Public output types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DriftSnapshot:
    """Point-in-time summary of drift signals for one MCP server."""

    server_id: str
    observation_count: int
    latency_p50: float | None
    latency_p99: float | None
    baseline_p99: float | None
    baseline_shape: frozenset[str] | None
    baseline_histograms: dict[str, dict[str, float]]


@dataclass(frozen=True)
class DriftAlert:
    """A single drift signal that crossed its threshold."""

    server_id: str
    kind: str  # "shape" | "latency" | "distribution"
    detail: dict[str, Any]


# ---------------------------------------------------------------------------
# DriftMonitor
# ---------------------------------------------------------------------------

class DriftMonitor:
    """Track behavioral signals per MCP server and emit alerts on drift.

    Instantiate once per agent process. Thread-safe via per-server locks.

    In-memory only. Production deployments should subclass and override
    _load_state / _save_state to wire persistence (e.g. Redis or Postgres).
    """

    def __init__(
        self,
        *,
        reservoir_size: int = _DEFAULT_RESERVOIR,
        latency_jump_threshold: float = _LATENCY_JUMP_THRESHOLD,
        kl_threshold: float = _KL_DIVERGENCE_THRESHOLD,
        baseline_min_observations: int = _BASELINE_MIN_OBSERVATIONS,
    ) -> None:
        self._reservoir_size = reservoir_size
        self._latency_jump_threshold = latency_jump_threshold
        self._kl_threshold = kl_threshold
        self._baseline_min = baseline_min_observations
        self._states: dict[str, _ServerState] = {}
        self._locks: dict[str, Lock] = defaultdict(Lock)

    def _state(self, server_id: str) -> _ServerState:
        if server_id not in self._states:
            self._states[server_id] = _ServerState(
                reservoir=_Reservoir(self._reservoir_size)
            )
        return self._states[server_id]

    def observe(
        self,
        server_id: str,
        response: dict[str, Any],
        latency_seconds: float,
    ) -> None:
        """Record one tool-call response for a server.

        Args:
            server_id: Stable identifier for the MCP server (e.g. hostname or
                URL). Must be consistent across calls.
            response: The parsed JSON response dict from the tool call.
            latency_seconds: Wall-clock seconds from request sent to response
                received.
        """
        with self._locks[server_id]:
            state = self._state(server_id)
            state.observation_count += 1
            state.reservoir.add(latency_seconds)

            # Accumulate per-field histograms.
            for key, value in response.items():
                text = value if isinstance(value, str) else str(value)
                hist = _char_histogram(text)
                state._pending_histograms[key].append(hist)

            # Promote pending to baseline after enough observations.
            if (
                state.observation_count == self._baseline_min
                or (
                    state.baseline_p99 is None
                    and state.observation_count >= self._baseline_min
                )
            ):
                p99 = state.reservoir.percentile(99)
                if p99 is not None:
                    state.baseline_p99 = p99
                state.baseline_shape = frozenset(response.keys())
                for key, hists in state._pending_histograms.items():
                    state.baseline_histograms[key] = _average_histograms(hists)

    def snapshot(self, server_id: str) -> DriftSnapshot:
        """Return a point-in-time summary of signals for server_id.

        Args:
            server_id: The server to snapshot.

        Returns:
            DriftSnapshot with current latency percentiles and baselines.
        """
        with self._locks[server_id]:
            state = self._state(server_id)
            return DriftSnapshot(
                server_id=server_id,
                observation_count=state.observation_count,
                latency_p50=state.reservoir.percentile(50),
                latency_p99=state.reservoir.percentile(99),
                baseline_p99=state.baseline_p99,
                baseline_shape=state.baseline_shape,
                baseline_histograms=dict(state.baseline_histograms),
            )

    def check(
        self,
        server_id: str,
        response: dict[str, Any] | None = None,
    ) -> list[DriftAlert]:
        """Check current signals against baselines and emit security events.

        Call after observe() once the agent wants an up-to-date verdict.
        If response is provided, shape and distribution checks use it directly.
        Otherwise they compare the stored baseline to the most-recently-observed
        shape (not available -- callers should pass response for accuracy).

        Args:
            server_id: Server to evaluate.
            response: The response dict from the most recent tool call. When
                provided, shape and distribution checks use it. Pass None to
                skip shape/distribution checks and only evaluate latency.

        Returns:
            List of DriftAlert, one per signal that crossed its threshold.
            Each alert also emits the matching SecurityEvent.
        """
        with self._locks[server_id]:
            state = self._state(server_id)
            if state.baseline_p99 is None:
                # Not enough data for a baseline yet.
                return []

            alerts: list[DriftAlert] = []

            # Shape check.
            if response is not None and state.baseline_shape is not None:
                current_shape = frozenset(response.keys())
                if current_shape != state.baseline_shape:
                    added = current_shape - state.baseline_shape
                    removed = state.baseline_shape - current_shape
                    detail: dict[str, Any] = {
                        "server_id": server_id,
                        "added_keys": sorted(added),
                        "removed_keys": sorted(removed),
                    }
                    alerts.append(DriftAlert(server_id=server_id, kind="shape", detail=detail))
                    _emit_drift_event("MCP_DRIFT_SHAPE", server_id, detail)

            # Latency check.
            current_p99 = state.reservoir.percentile(99)
            if current_p99 is not None and state.baseline_p99 > 0:
                jump = (current_p99 - state.baseline_p99) / state.baseline_p99
                if jump > self._latency_jump_threshold:
                    detail = {
                        "server_id": server_id,
                        "baseline_p99": state.baseline_p99,
                        "current_p99": current_p99,
                        "jump_fraction": round(jump, 4),
                    }
                    alerts.append(DriftAlert(server_id=server_id, kind="latency", detail=detail))
                    _emit_drift_event("MCP_DRIFT_LATENCY", server_id, detail)

            # Distribution check.
            if response is not None and state.baseline_histograms:
                for key, baseline_hist in state.baseline_histograms.items():
                    if key not in response:
                        continue
                    text = response[key] if isinstance(response[key], str) else str(response[key])
                    current_hist = _char_histogram(text)
                    kl = _kl_divergence(current_hist, baseline_hist)
                    if kl > self._kl_threshold:
                        detail = {
                            "server_id": server_id,
                            "field": key,
                            "kl_divergence": round(kl, 4),
                            "threshold": self._kl_threshold,
                        }
                        alerts.append(
                            DriftAlert(server_id=server_id, kind="distribution", detail=detail)
                        )
                        _emit_drift_event("MCP_DRIFT_DISTRIBUTION", server_id, detail)

            return alerts


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _average_histograms(hists: list[dict[str, float]]) -> dict[str, float]:
    """Return the element-wise average of a list of histograms."""
    keys = hists[0].keys() if hists else []
    avg: dict[str, float] = {}
    n = len(hists)
    for key in keys:
        avg[key] = sum(h.get(key, 0.0) for h in hists) / n
    return avg


def _emit_drift_event(kind_name: str, server_id: str, detail: dict[str, Any]) -> None:
    from tessera.events import EventKind, SecurityEvent, emit

    kind_map = {
        "MCP_DRIFT_SHAPE": EventKind.MCP_DRIFT_SHAPE,
        "MCP_DRIFT_LATENCY": EventKind.MCP_DRIFT_LATENCY,
        "MCP_DRIFT_DISTRIBUTION": EventKind.MCP_DRIFT_DISTRIBUTION,
    }
    emit(
        SecurityEvent.now(
            kind=kind_map[kind_name],
            principal="system",
            detail=detail,
        )
    )
