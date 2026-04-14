"""Liveness attestation for delegation chains.

Tracks agent liveness via heartbeat TTL. A delegation token from an
agent that has not heartbeated within the TTL is treated as suspended,
regardless of whether the token itself has expired.

This implements the three-property gate from Agent Governance Toolkit
ADR 0005: identity AND authority AND liveness must all hold for a
delegation to be valid.

Source attribution: three-property decomposition and suspension
semantics from Microsoft Agent Governance Toolkit (ADR 0005).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock


@dataclass(frozen=True)
class LivenessState:
    """Liveness state for one agent.

    Attributes:
        agent_id: The agent identity.
        alive: True if the agent has heartbeated within the TTL.
        suspended: True if the agent was explicitly suspended.
        last_heartbeat: The timestamp of the last heartbeat, or None.
        ttl_seconds: The configured TTL in seconds.
    """

    agent_id: str
    alive: bool
    suspended: bool
    last_heartbeat: datetime | None
    ttl_seconds: float


class LivenessChecker:
    """Track agent liveness via heartbeat TTL.

    Three-property gate: identity AND authority AND liveness.
    A delegation token from an agent that has not heartbeated
    within the TTL is treated as suspended.

    Args:
        ttl: Maximum time between heartbeats before an agent is
            considered dead. Default 90 seconds.

    Usage::

        checker = LivenessChecker()
        checker.heartbeat("agent-1")
        assert checker.is_alive("agent-1")

        # After TTL expires without heartbeat:
        assert not checker.is_alive("agent-1")

        # Explicit suspension:
        checker.suspend("agent-1")
        assert not checker.is_alive("agent-1")
    """

    def __init__(self, ttl: timedelta = timedelta(seconds=90)) -> None:
        self._ttl = ttl
        self._heartbeats: dict[str, datetime] = {}
        self._suspended: set[str] = set()
        self._lock = Lock()

    def heartbeat(self, agent_id: str, at: datetime | None = None) -> None:
        """Record a heartbeat from an agent.

        Clears any prior suspension.

        Args:
            agent_id: The agent identity.
            at: Heartbeat timestamp. Defaults to now (UTC).
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            self._heartbeats[agent_id] = ts
            self._suspended.discard(agent_id)

    def is_alive(self, agent_id: str, at: datetime | None = None) -> bool:
        """Check if an agent is alive (heartbeated within TTL and not suspended).

        Args:
            agent_id: The agent identity.
            at: Reference time. Defaults to now (UTC).

        Returns:
            True if the agent is alive and not suspended.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            if agent_id in self._suspended:
                return False
            last = self._heartbeats.get(agent_id)
            if last is None:
                return False
            return (ts - last) < self._ttl

    def suspend(self, agent_id: str) -> None:
        """Explicitly suspend an agent.

        A suspended agent is not alive regardless of heartbeat state.
        A subsequent heartbeat clears the suspension.

        Args:
            agent_id: The agent identity.
        """
        with self._lock:
            self._suspended.add(agent_id)

    def revoke(self, agent_id: str) -> None:
        """Permanently remove an agent from the liveness tracker.

        Unlike suspend, revoke removes all state. The agent must
        re-register with a fresh heartbeat.

        Args:
            agent_id: The agent identity.
        """
        with self._lock:
            self._heartbeats.pop(agent_id, None)
            self._suspended.discard(agent_id)

    def state(self, agent_id: str, at: datetime | None = None) -> LivenessState:
        """Return the full liveness state for an agent.

        Args:
            agent_id: The agent identity.
            at: Reference time. Defaults to now (UTC).

        Returns:
            LivenessState with current heartbeat and suspension info.
        """
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            suspended = agent_id in self._suspended
            last = self._heartbeats.get(agent_id)
            alive = (
                not suspended
                and last is not None
                and (ts - last) < self._ttl
            )
            return LivenessState(
                agent_id=agent_id,
                alive=alive,
                suspended=suspended,
                last_heartbeat=last,
                ttl_seconds=self._ttl.total_seconds(),
            )
