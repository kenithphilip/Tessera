"""Per-session tool-call rate limit (`ToolCallRateLimit`).

Mirrors `tessera.ratelimit.ToolCallRateLimit`. Three independent
caps: rolling-window rate, burst detection (with cooldown), and
absolute session-lifetime cap.

Example::

    from tessera_rs.ratelimit import ToolCallRateLimit

    limiter = ToolCallRateLimit(
        max_calls=20,
        window_seconds=300,        # 5 minutes
        burst_threshold=8,
        burst_window_seconds=5,
        cooldown_seconds=30,
        session_lifetime_max=500,
    )
    allowed, reason = limiter.check("session_abc", "search_hotels")
    if not allowed:
        raise RuntimeError(reason)
"""

from __future__ import annotations

from tessera_rs._native import ToolCallRateLimit

__all__ = ["ToolCallRateLimit"]
