"""Benchmarks for ``tessera.policy``.

Policy.evaluate is on every tool-call path, so its cost is the one most
likely to show up in aggregate overhead. We measure both allow and deny
branches. The deny branch is more expensive because it also emits a
SecurityEvent, which is representative of real incident-response traffic.
"""

from __future__ import annotations

from tessera.context import Context, make_segment
from tessera.events import clear_sinks, register_sink
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy

KEY = b"0" * 32


def _noop_sink(_event) -> None:  # type: ignore[no-untyped-def]
    pass


clear_sinks()
register_sink(_noop_sink)


_POLICY = Policy()
_POLICY.require("send_email", TrustLevel.USER)
_POLICY.require("fetch_url", TrustLevel.TOOL)

_TRUSTED_CTX = Context()
_TRUSTED_CTX.add(make_segment("System prompt.", Origin.SYSTEM, "system", key=KEY))
_TRUSTED_CTX.add(make_segment("Send the weekly digest.", Origin.USER, "alice", key=KEY))

_TAINTED_CTX = Context()
_TAINTED_CTX.add(make_segment("System prompt.", Origin.SYSTEM, "system", key=KEY))
_TAINTED_CTX.add(make_segment("Summarize this.", Origin.USER, "alice", key=KEY))
_TAINTED_CTX.add(
    make_segment("Scraped page with injection.", Origin.WEB, "crawler", key=KEY)
)


def _evaluate_allow() -> None:
    _POLICY.evaluate(_TRUSTED_CTX, "send_email")


def _evaluate_deny() -> None:
    _POLICY.evaluate(_TAINTED_CTX, "send_email")


def _evaluate_allow_tool_tier() -> None:
    _POLICY.evaluate(_TAINTED_CTX, "fetch_url")


BENCHMARKS = [
    ("Policy.evaluate, allow (trusted context)", _evaluate_allow),
    ("Policy.evaluate, allow at TOOL tier (tainted ctx)", _evaluate_allow_tool_tier),
    ("Policy.evaluate, deny (tainted context, emits event)", _evaluate_deny),
]
