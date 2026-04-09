"""Benchmarks for ``tessera.context``.

Covers the user-facing make_segment factory, Context.min_trust (the taint
ceiling computation that policy evaluates against), and Context.render
(spotlighting assembly for the prompt).
"""

from __future__ import annotations

from tessera.context import Context, make_segment
from tessera.labels import Origin

KEY = b"0" * 32
USER_CONTENT = "Summarize the attached document."
WEB_CONTENT = "Scraped page body. " * 40  # ~780 bytes

_USER_SEG = make_segment(USER_CONTENT, Origin.USER, "alice", key=KEY)
_WEB_SEG = make_segment(WEB_CONTENT, Origin.WEB, "crawler", key=KEY)
_TOOL_SEG = make_segment("tool result", Origin.TOOL, "fetch_url", key=KEY)


def _build_context(n_segments: int) -> Context:
    ctx = Context()
    ctx.add(_USER_SEG)
    for _ in range(n_segments - 2):
        ctx.add(_TOOL_SEG)
    ctx.add(_WEB_SEG)
    return ctx


_CTX_3 = _build_context(3)
_CTX_10 = _build_context(10)
_CTX_50 = _build_context(50)


def _make_segment_user() -> None:
    make_segment(USER_CONTENT, Origin.USER, "alice", key=KEY)


def _make_segment_web() -> None:
    make_segment(WEB_CONTENT, Origin.WEB, "crawler", key=KEY)


def _min_trust_3() -> None:
    _ = _CTX_3.min_trust


def _min_trust_10() -> None:
    _ = _CTX_10.min_trust


def _min_trust_50() -> None:
    _ = _CTX_50.min_trust


def _render_3() -> None:
    _CTX_3.render()


def _render_10() -> None:
    _CTX_10.render()


BENCHMARKS = [
    ("make_segment, USER origin", _make_segment_user),
    ("make_segment, WEB origin (780 B)", _make_segment_web),
    ("Context.min_trust, 3 segments", _min_trust_3),
    ("Context.min_trust, 10 segments", _min_trust_10),
    ("Context.min_trust, 50 segments", _min_trust_50),
    ("Context.render, 3 segments", _render_3),
    ("Context.render, 10 segments", _render_10),
]
