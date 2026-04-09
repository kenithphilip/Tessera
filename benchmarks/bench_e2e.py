"""End-to-end benchmarks for a realistic Tessera request path.

These stitch together the micro benchmarks into the actual sequence a
proxy would run on every inbound request:

1. Sign three segments (system prompt, user instruction, web tool result).
2. Build a Context from them.
3. Verify every segment's signature.
4. Evaluate a proposed tool call against the Context.

The resulting per-request number is the one to compare against your
expected LLM round-trip latency. If a single LLM call is 500 ms, the
Tessera overhead is this number divided by 500,000.
"""

from __future__ import annotations

from tessera.context import Context, make_segment
from tessera.events import clear_sinks, register_sink
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy

KEY = b"0" * 32

SYSTEM_PROMPT = "You are a helpful assistant with access to tools."
USER_INSTRUCTION = "Summarize https://example.com/article."
SCRAPED_PAGE = "Example Domain. This domain is for use in illustrative examples." * 10


def _noop_sink(_event) -> None:  # type: ignore[no-untyped-def]
    pass


clear_sinks()
register_sink(_noop_sink)

_POLICY = Policy()
_POLICY.require("send_email", TrustLevel.USER)
_POLICY.require("fetch_url", TrustLevel.TOOL)


def _request_allow() -> None:
    """A fetch_url call against a context with an untrusted web segment.

    min_trust is UNTRUSTED, required for fetch_url is TOOL. This is the
    common, uninteresting success path for a read-only tool.
    """
    system_seg = make_segment(SYSTEM_PROMPT, Origin.SYSTEM, "system", key=KEY)
    user_seg = make_segment(USER_INSTRUCTION, Origin.USER, "alice", key=KEY)
    web_seg = make_segment(SCRAPED_PAGE, Origin.WEB, "crawler", key=KEY)

    ctx = Context()
    ctx.add(system_seg)
    ctx.add(user_seg)
    ctx.add(web_seg)

    ctx.verify_all(KEY)
    _POLICY.evaluate(ctx, "fetch_url")


def _request_deny() -> None:
    """A send_email call against the same tainted context.

    min_trust is UNTRUSTED, required for send_email is USER. This is the
    path that matters: an injection in the scraped page tried to trigger
    a privileged tool and the policy denied it.
    """
    system_seg = make_segment(SYSTEM_PROMPT, Origin.SYSTEM, "system", key=KEY)
    user_seg = make_segment(USER_INSTRUCTION, Origin.USER, "alice", key=KEY)
    web_seg = make_segment(SCRAPED_PAGE, Origin.WEB, "crawler", key=KEY)

    ctx = Context()
    ctx.add(system_seg)
    ctx.add(user_seg)
    ctx.add(web_seg)

    ctx.verify_all(KEY)
    _POLICY.evaluate(ctx, "send_email")


BENCHMARKS = [
    ("E2E: sign 3, verify 3, policy allow", _request_allow),
    ("E2E: sign 3, verify 3, policy deny + event", _request_deny),
]
