"""Tessera strategy: schema-enforced dual-LLM with signed trust labels.

Uses real Tessera imports for every step: segment signing, context
assembly, trust partitioning, Pydantic schema validation, and taint-floor
policy evaluation. Nothing is reimplemented; this measures the actual
library overhead.
"""

from __future__ import annotations

from tessera.context import Context, make_segment
from tessera.events import clear_sinks, register_sink
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.quarantine import WorkerReport, split_by_trust

from benchmarks.comparison.stubs import stub_planner_response, stub_worker_response
from benchmarks.comparison.workload import (
    SCRAPED_DOCUMENT,
    SYSTEM_PROMPT,
    TOOL_TRUST_REQUIREMENTS,
    USER_INSTRUCTION,
)

KEY = b"0" * 32

# Silence event sinks so benchmark timing is not polluted by I/O.
clear_sinks()
register_sink(lambda _: None)

_POLICY = Policy()
for tool_name, level in TOOL_TRUST_REQUIREMENTS.items():
    _POLICY.require(tool_name, level)


def _tessera_request() -> None:
    """Full Tessera request path: sign, partition, worker, planner, policy."""
    # 1. Sign all context segments.
    system_seg = make_segment(SYSTEM_PROMPT, Origin.SYSTEM, "system", key=KEY)
    user_seg = make_segment(USER_INSTRUCTION, Origin.USER, "analyst", key=KEY)
    web_seg = make_segment(SCRAPED_DOCUMENT, Origin.WEB, "scraper", key=KEY)

    # 2. Assemble context and verify signatures.
    ctx = Context()
    ctx.add(system_seg)
    ctx.add(user_seg)
    ctx.add(web_seg)
    ctx.verify_all(KEY)

    # 3. Split by trust for dual-LLM quarantine.
    trusted, untrusted = split_by_trust(ctx)

    # 4. Worker processes untrusted content, output validated by Pydantic.
    raw_worker = stub_worker_response()
    _report = WorkerReport.model_validate_json(raw_worker)

    # 5. Planner sees only trusted context + structured worker report.
    tool_calls = stub_planner_response()

    # 6. Policy evaluation on each proposed tool call.
    for call in tool_calls:
        _POLICY.evaluate(ctx, call["tool"])


BENCHMARKS = [
    ("Tessera: dual-LLM, sign/verify, policy", _tessera_request),
]
