"""CaMeL strategy: interpreter with value-level taint tracking.

Uses the faithful CaMeL value system from interpreter.py: CaMeLValue
wrappers with dependency DAGs, Capabilities (Sources + Readers),
recursive DAG walking for taint propagation, and SecurityPolicyEngine
with fnmatch-based policy matching.

The key difference from Tessera: CaMeL tracks taint at the variable
level with a dependency DAG. Tessera tracks taint at the context-segment
level with min_trust. CaMeL's DAG walking is the main source of its
per-request overhead.
"""

from __future__ import annotations

from typing import Any

from benchmarks.comparison.interpreter import (
    Allowed,
    CaMeLInterpreter,
    Capabilities,
    Public,
    SecurityPolicyEngine,
    SecurityPolicyResult,
    SourceEnum,
    base_security_policy,
    parse_plan,
)
from benchmarks.comparison.stubs import stub_camel_plan
from benchmarks.comparison.workload import (
    SCRAPED_DOCUMENT,
    USER_INSTRUCTION,
)


def _tool_dispatch(name: str, args: dict[str, Any]) -> Any:
    """Deterministic tool dispatch for the interpreter benchmark."""
    if name == "extract_entities":
        return "Q3 revenue $4.2B, net income $890M"
    if name == "send_email":
        return {"status": "sent", "recipient": args.get("recipient")}
    return None


# Build the security policy engine matching CaMeL's default configuration.
# extract_entities has no side effects (read-only), so it's always allowed.
# send_email has side effects, so it gets the base_security_policy check:
# if any dependency has non-public readers, deny.
_NO_SIDE_EFFECT_TOOLS = {"extract_entities"}


def _wildcard_policy(
    tool_name: str,
    kwargs: dict,
) -> SecurityPolicyResult:
    """Fallback policy: run base_security_policy for all tools."""
    return base_security_policy(tool_name, kwargs, _NO_SIDE_EFFECT_TOOLS)


_POLICY_ENGINE = SecurityPolicyEngine(
    policies=[("*", _wildcard_policy)],
    no_side_effect_tools=_NO_SIDE_EFFECT_TOOLS,
)

_PLAN_STEPS = parse_plan(stub_camel_plan())


def _camel_request() -> None:
    """Full CaMeL request path with faithful value system.

    1. Bind variables as CaMeLValues with Capabilities metadata.
       - User inputs: SourceEnum.User, Public() readers (trusted, public)
       - Scraped content: Tool("web_scrape"), restricted readers (untrusted)
    2. Parse plan into PlanSteps.
    3. Execute: for each step, walk the dependency DAG to compute
       effective readers, run SecurityPolicyEngine, dispatch or deny.
    """
    interp = CaMeLInterpreter(policy_engine=_POLICY_ENGINE)

    # User-controlled values: trusted, publicly readable.
    interp.bind("user_recipient", "team@acme.com", Capabilities.user())
    interp.bind("user_instruction", USER_INSTRUCTION, Capabilities.user())

    # Scraped content: untrusted, restricted readers.
    # In CaMeL, tool outputs from untrusted sources get restricted readers,
    # which is what triggers denial when they flow into side-effecting tools.
    interp.bind(
        "scraped_content",
        SCRAPED_DOCUMENT,
        Capabilities.untrusted_tool("web_scrape", frozenset({"web_scrape"})),
    )

    interp.execute_plan(_PLAN_STEPS, _tool_dispatch)


BENCHMARKS = [
    ("CaMeL: interpreter, taint tracking, capability check", _camel_request),
]
