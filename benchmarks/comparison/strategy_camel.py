"""CaMeL strategy: custom interpreter with variable-level taint tracking.

Uses the CaMeL interpreter from interpreter.py to execute a pseudo-Python
plan with capability-based security. The interpreter tracks taint at the
variable level, propagates it through dataflow, and blocks sensitive tool
calls when any argument carries tainted provenance.
"""

from __future__ import annotations

from typing import Any

from benchmarks.comparison.interpreter import (
    Capability,
    CaMeLInterpreter,
    CapabilityViolation,
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


_CAPABILITIES = {
    "send_email": Capability(tool="send_email", requires_clean=True),
    "extract_entities": Capability(tool="extract_entities", requires_clean=False),
}

_PLAN_STEPS = parse_plan(stub_camel_plan())


def _camel_request() -> None:
    """Full CaMeL request path: set up variables, parse plan, execute."""
    interp = CaMeLInterpreter(capabilities=_CAPABILITIES)

    # Bind initial variables with taint metadata.
    interp.set_variable(
        "user_recipient", "team@acme.com", taint="clean", source="user_input"
    )
    interp.set_variable(
        "user_instruction", USER_INSTRUCTION, taint="clean", source="user_input"
    )
    interp.set_variable(
        "scraped_content", SCRAPED_DOCUMENT, taint="tainted", source="web_scrape"
    )

    # Execute the plan. The interpreter will block send_email because
    # extract_entities produces a tainted output (its input was tainted),
    # and send_email requires clean inputs.
    interp.execute_plan(_PLAN_STEPS, _tool_dispatch)


BENCHMARKS = [
    ("CaMeL: interpreter, taint tracking, capability check", _camel_request),
]
