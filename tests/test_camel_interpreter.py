"""Tests for the CaMeL-style interpreter used in comparison benchmarks.

Pins the taint-tracking and capability-checking behavior that drives the
benchmark's security claims. If these fail, the benchmark numbers are
measuring the wrong thing.
"""

from __future__ import annotations

from typing import Any

import pytest

from benchmarks.comparison.interpreter import (
    Capability,
    CaMeLInterpreter,
    CapabilityViolation,
    PlanStep,
    parse_plan,
)


def _echo_dispatch(name: str, args: dict[str, Any]) -> Any:
    """Returns args unchanged so tests can inspect what the tool received."""
    return {"tool": name, "args": args}


def _make_interpreter(**capabilities: bool) -> CaMeLInterpreter:
    """Build an interpreter with named capabilities.

    Usage: _make_interpreter(send_email=True, fetch_url=False)
    True means the tool requires clean inputs; False means it allows tainted.
    """
    caps = {
        name: Capability(tool=name, requires_clean=requires_clean)
        for name, requires_clean in capabilities.items()
    }
    return CaMeLInterpreter(capabilities=caps)


class TestCleanVariablePassesCapabilityCheck:
    def test_clean_variable_passes_capability_check(self) -> None:
        interp = _make_interpreter(send_email=True)
        interp.set_variable("addr", "team@acme.com", taint="clean", source="user")

        plan = [PlanStep(function="send_email", args={"to": "addr"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is False
        assert results[0]["output_taint"] == "clean"


class TestTaintedVariableBlocksSensitiveTool:
    def test_tainted_variable_blocks_sensitive_tool(self) -> None:
        interp = _make_interpreter(send_email=True)
        interp.set_variable("data", "stolen secrets", taint="tainted", source="web")

        plan = [PlanStep(function="send_email", args={"body": "data"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is True
        assert results[0]["output_taint"] == "tainted"
        assert "requires clean" in results[0]["reason"]


class TestTaintPropagationThroughIntermediateSteps:
    def test_taint_propagation_through_intermediate_steps(self) -> None:
        """Taint flows through extract -> transform -> send, blocking the send."""
        interp = _make_interpreter(
            extract=False,
            transform=False,
            send_email=True,
        )
        interp.set_variable("raw", "attacker data", taint="tainted", source="web")

        plan = [
            PlanStep(function="extract", args={"input": "raw"}, result_var="extracted"),
            PlanStep(function="transform", args={"input": "extracted"}, result_var="transformed"),
            PlanStep(function="send_email", args={"body": "transformed"}, result_var="sent"),
        ]
        results = interp.execute_plan(plan, _echo_dispatch)

        # extract and transform succeed (no clean requirement).
        assert results[0]["blocked"] is False
        assert results[0]["output_taint"] == "tainted"
        assert results[1]["blocked"] is False
        assert results[1]["output_taint"] == "tainted"
        # send_email blocks because taint propagated through the chain.
        assert results[2]["blocked"] is True


class TestMixedCleanAndTaintedArgsPropagatesTaint:
    def test_mixed_clean_and_tainted_args_propagates_taint(self) -> None:
        """One tainted arg among clean ones is enough to taint the output."""
        interp = _make_interpreter(merge=False, send_email=True)
        interp.set_variable("clean_data", "safe", taint="clean", source="user")
        interp.set_variable("dirty_data", "injected", taint="tainted", source="web")

        plan = [
            PlanStep(
                function="merge",
                args={"a": "clean_data", "b": "dirty_data"},
                result_var="merged",
            ),
            PlanStep(
                function="send_email",
                args={"body": "merged"},
                result_var="sent",
            ),
        ]
        results = interp.execute_plan(plan, _echo_dispatch)

        # merge succeeds but produces tainted output.
        assert results[0]["blocked"] is False
        assert results[0]["output_taint"] == "tainted"
        # send_email blocks due to tainted input.
        assert results[1]["blocked"] is True


class TestToolWithoutCapabilityRestrictionAllowsTainted:
    def test_tool_without_capability_restriction_allows_tainted(self) -> None:
        """Tools not in the capability map allow tainted data through."""
        interp = CaMeLInterpreter(capabilities={})
        interp.set_variable("data", "tainted payload", taint="tainted", source="web")

        plan = [PlanStep(function="log_event", args={"msg": "data"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is False
        assert results[0]["output_taint"] == "tainted"


class TestParsePlan:
    def test_parse_roundtrip(self) -> None:
        plan_text = (
            "extracted = extract_entities(text=scraped_content)\n"
            "result = send_email(recipient=user_addr, body=extracted)"
        )
        steps = parse_plan(plan_text)

        assert len(steps) == 2
        assert steps[0].function == "extract_entities"
        assert steps[0].args == {"text": "scraped_content"}
        assert steps[0].result_var == "extracted"
        assert steps[1].function == "send_email"
        assert steps[1].args == {"recipient": "user_addr", "body": "extracted"}
        assert steps[1].result_var == "result"
