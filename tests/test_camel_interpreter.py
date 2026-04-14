"""Tests for the CaMeL value system used in comparison benchmarks.

Pins the taint-tracking and security policy behavior that drives the
benchmark's security claims. If these fail, the benchmark numbers are
measuring the wrong thing.
"""

from __future__ import annotations

from typing import Any

import pytest

from benchmarks.comparison.interpreter import (
    Allowed,
    CaMeLInterpreter,
    Capabilities,
    CapabilityViolation,
    Denied,
    PlanStep,
    Public,
    SecurityPolicyEngine,
    SourceEnum,
    Value,
    base_security_policy,
    get_all_readers,
    is_public,
    parse_plan,
)


def _echo_dispatch(name: str, args: dict[str, Any]) -> Any:
    return {"tool": name, "args": args}


def _make_interpreter(
    side_effect_tools: set[str] | None = None,
    no_side_effect_tools: set[str] | None = None,
) -> CaMeLInterpreter:
    """Build an interpreter with a policy engine.

    side_effect_tools: tools that have side effects (will be denied if
        any argument has non-public readers).
    no_side_effect_tools: tools that are read-only (always allowed).
    """
    nse = no_side_effect_tools or set()

    def wildcard(tn: str, kw: dict) -> Allowed | Denied:
        return base_security_policy(tn, kw, nse)

    engine = SecurityPolicyEngine(
        policies=[("*", wildcard)],
        no_side_effect_tools=nse,
    )
    return CaMeLInterpreter(policy_engine=engine)


class TestCleanVariablePassesPolicyCheck:
    def test_clean_variable_passes_policy_check(self) -> None:
        interp = _make_interpreter()
        interp.bind("addr", "team@acme.com", Capabilities.user())

        plan = [PlanStep(function="send_email", args={"to": "addr"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is False


class TestTaintedVariableBlocksSideEffectingTool:
    def test_tainted_variable_blocks_side_effecting_tool(self) -> None:
        interp = _make_interpreter()
        # Restricted readers = untrusted data (non-public).
        interp.bind(
            "data", "stolen secrets",
            Capabilities.untrusted_tool("web", frozenset({"web"})),
        )

        plan = [PlanStep(function="send_email", args={"body": "data"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is True
        assert "state-changing" in results[0]["reason"]


class TestTaintPropagationThroughDependencyDAG:
    def test_taint_propagation_through_intermediate_steps(self) -> None:
        """Taint flows through extract -> transform -> send, blocking the send."""
        interp = _make_interpreter(
            no_side_effect_tools={"extract", "transform"},
        )
        interp.bind(
            "raw", "attacker data",
            Capabilities.untrusted_tool("web", frozenset({"web"})),
        )

        plan = [
            PlanStep(function="extract", args={"input": "raw"}, result_var="extracted"),
            PlanStep(function="transform", args={"input": "extracted"}, result_var="transformed"),
            PlanStep(function="send_email", args={"body": "transformed"}, result_var="sent"),
        ]
        results = interp.execute_plan(plan, _echo_dispatch)

        # extract and transform succeed (no side effects).
        assert results[0]["blocked"] is False
        assert results[1]["blocked"] is False
        # send_email blocks because taint propagated through the DAG.
        assert results[2]["blocked"] is True


class TestMixedCleanAndTaintedInputs:
    def test_mixed_clean_and_tainted_args_blocks(self) -> None:
        """One tainted arg among clean ones blocks side-effecting tools."""
        interp = _make_interpreter(no_side_effect_tools={"merge"})
        interp.bind("clean_data", "safe", Capabilities.user())
        interp.bind(
            "dirty_data", "injected",
            Capabilities.untrusted_tool("web", frozenset({"web"})),
        )

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

        # merge succeeds (no side effects).
        assert results[0]["blocked"] is False
        # send_email blocks: merged value depends on dirty_data.
        assert results[1]["blocked"] is True


class TestNoSideEffectToolAllowsTainted:
    def test_no_side_effect_tool_allows_tainted(self) -> None:
        """Read-only tools allow tainted data through."""
        interp = _make_interpreter(no_side_effect_tools={"log_event"})
        interp.bind(
            "data", "tainted payload",
            Capabilities.untrusted_tool("web", frozenset({"web"})),
        )

        plan = [PlanStep(function="log_event", args={"msg": "data"}, result_var="out")]
        results = interp.execute_plan(plan, _echo_dispatch)

        assert len(results) == 1
        assert results[0]["blocked"] is False


class TestReaderIntersection:
    def test_public_and_restricted_yields_restricted(self) -> None:
        """Public & restricted = restricted (CaMeL's core taint mechanism)."""
        public_val = Value(_python_value="clean", _metadata=Capabilities.user())
        restricted_val = Value(
            _python_value="dirty",
            _metadata=Capabilities.untrusted_tool("web", frozenset({"web"})),
        )

        assert is_public(public_val)
        assert not is_public(restricted_val)

        # A value depending on both inherits the restricted readers.
        combined = Value(
            _python_value="combined",
            _metadata=Capabilities.user(),
            _dependencies=(public_val, restricted_val),
        )
        assert not is_public(combined)

    def test_public_and_public_stays_public(self) -> None:
        a = Value(_python_value="a", _metadata=Capabilities.user())
        b = Value(_python_value="b", _metadata=Capabilities.user())
        combined = Value(
            _python_value="ab",
            _metadata=Capabilities.user(),
            _dependencies=(a, b),
        )
        assert is_public(combined)


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
