"""Minimal CaMeL-style interpreter for benchmark comparison.

CaMeL (Debenedetti et al, 2025) uses a custom interpreter that executes
LLM-generated pseudo-Python, tracking data provenance with capability-based
security. This module faithfully captures the overhead characteristics of
that approach: variable-level taint tracking, taint propagation through
intermediate steps, and capability checks before tool dispatch.

The interpreter does NOT reimplement CaMeL's full semantics. It captures
the computational work that drives their reported 6.6x latency cost:
parsing a plan, maintaining a taint store, propagating taint through
dataflow, and checking capabilities before each tool call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class TaintedValue:
    """A value with provenance tracking.

    CaMeL tracks taint at the variable level. Each value knows whether it
    originated from clean (user-controlled) or tainted (attacker-influenced)
    data, and which execution step produced it.
    """

    value: Any
    taint: str  # "clean" or "tainted"
    source: str  # which step produced this


@dataclass(frozen=True)
class PlanStep:
    """One step in a CaMeL execution plan.

    Maps to a single function call in CaMeL's pseudo-Python output.
    Args reference variable names from previous steps or initial bindings.
    """

    function: str
    args: dict[str, str]  # param name -> variable reference
    result_var: str


@dataclass(frozen=True)
class Capability:
    """Access control for a single tool.

    When requires_clean is True, the interpreter blocks execution if any
    argument carries tainted provenance. This is CaMeL's mechanism for
    preventing exfiltration: sensitive tools (send_email, write_file)
    require clean inputs, so tainted data from scraped content cannot
    reach them.
    """

    tool: str
    requires_clean: bool


class CapabilityViolation(Exception):
    """Raised when a tool call violates its capability constraint.

    Analogous to Tessera's PolicyViolation, but triggered by variable-level
    taint rather than context-level min_trust.
    """


@dataclass
class CaMeLInterpreter:
    """Execute a plan with variable-level taint tracking and capability checks.

    The interpreter maintains a variable store where each binding carries
    taint metadata. When executing a step:

    1. Resolve all argument variable references.
    2. Compute the output taint: if ANY input is tainted, the output is tainted.
    3. Check the tool's capability: if it requires clean data and any arg
       is tainted, raise CapabilityViolation.
    4. Dispatch the tool call and bind the result.

    This faithfully models the overhead characteristics of CaMeL's approach.
    The per-step cost is: dict lookups for variable resolution, taint
    propagation (an any() over the args), capability check (a dict lookup
    plus a conditional), and the tool dispatch itself.
    """

    capabilities: dict[str, Capability] = field(default_factory=dict)
    variables: dict[str, TaintedValue] = field(default_factory=dict)

    def set_variable(self, name: str, value: Any, taint: str, source: str) -> None:
        """Bind a variable with explicit taint metadata."""
        self.variables[name] = TaintedValue(value=value, taint=taint, source=source)

    def _resolve_args(self, args: dict[str, str]) -> dict[str, TaintedValue]:
        """Resolve variable references to their TaintedValue bindings."""
        resolved: dict[str, TaintedValue] = {}
        for param, var_ref in args.items():
            if var_ref not in self.variables:
                raise KeyError(f"unresolved variable reference: {var_ref!r}")
            resolved[param] = self.variables[var_ref]
        return resolved

    def _propagate_taint(self, inputs: dict[str, TaintedValue]) -> str:
        """If any input is tainted, the output is tainted."""
        if any(tv.taint == "tainted" for tv in inputs.values()):
            return "tainted"
        return "clean"

    def _check_capability(self, tool: str, resolved: dict[str, TaintedValue]) -> None:
        """Raise CapabilityViolation if a sensitive tool receives tainted data."""
        cap = self.capabilities.get(tool)
        if cap is None:
            return
        if not cap.requires_clean:
            return
        tainted_args = [
            name for name, tv in resolved.items() if tv.taint == "tainted"
        ]
        if tainted_args:
            raise CapabilityViolation(
                f"tool {tool!r} requires clean inputs, but args "
                f"{tainted_args} are tainted"
            )

    def execute_plan(
        self,
        plan: list[PlanStep],
        tool_dispatch: Callable[[str, dict[str, Any]], Any],
    ) -> list[dict[str, Any]]:
        """Execute a sequence of plan steps with taint tracking.

        Args:
            plan: Ordered list of steps to execute.
            tool_dispatch: Callable that runs a tool given (name, args_dict).
                The args_dict contains raw values (unwrapped from TaintedValue).

        Returns:
            List of execution records, one per step, containing the tool name,
            result, output taint, and whether the step was blocked.
        """
        results: list[dict[str, Any]] = []

        for step in plan:
            resolved = self._resolve_args(step.args)
            output_taint = self._propagate_taint(resolved)

            try:
                self._check_capability(step.function, resolved)
            except CapabilityViolation as exc:
                results.append({
                    "tool": step.function,
                    "blocked": True,
                    "reason": str(exc),
                    "output_taint": output_taint,
                })
                # Bind the result variable as tainted with a sentinel value
                # so downstream steps can still resolve references.
                self.set_variable(
                    step.result_var,
                    None,
                    taint="tainted",
                    source=f"{step.function}:blocked",
                )
                continue

            # Unwrap TaintedValues to raw values for the tool dispatch.
            raw_args = {k: tv.value for k, tv in resolved.items()}
            result_value = tool_dispatch(step.function, raw_args)

            self.set_variable(
                step.result_var,
                result_value,
                taint=output_taint,
                source=step.function,
            )

            results.append({
                "tool": step.function,
                "blocked": False,
                "result": result_value,
                "output_taint": output_taint,
            })

        return results


def parse_plan(plan_text: str) -> list[PlanStep]:
    """Parse a simple pseudo-Python plan into PlanStep objects.

    Handles lines of the form:
        result_var = function_name(arg1=var1, arg2=var2)

    This is a minimal parser, not a full Python interpreter. It handles
    the subset of syntax that CaMeL's planner emits.
    """
    steps: list[PlanStep] = []
    for line in plan_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Split on first "="
        result_var, _, rhs = line.partition("=")
        result_var = result_var.strip()
        rhs = rhs.strip()

        # Extract function name and args from "func(arg1=val1, arg2=val2)"
        func_name, _, args_str = rhs.partition("(")
        func_name = func_name.strip()
        args_str = args_str.rstrip(")").strip()

        args: dict[str, str] = {}
        if args_str:
            for pair in args_str.split(","):
                key, _, val = pair.partition("=")
                args[key.strip()] = val.strip()

        steps.append(PlanStep(function=func_name, args=args, result_var=result_var))

    return steps
