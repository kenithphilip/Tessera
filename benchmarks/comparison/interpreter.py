"""Faithful CaMeL value system for benchmark comparison.

Reimplements the core security mechanisms from CaMeL (Debenedetti et al,
2025, Google DeepMind) that drive their reported overhead: the CaMeLValue
wrapper with dependency DAG, Capabilities (Sources + Readers), recursive
DAG walking for taint propagation, and the SecurityPolicyEngine with
fnmatch-based tool matching and reader-based access control.

This does NOT reimplement CaMeL's full 2,700-line Python AST interpreter.
It captures the security-layer overhead: value wrapping, dependency
tracking, DAG traversal for source/reader computation, and policy checks.
The full interpreter adds AST parsing and evaluation overhead on top of
this, so our numbers are a lower bound on CaMeL's actual cost.

Reference: github.com/google-deepmind/camel-prompt-injection
License of original: Apache 2.0
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Protocol, TypeAlias, runtime_checkable


# --- Sources (who produced the data) ---

class SourceEnum(Enum):
    """Built-in data sources, matching CaMeL's SourceEnum."""
    CaMeL = auto()
    User = auto()
    Assistant = auto()
    TrustedToolSource = auto()


@dataclass(frozen=True)
class Tool:
    """Tool-originated data source with optional inner source tracking."""
    tool_name: str
    inner_sources: frozenset[str | SourceEnum] = field(default_factory=frozenset)

    def __hash__(self) -> int:
        return hash(self.tool_name) ^ hash(tuple(self.inner_sources))


Source: TypeAlias = SourceEnum | Tool


# --- Readers (who can see the data) ---

@dataclass(frozen=True)
class Public:
    """Data readable by anyone. Intersection with anything returns the other."""

    def __hash__(self) -> int:
        return 7810134600596034160  # fixed hash, matching CaMeL

    def __and__(self, other: Readers) -> Readers:
        if not isinstance(other, frozenset | Public):
            return NotImplemented
        return other

    def __rand__(self, other: Readers) -> Readers:
        if not isinstance(other, frozenset | Public):
            return NotImplemented
        return other


Readers: TypeAlias = frozenset | Public


# --- Capabilities (metadata on each value) ---

@dataclass(frozen=True)
class Capabilities:
    """Sources and readers attached to a CaMeLValue."""
    sources_set: frozenset[Source]
    readers_set: Readers

    def __hash__(self) -> int:
        return hash(self.sources_set) ^ hash(self.readers_set)

    @classmethod
    def user(cls) -> Capabilities:
        return cls(frozenset({SourceEnum.User}), Public())

    @classmethod
    def tool(cls, tool_name: str) -> Capabilities:
        return cls(frozenset({Tool(tool_name)}), Public())

    @classmethod
    def untrusted_tool(cls, tool_name: str, restricted_to: frozenset) -> Capabilities:
        return cls(frozenset({Tool(tool_name)}), restricted_to)


# --- CaMeLValue (the core wrapper) ---

@runtime_checkable
class CaMeLValue(Protocol):
    """Protocol matching CaMeL's value wrapper.

    Every value in the interpreter is wrapped with metadata (Capabilities)
    and a tuple of parent dependencies. The dependency DAG is what makes
    taint propagation work: to check if a value is safe, you walk its
    entire ancestry.
    """
    _python_value: Any
    _metadata: Capabilities
    _dependencies: tuple[CaMeLValue, ...]


@dataclass
class Value:
    """Concrete CaMeLValue implementation for the benchmark."""
    _python_value: Any
    _metadata: Capabilities
    _dependencies: tuple[CaMeLValue, ...] = ()

    @property
    def raw(self) -> Any:
        return self._python_value

    def with_dependencies(self, *deps: CaMeLValue) -> Value:
        """Return a new Value with additional dependencies appended."""
        return Value(
            _python_value=self._python_value,
            _metadata=self._metadata,
            _dependencies=self._dependencies + deps,
        )


# --- DAG walking utilities ---

def get_all_readers(
    value: CaMeLValue,
    visited: frozenset[int] = frozenset(),
) -> tuple[Readers, frozenset[int]]:
    """Walk the dependency DAG, intersecting readers at each node.

    This is where CaMeL's overhead lives. For a value with N ancestors,
    this visits every node and computes reader intersections. Public & x = x,
    so a single restricted reader anywhere in the DAG restricts the result.
    """
    if id(value) in visited:
        return value._metadata.readers_set, visited
    result_readers = value._metadata.readers_set
    for dep in value._dependencies:
        dep_readers, visited = get_all_readers(dep, visited | {id(value)})
        result_readers = result_readers & dep_readers
    return result_readers, visited | {id(value)}


def get_all_sources(
    value: CaMeLValue,
    visited: frozenset[int] = frozenset(),
) -> tuple[frozenset[Source], frozenset[int]]:
    """Walk the dependency DAG, unioning sources at each node."""
    if id(value) in visited:
        return frozenset(), visited
    result_sources = value._metadata.sources_set
    for dep in value._dependencies:
        dep_sources, visited = get_all_sources(dep, visited | {id(value)})
        result_sources = result_sources | dep_sources
    return result_sources, visited


def is_public(value: CaMeLValue) -> bool:
    """True if the value's effective readers (after DAG walk) are Public."""
    readers, _ = get_all_readers(value)
    return isinstance(readers, Public)


# --- Security policy engine ---

@dataclass(frozen=True)
class Allowed:
    """Tool call permitted."""


@dataclass(frozen=True)
class Denied:
    """Tool call blocked."""
    reason: str


SecurityPolicyResult: TypeAlias = Allowed | Denied

SecurityPolicyFn: TypeAlias = Callable[[str, dict[str, CaMeLValue]], SecurityPolicyResult]


def base_security_policy(
    tool_name: str,
    kwargs: dict[str, CaMeLValue],
    no_side_effect_tools: set[str],
) -> SecurityPolicyResult:
    """If any argument has non-public readers and the tool has side effects, deny."""
    readers_list = [get_all_readers(v) for v in kwargs.values()]
    if any(not isinstance(r, Public) for r, _ in readers_list) and tool_name not in no_side_effect_tools:
        return Denied("Data is not public.")
    return Allowed()


@dataclass
class SecurityPolicyEngine:
    """Matches CaMeL's SecurityPolicyEngine protocol.

    Evaluation order:
    1. If tool is in no_side_effect_tools, allow immediately.
    2. Walk dependencies of all arguments. If any dependency has
       non-public readers, deny (the tool is state-changing).
    3. Run fnmatch-based policy rules in order. First match wins.
    4. If no policy matches, deny by default.
    """
    policies: list[tuple[str, SecurityPolicyFn]] = field(default_factory=list)
    no_side_effect_tools: set[str] = field(default_factory=set)

    def check_policy(
        self,
        tool_name: str,
        kwargs: dict[str, CaMeLValue],
        dependencies: list[CaMeLValue],
    ) -> SecurityPolicyResult:
        if tool_name in self.no_side_effect_tools:
            return Allowed()
        non_public = [d.raw for d in dependencies if not is_public(d)]
        if non_public:
            return Denied(
                f"{tool_name} is state-changing and depends on "
                f"private values {non_public}."
            )
        for pattern, policy_fn in self.policies:
            if fnmatch.fnmatch(tool_name, pattern):
                return policy_fn(tool_name, kwargs)
        return Denied("No security policy matched. Defaulting to denial.")


# --- Plan execution ---

@dataclass(frozen=True)
class PlanStep:
    """One step in a CaMeL execution plan."""
    function: str
    args: dict[str, str]  # param name -> variable reference
    result_var: str


class CapabilityViolation(Exception):
    """Raised when a tool call is denied by the security policy."""


@dataclass
class CaMeLInterpreter:
    """Execute a plan with CaMeL's value-level taint tracking.

    Each variable binding is a full CaMeLValue with Capabilities metadata
    and a dependency tuple pointing to its parent values. Tool dispatch
    walks the entire dependency DAG to compute effective readers, then
    runs the SecurityPolicyEngine check.
    """
    policy_engine: SecurityPolicyEngine
    variables: dict[str, Value] = field(default_factory=dict)

    def bind(self, name: str, python_value: Any, capabilities: Capabilities) -> None:
        """Bind a variable as a CaMeLValue with the given capabilities."""
        self.variables[name] = Value(
            _python_value=python_value,
            _metadata=capabilities,
        )

    def _resolve(self, args: dict[str, str]) -> dict[str, Value]:
        resolved: dict[str, Value] = {}
        for param, var_ref in args.items():
            if var_ref not in self.variables:
                raise KeyError(f"unresolved variable: {var_ref!r}")
            resolved[param] = self.variables[var_ref]
        return resolved

    def _collect_dependencies(self, resolved: dict[str, Value]) -> list[Value]:
        """Collect all transitive dependencies for the policy check.

        This matches CaMeL's behavior: the policy engine receives the
        full dependency set, not just the immediate arguments.
        """
        deps: list[Value] = []
        visited: set[int] = set()
        stack = list(resolved.values())
        while stack:
            val = stack.pop()
            vid = id(val)
            if vid in visited:
                continue
            visited.add(vid)
            deps.append(val)
            for d in val._dependencies:
                if isinstance(d, Value):
                    stack.append(d)
        return deps

    def execute_plan(
        self,
        plan: list[PlanStep],
        tool_dispatch: Callable[[str, dict[str, Any]], Any],
    ) -> list[dict[str, Any]]:
        """Execute plan steps with full CaMeL-style security checks."""
        results: list[dict[str, Any]] = []

        for step in plan:
            resolved = self._resolve(step.args)
            all_deps = self._collect_dependencies(resolved)

            # Run the security policy engine (the expensive part).
            decision = self.policy_engine.check_policy(
                step.function, resolved, all_deps,
            )

            if isinstance(decision, Denied):
                results.append({
                    "tool": step.function,
                    "blocked": True,
                    "reason": decision.reason,
                })
                # Bind a sentinel so downstream references resolve.
                self.variables[step.result_var] = Value(
                    _python_value=None,
                    _metadata=Capabilities(
                        frozenset({Tool(step.function)}),
                        frozenset(),  # empty readers = maximally restricted
                    ),
                    _dependencies=tuple(resolved.values()),
                )
                continue

            # Tool is allowed. Dispatch it.
            raw_args = {k: v._python_value for k, v in resolved.items()}
            result_value = tool_dispatch(step.function, raw_args)

            # Bind the result as a new CaMeLValue with the tool as source
            # and all input values as dependencies (for DAG propagation).
            self.variables[step.result_var] = Value(
                _python_value=result_value,
                _metadata=Capabilities.tool(step.function),
                _dependencies=tuple(resolved.values()),
            )

            results.append({
                "tool": step.function,
                "blocked": False,
                "result": result_value,
            })

        return results


def parse_plan(plan_text: str) -> list[PlanStep]:
    """Parse pseudo-Python plan text into PlanStep objects."""
    steps: list[PlanStep] = []
    for line in plan_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        result_var, _, rhs = line.partition("=")
        result_var = result_var.strip()
        rhs = rhs.strip()
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
