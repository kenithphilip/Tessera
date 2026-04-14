"""Value-level taint tracking and dependency accumulation.

Context-level min_trust answers "is anything in the window untrusted?"
Value-level taint answers "does THIS specific value depend on untrusted
data?" This is the difference between blocking all sends when any tool
output is untrusted vs blocking only sends where the recipient came from
untrusted data.

Core abstraction: TaintedValue wraps any Python value with a provenance
set (which segments contributed to it). The DependencyAccumulator tracks
a session's data flow graph, recording which tool outputs influenced
which tool call arguments.

Source attribution: CaMeL's per-variable Capabilities/readers model.
Tessera's version uses segment indices rather than CaMeL's frozenset
reader intersection, because Tessera already has TrustLabel on each
segment. We compute taint from the labels rather than duplicating
the reader lattice.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tessera.context import Context, LabeledSegment
from tessera.labels import TrustLevel


@dataclass(frozen=True)
class TaintedValue:
    """A value annotated with which context segments it depends on.

    The value can be anything (str, int, dict). The sources set tracks
    segment indices into the parent Context. If any source segment is
    UNTRUSTED, the value is tainted.
    """

    value: Any
    sources: frozenset[int]  # indices into Context.segments

    def trust_level(self, context: Context) -> TrustLevel:
        """Minimum trust across all source segments."""
        if not self.sources:
            return TrustLevel.SYSTEM
        return min(
            context.segments[i].label.trust_level
            for i in self.sources
            if i < len(context.segments)
        )

    def is_tainted(self, context: Context, threshold: TrustLevel = TrustLevel.USER) -> bool:
        """True if any source segment is below the threshold."""
        return self.trust_level(context) < threshold

    def merge(self, other: TaintedValue) -> TaintedValue:
        """Combine two values' source sets (union). Used when a value
        is derived from multiple inputs."""
        return TaintedValue(
            value=self.value,
            sources=self.sources | other.sources,
        )


def from_user(value: Any) -> TaintedValue:
    """Create a value with no dependencies (user-provided, fully trusted)."""
    return TaintedValue(value=value, sources=frozenset())


def from_segment(value: Any, segment_index: int) -> TaintedValue:
    """Create a value that depends on a specific context segment."""
    return TaintedValue(value=value, sources=frozenset({segment_index}))


@dataclass
class DependencyAccumulator:
    """Track data flow across tool calls within a session.

    Records which tool outputs (segments) contributed to which tool call
    arguments, enabling per-argument taint checking instead of per-context
    taint checking.

    Usage::

        acc = DependencyAccumulator(context)

        # User typed the recipient
        acc.bind("recipient", from_user("alice@acme.com"))

        # Tool output at segment 3 provided the amount
        acc.bind("amount", from_segment(98.70, 3))

        # Check if a tool call's arguments are clean
        decision = acc.evaluate_args(
            "send_money",
            {"recipient": "alice@acme.com", "amount": 98.70},
            critical_args={"recipient"},  # only these must be user-sourced
        )
    """

    context: Context
    bindings: dict[str, TaintedValue] = field(default_factory=dict)

    def bind(self, name: str, value: TaintedValue) -> None:
        """Bind a named value with its provenance."""
        self.bindings[name] = value

    def bind_from_user(self, name: str, value: Any) -> None:
        """Shorthand: bind a user-provided value (no taint)."""
        self.bindings[name] = from_user(value)

    def bind_from_segment(self, name: str, value: Any, segment_index: int) -> None:
        """Shorthand: bind a value from a specific context segment."""
        self.bindings[name] = from_segment(value, segment_index)

    def bind_from_tool_output(self, name: str, value: Any, tool_name: str) -> None:
        """Bind a value from the most recent segment matching a tool name.

        Searches context segments in reverse for one whose content contains
        the string representation of the value. Falls back to the last
        non-USER segment if no exact match is found.
        """
        str_val = str(value)
        for i in range(len(self.context.segments) - 1, -1, -1):
            seg = self.context.segments[i]
            if str_val in seg.content:
                self.bindings[name] = from_segment(value, i)
                return
        # Fallback: attribute to the last non-USER segment
        for i in range(len(self.context.segments) - 1, -1, -1):
            seg = self.context.segments[i]
            if seg.label.trust_level < TrustLevel.USER:
                self.bindings[name] = from_segment(value, i)
                return
        self.bindings[name] = from_user(value)

    def get_taint(self, name: str) -> TaintedValue | None:
        """Look up a binding's taint info."""
        return self.bindings.get(name)

    def evaluate_args(
        self,
        tool_name: str,
        args: dict[str, Any],
        critical_args: frozenset[str] | None = None,
        threshold: TrustLevel = TrustLevel.USER,
    ) -> ArgTaintResult:
        """Check whether a tool call's arguments are clean.

        Args:
            tool_name: Name of the tool being called.
            args: The tool call's arguments.
            critical_args: Argument names that MUST be user-sourced for the
                call to be allowed. If None, all args are checked. Common
                critical args: recipient, to, url, amount, target.
            threshold: Trust level below which an arg is considered tainted.

        Returns:
            ArgTaintResult with per-argument taint status.
        """
        check_args = critical_args if critical_args is not None else frozenset(args.keys())
        tainted_args: dict[str, TrustLevel] = {}
        clean_args: set[str] = set()
        unknown_args: set[str] = set()

        for arg_name in check_args:
            if arg_name not in args:
                continue
            binding = self.bindings.get(arg_name)
            if binding is None:
                unknown_args.add(arg_name)
                continue
            level = binding.trust_level(self.context)
            if level < threshold:
                tainted_args[arg_name] = level
            else:
                clean_args.add(arg_name)

        return ArgTaintResult(
            tool_name=tool_name,
            tainted_args=tainted_args,
            clean_args=clean_args,
            unknown_args=unknown_args,
            passed=len(tainted_args) == 0,
        )


@dataclass(frozen=True)
class ArgTaintResult:
    """Result of per-argument taint evaluation."""

    tool_name: str
    tainted_args: dict[str, TrustLevel]  # arg_name -> observed trust
    clean_args: set[str]
    unknown_args: set[str]  # args with no binding (cannot determine provenance)
    passed: bool

    @property
    def reason(self) -> str | None:
        if self.passed:
            return None
        parts = []
        for arg, level in self.tainted_args.items():
            parts.append(f"argument {arg!r} has trust_level={int(level)} (from untrusted source)")
        return "; ".join(parts)


# Common critical argument sets for well-known tool patterns.
CRITICAL_ARGS_SEND = frozenset({"to", "recipient", "recipients", "email", "destination"})
CRITICAL_ARGS_TRANSFER = frozenset({"recipient", "to", "account", "iban", "amount"})
CRITICAL_ARGS_WRITE = frozenset({"path", "file_path", "filename", "url", "endpoint"})
CRITICAL_ARGS_EXECUTE = frozenset({"command", "code", "script", "query"})
