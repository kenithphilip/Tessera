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


_LEGACY_SEGMENT_PREFIX = "legacy:segment:"


class TaintedValue:
    """A value annotated with which context segments it depends on.

    Phase 1 wave 1A reshaped this class so the canonical source of
    provenance is :class:`tessera.taint.label.ProvenanceLabel`. The
    legacy ``sources: frozenset[int]`` constructor keyword still
    works for backward compatibility; internally it synthesizes a
    :class:`ProvenanceLabel` whose :class:`SegmentRef` ids are
    namespaced under ``legacy:segment:<index>``. The
    :attr:`sources` attribute is now a ``@property`` that returns
    ``frozenset[int]`` derived from ``self.label.sources``, so old
    callers continue to read the integer-index view they expect
    while the underlying state moves to the richer label.

    New callers should pass ``label=`` directly:

        from tessera.taint.label import ProvenanceLabel
        TaintedValue(value="abc", label=ProvenanceLabel.trusted_user("alice"))
    """

    __slots__ = ("value", "_label")

    def __init__(
        self,
        value: Any,
        sources: frozenset[int] | None = None,
        *,
        label: Any = None,
    ) -> None:
        self.value = value
        if label is not None and sources is not None:
            raise ValueError(
                "TaintedValue: pass either `sources=` (legacy) or `label=` "
                "(v0.12+); not both"
            )
        if label is not None:
            self._label = label
        else:
            self._label = _legacy_label_from_sources(sources or frozenset())

    @property
    def label(self) -> Any:
        """The underlying :class:`ProvenanceLabel` source of truth."""
        return self._label

    @property
    def sources(self) -> frozenset[int]:
        """Legacy view: the segment-index frozenset derived from
        ``self.label.sources``. Indices are extracted from
        :class:`SegmentRef` ids under the ``legacy:segment:<i>``
        namespace; non-legacy segments contribute the hash of their
        id (``hash(id) & 0xFFFFFFFF``) so the legacy API never
        crashes on a label that mixes new and legacy refs."""
        out: set[int] = set()
        for ref in self._label.sources:
            seg_id = getattr(ref, "segment_id", str(ref))
            if seg_id.startswith(_LEGACY_SEGMENT_PREFIX):
                try:
                    out.add(int(seg_id[len(_LEGACY_SEGMENT_PREFIX) :]))
                except ValueError:
                    out.add(hash(seg_id) & 0xFFFFFFFF)
            else:
                out.add(hash(seg_id) & 0xFFFFFFFF)
        return frozenset(out)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TaintedValue):
            return NotImplemented
        return (
            self.value == other.value
            and self.sources == other.sources
        )

    def __hash__(self) -> int:
        return hash((repr(self.value), self.sources))

    def __repr__(self) -> str:
        return (
            f"TaintedValue(value={self.value!r}, "
            f"sources={sorted(self.sources)!r})"
        )

    def trust_level(self, context: Context) -> TrustLevel:
        """Minimum trust across all source segments.

        Returns :attr:`TrustLevel.SYSTEM` when ``sources`` is empty
        OR when every entry in ``sources`` falls outside the
        context's segment range (the latter happens when a label is
        attached to a value that was constructed against a different
        context, e.g. after deserialization).
        """
        if not self.sources:
            return TrustLevel.SYSTEM
        in_range = [
            context.segments[i].label.trust_level
            for i in self.sources
            if i < len(context.segments)
        ]
        if not in_range:
            return TrustLevel.SYSTEM
        return min(in_range)

    def is_tainted(
        self, context: Context, threshold: TrustLevel = TrustLevel.USER
    ) -> bool:
        """True if any source segment is below the threshold."""
        return self.trust_level(context) < threshold

    def merge(self, other: TaintedValue) -> TaintedValue:
        """Combine two values' source sets (union)."""
        return TaintedValue(
            value=self.value,
            sources=self.sources | other.sources,
        )


def _legacy_label_from_sources(sources: frozenset[int]) -> Any:
    """Build a :class:`ProvenanceLabel` from a legacy index frozenset.

    Lazy import so this module works even when ``tessera.taint.label``
    is not yet available during early bootstrap.
    """
    from tessera.taint.label import (
        IntegrityLevel,
        ProvenanceLabel,
        Public,
        SecrecyLevel,
        SegmentRef,
        TrustLevel as TaintTrustLevel,
        InformationCapacity,
    )

    if not sources:
        # Match the legacy semantics: empty sources == trusted-user
        # value with no segment dependencies. ProvenanceLabel allows
        # empty sources so the .sources property returns frozenset().
        return ProvenanceLabel(
            sources=frozenset(),
            readers=Public.PUBLIC,
            integrity=IntegrityLevel.TRUSTED,
            secrecy=SecrecyLevel.PUBLIC,
            capacity=InformationCapacity.STRING,
        )
    refs = frozenset(
        SegmentRef(
            segment_id=f"{_LEGACY_SEGMENT_PREFIX}{i}",
            origin_uri=f"legacy://segment/{i}",
            trust_level=TaintTrustLevel.UNTRUSTED,
        )
        for i in sources
    )
    return ProvenanceLabel(
        sources=refs,
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.UNTRUSTED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
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
        """Bind a value to the context segment it came from.

        Searches context segments in reverse for one whose content contains
        the string representation of the value. Prefers the highest-trust
        matching segment (if the value appears in both a clean and a
        tainted segment, bind to the clean one).

        If no segment contains the value, the value was model-generated
        (computed from trusted context, formatted by the model, etc.)
        and is treated as user-provided.
        """
        str_val = str(value)
        if len(str_val) < 3:
            # Very short values (numbers, single chars) match too broadly.
            # Treat as model-generated.
            self.bindings[name] = from_user(value)
            return

        # Find all segments that contain this value
        matches: list[tuple[int, TrustLevel]] = []
        for i in range(len(self.context.segments) - 1, -1, -1):
            seg = self.context.segments[i]
            if str_val in seg.content:
                matches.append((i, seg.label.trust_level))

        if matches:
            # Prefer the highest-trust match. If the value appears in
            # both a USER segment and an UNTRUSTED segment, the user
            # mentioned it, so it's clean.
            best = max(matches, key=lambda m: m[1])
            self.bindings[name] = from_segment(value, best[0])
            return

        # Value not found in any segment: model-generated.
        # The model computed this value from its reasoning (e.g.,
        # formatted a date, composed an address, calculated a price).
        # Not attributable to any untrusted source.
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
