"""Argument-level provenance lattice.

The substrate types for v0.12 to v1.0 argument-level enforcement
(ADR 0006). Mirrors the engineering brief Section 1.2 (CaMeL +
FIDES + PCAS hybrid).

Three independent dimensions on every value's label:

- **Sources** identify *where* the value came from. A
  :class:`SegmentRef` is a stable cross-process identifier for one
  context segment, plus the URI it originated at and the SHA-256
  of the MCP manifest that produced it (if any). The set of sources
  is the dependency DAG; binary operations on labels intersect
  readers (most restrictive wins) and union sources.
- **Readers** identify *who* may read the value. Either the
  :class:`Public` singleton or a frozen set of principal IDs.
  Mirrors CaMeL Figure 6 exactly.
- **Integrity / Secrecy / Capacity** form the FIDES lattice.
  ``integrity`` reflects how trustworthy the value is (TRUSTED for
  user input or system-generated, ENDORSED for declassified-via-
  capacity-bound output, UNTRUSTED for tool / web / MCP-flagged-
  open-world). ``secrecy`` reflects how sensitive the value is
  (PUBLIC, INTERNAL, PRIVATE, REGULATED). ``capacity`` is the
  declassification dial: a one-bit channel cannot carry an injection
  payload, so a constrained-decode boolean output of an UNTRUSTED
  context is moved to ENDORSED with capacity=BOOL.

The legacy :class:`tessera.taint.TaintedValue` (segment-index based)
remains available for backward compatibility through v0.x. New code
should use :class:`ProvenanceLabel` + :class:`LabeledValue` directly
or via the convenience constructors at the bottom of this module.

References
----------

- arXiv:2503.18813 (CaMeL): Sources / Readers per-value lattice.
- arXiv:2505.23643 (FIDES): integrity / secrecy / capacity lattice.
- arXiv:2602.16708 (PCAS): dependency DAG for cross-call reasoning.
- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.2.
- ``docs/adr/0006-arg-level-provenance-primary.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Generic, TypeVar, Union

from tessera.labels import TrustLevel

# Type for the wrapped value. Generic so a TaintedStr remains
# subscriptable for type-checkers as ``LabeledValue[str]``.
T = TypeVar("T")

# A principal identifier. Free-form string today; intentionally not
# bound to ``tessera.identity.AgentIdentity`` so labels can be
# constructed without importing the full identity surface.
Principal = str


class IntegrityLevel(IntEnum):
    """FIDES integrity / trust dimension.

    Lower numeric values are *more* trusted. The join of two
    integrity levels is :func:`max` (most restrictive wins).
    """

    #: User input or system-generated content. The Worker's planner
    #: model is the canonical TRUSTED source.
    TRUSTED = 0
    #: Declassified through capacity bound. A bool / enum / int field
    #: produced by a constrained-decode call against UNTRUSTED context
    #: lives here. Cannot be elevated back to TRUSTED.
    ENDORSED = 1
    #: Web / email / MCP tool output flagged ``openWorldHint=true``.
    UNTRUSTED = 2


class SecrecyLevel(IntEnum):
    """FIDES secrecy / confidentiality dimension.

    Higher numeric values are *more* sensitive. The join of two
    secrecy levels is :func:`max` (most restrictive wins).
    """

    PUBLIC = 0
    INTERNAL = 1
    PRIVATE = 2
    #: GDPR / HIPAA / PCI-DSS / SOX / CUI. A side-channel ``DataClass``
    #: sidecar carries the specific regulatory regime.
    REGULATED = 3


class InformationCapacity(IntEnum):
    """FIDES information-capacity dimension.

    The information-capacity bound is the declassification rule:
    constrained decoding into a value with bounded capacity may
    move integrity from UNTRUSTED to ENDORSED. The capacity is the
    enum *index* (BOOL=1, ENUM=2, NUMBER=3, STRING=4); the actual
    bit budget for ENUM is stored separately on the
    :class:`ProvenanceLabel.capacity_bits` field when meaningful.
    """

    #: ~1 bit. Cannot carry an injection payload; safe to declassify.
    BOOL = 1
    #: log2(|enum|) bits. Safe to declassify when |enum| <= 256.
    ENUM = 2
    #: 64 bits. Safe to declassify for numeric fields where the
    #: range itself is policy-bounded (e.g., transfer amount <= cap).
    NUMBER = 3
    #: Unbounded. NEVER auto-declassified. The schema-enforced
    #: WorkerReport boundary may still set integrity=ENDORSED on a
    #: STRING field with explicit per-tool policy approval.
    STRING = 4


class _PublicMarker(Enum):
    """Singleton sentinel for "any reader". CaMeL Figure 6."""

    PUBLIC = "public"


#: Public singleton for "any reader may read this value". When a
#: label's ``readers`` is :data:`Public.PUBLIC`, the value is fully
#: public; otherwise ``readers`` is a ``frozenset[Principal]`` of
#: explicit principals.
Public = _PublicMarker

Readers = Union[_PublicMarker, "frozenset[Principal]"]


@dataclass(frozen=True, slots=True)
class SegmentRef:
    """Stable, cross-process identifier for one context segment.

    Replaces the v0.7 ``frozenset[int]`` of segment indices. The
    string ``segment_id`` survives serialization to the audit log,
    replay, and cross-language interop (Rust gateway). The
    ``origin_uri`` populates SEP-1913 ``attribution`` and the MITRE
    ATLAS ``AML.T0051`` forensic trace. The ``manifest_digest``
    binds the value to the exact MCP manifest version that produced
    it; a rug-pull (manifest changes mid-session) flips the digest
    and any cached values inherit the new label automatically.
    """

    #: Stable cross-process identifier. Format is implementation-
    #: defined; recommended scheme is ``"<session_id>:<seg_index>"``
    #: for in-process use and a content-addressed hash for any value
    #: that survives a process boundary.
    segment_id: str

    #: URI of the segment's origin. Examples:
    #: ``"mcp://gmail.example.com/tools/search"``,
    #: ``"user://session/42"``,
    #: ``"web://news.example.com/article/123"``.
    origin_uri: str

    #: SHA-256 of the MCP manifest that emitted this segment, if
    #: known. ``None`` for user input or system-generated content.
    manifest_digest: str | None = None

    #: Legacy scalar trust level, kept for backward-compatibility
    #: with the v0.7 :class:`tessera.taint.TaintedValue` API.
    trust_level: TrustLevel = TrustLevel.UNTRUSTED


@dataclass(frozen=True, slots=True)
class ProvenanceLabel:
    """A value's full provenance label.

    Five independent dimensions plus the dependency DAG. The label
    is immutable; binary operations on values produce a *new* label
    via :meth:`join`.
    """

    #: The set of source segments that contributed to this value.
    #: Union on join.
    sources: frozenset[SegmentRef]

    #: Who may read this value. :data:`Public.PUBLIC` for any
    #: reader; otherwise a frozenset of principal IDs. *Intersect*
    #: on join (most restrictive wins). CaMeL Figure 6.
    readers: Readers

    #: How trustworthy the value is. *Max* on join.
    integrity: IntegrityLevel

    #: How sensitive the value is. *Max* on join.
    secrecy: SecrecyLevel

    #: Information-capacity bound for declassification.
    capacity: InformationCapacity

    #: For ENUM capacity, the bit budget (``log2(|enum|)``). Unused
    #: for BOOL (=1), NUMBER (=64), STRING (unbounded).
    capacity_bits: int = 0

    #: Lazy back-references to dependency labels for transitive
    #: PCAS-style reasoning. The default empty set is sufficient for
    #: most v0.12 workloads; populated by :meth:`with_deps` when a
    #: caller wants the full DAG.
    deps: frozenset["ProvenanceLabel"] = field(default_factory=frozenset)

    @classmethod
    def trusted_user(
        cls,
        principal: Principal | None = None,
        readers: Readers | None = None,
    ) -> ProvenanceLabel:
        """Construct a label for user-provided content.

        Default: TRUSTED integrity, PUBLIC secrecy, STRING capacity,
        readers=Public. Pass a ``principal`` to attribute the segment
        to a named user; pass explicit ``readers`` to restrict
        visibility.
        """
        return cls(
            sources=frozenset(
                {
                    SegmentRef(
                        segment_id=f"user:{principal or 'anonymous'}",
                        origin_uri=f"user://{principal or 'anonymous'}",
                        trust_level=TrustLevel.USER,
                    )
                }
            ),
            readers=readers if readers is not None else Public.PUBLIC,
            integrity=IntegrityLevel.TRUSTED,
            secrecy=SecrecyLevel.PUBLIC,
            capacity=InformationCapacity.STRING,
        )

    @classmethod
    def untrusted_tool_output(
        cls,
        segment_id: str,
        origin_uri: str,
        manifest_digest: str | None = None,
        secrecy: SecrecyLevel = SecrecyLevel.INTERNAL,
    ) -> ProvenanceLabel:
        """Construct a label for content returned from an MCP tool
        whose manifest annotated ``openWorldHint=true``."""
        return cls(
            sources=frozenset(
                {
                    SegmentRef(
                        segment_id=segment_id,
                        origin_uri=origin_uri,
                        manifest_digest=manifest_digest,
                        trust_level=TrustLevel.UNTRUSTED,
                    )
                }
            ),
            readers=Public.PUBLIC,
            integrity=IntegrityLevel.UNTRUSTED,
            secrecy=secrecy,
            capacity=InformationCapacity.STRING,
        )

    def join(self, other: ProvenanceLabel) -> ProvenanceLabel:
        """Combine two labels per the v1.0 lattice rules.

        ``sources`` union, ``readers`` intersect, ``integrity`` max,
        ``secrecy`` max, ``capacity`` max. Idempotent and
        commutative; see ``tests/invariants/test_label_lattice.py``
        for the algebraic-law property tests.
        """
        return ProvenanceLabel(
            sources=self.sources | other.sources,
            readers=_intersect_readers(self.readers, other.readers),
            integrity=IntegrityLevel(
                max(int(self.integrity), int(other.integrity))
            ),
            secrecy=SecrecyLevel(max(int(self.secrecy), int(other.secrecy))),
            capacity=InformationCapacity(
                max(int(self.capacity), int(other.capacity))
            ),
            capacity_bits=max(self.capacity_bits, other.capacity_bits),
            # Don't propagate deps automatically: caller asks via
            # `with_deps()` if they want the full DAG.
            deps=frozenset(),
        )

    def declassify(
        self, new_capacity: InformationCapacity, new_integrity: IntegrityLevel
    ) -> ProvenanceLabel:
        """Apply an explicit capacity-bounded declassification.

        Used at the schema-enforced WorkerReport boundary: a
        ``bool`` / ``Literal[...]`` / int / Enum field's value moves
        from UNTRUSTED to ENDORSED with the appropriate capacity.
        Caller is responsible for emitting the audit event
        (``LABEL_DECLASSIFY``) and verifying that the declassification
        rule applies (capacity bound, schema field type, no prompt
        leakage from the constrained decode).

        Returns a *new* label; never mutates ``self``. The legitimate
        path is UNTRUSTED to ENDORSED under a capacity bound; same-
        level is also allowed (capacity-only change). The only
        forbidden destination is TRUSTED: that level is reserved for
        the initial labels of user input and system-generated content
        and is unreachable via declassification.
        """
        # In IntegrityLevel numerics: 0=TRUSTED, 1=ENDORSED, 2=UNTRUSTED.
        # The forbidden move is reaching TRUSTED via declassify; the
        # one legitimate trust-raising move (UNTRUSTED -> ENDORSED) is
        # the whole point of capacity-bounded declassification.
        if (
            new_integrity == IntegrityLevel.TRUSTED
            and self.integrity != IntegrityLevel.TRUSTED
        ):
            raise ValueError(
                f"declassify cannot raise integrity from {self.integrity!r} "
                f"to {new_integrity!r}; TRUSTED is reserved for initial "
                f"labels and is unreachable via declassification"
            )
        return ProvenanceLabel(
            sources=self.sources,
            readers=self.readers,
            integrity=new_integrity,
            secrecy=self.secrecy,
            capacity=new_capacity,
            capacity_bits=self.capacity_bits,
            deps=self.deps,
        )

    def with_deps(
        self, deps: "frozenset[ProvenanceLabel]"
    ) -> ProvenanceLabel:
        """Return a copy with the given dependency back-references.

        Use sparingly: the dependency DAG can grow large for long
        sessions. The PCAS-style Datalog policies (Phase 3 wave 3A)
        consume the DAG; per-tool-call deterministic policy does not.
        """
        return ProvenanceLabel(
            sources=self.sources,
            readers=self.readers,
            integrity=self.integrity,
            secrecy=self.secrecy,
            capacity=self.capacity,
            capacity_bits=self.capacity_bits,
            deps=deps,
        )

    @property
    def trust_level(self) -> TrustLevel:
        """Lowest-trust ``TrustLevel`` across all sources, for
        backward-compat with the v0.7 scalar API. Computed from
        ``min(s.trust_level for s in self.sources)`` with SYSTEM as
        the empty-set default."""
        if not self.sources:
            return TrustLevel.SYSTEM
        return min(s.trust_level for s in self.sources)


@dataclass(frozen=True, slots=True)
class LabeledValue(Generic[T]):
    """A value carrying a :class:`ProvenanceLabel`.

    The new generic wrapper for argument-level enforcement. Coexists
    with the legacy ``tessera.taint.TaintedValue`` through v0.x;
    ADR 0006 deprecates the legacy class in v1.0.

    The wrapped ``raw`` attribute holds the actual Python value.
    Operations on ``LabeledValue`` produce *new* instances with
    joined labels; ``LabeledValue`` is never mutated in place.
    """

    raw: T
    label: ProvenanceLabel

    @classmethod
    def from_user(cls, value: T, principal: Principal | None = None) -> LabeledValue[T]:
        """Convenience constructor for user-provided values."""
        return cls(raw=value, label=ProvenanceLabel.trusted_user(principal))

    @classmethod
    def from_tool_output(
        cls,
        value: T,
        segment_id: str,
        origin_uri: str,
        manifest_digest: str | None = None,
        secrecy: SecrecyLevel = SecrecyLevel.INTERNAL,
    ) -> LabeledValue[T]:
        """Convenience constructor for MCP tool output values."""
        return cls(
            raw=value,
            label=ProvenanceLabel.untrusted_tool_output(
                segment_id=segment_id,
                origin_uri=origin_uri,
                manifest_digest=manifest_digest,
                secrecy=secrecy,
            ),
        )


def _intersect_readers(a: Readers, b: Readers) -> Readers:
    """Reader intersection rule (CaMeL Figure 6).

    ``Public ∩ Public = Public``;
    ``Public ∩ S = S`` (Public is the universal set, intersect
    with any explicit set keeps only that set);
    ``S1 ∩ S2 = the set intersection`` (most restrictive wins).
    """
    if a is Public.PUBLIC and b is Public.PUBLIC:
        return Public.PUBLIC
    if a is Public.PUBLIC:
        return b
    if b is Public.PUBLIC:
        return a
    # Both are explicit reader sets.
    assert isinstance(a, frozenset) and isinstance(b, frozenset)
    return frozenset(a & b)


def label_of(value: Any) -> ProvenanceLabel:
    """Return the label for ``value``, or a permissive default.

    For ``LabeledValue`` and ``TaintedStr`` (Phase 1B-i, future)
    instances, returns the carried label. For bare values (literals,
    untainted strings, ints, etc.), returns a TRUSTED user label
    with PUBLIC readers and STRING capacity. Used as the safe
    fall-through during operations on mixed-shape inputs.
    """
    if isinstance(value, LabeledValue):
        return value.label
    label = getattr(value, "_label", None)
    if isinstance(label, ProvenanceLabel):
        return label
    return ProvenanceLabel.trusted_user()


def join_labels(*labels: ProvenanceLabel) -> ProvenanceLabel:
    """Reduce a sequence of labels with :meth:`ProvenanceLabel.join`.

    Returns the trusted-user identity label when called with no
    arguments, so callers can fold over an empty argument list
    without special-casing.
    """
    iterator = iter(labels)
    try:
        first = next(iterator)
    except StopIteration:
        return ProvenanceLabel.trusted_user()
    result = first
    for next_label in iterator:
        result = result.join(next_label)
    return result


__all__ = [
    "IntegrityLevel",
    "SecrecyLevel",
    "InformationCapacity",
    "Public",
    "Principal",
    "Readers",
    "SegmentRef",
    "ProvenanceLabel",
    "LabeledValue",
    "label_of",
    "join_labels",
]
