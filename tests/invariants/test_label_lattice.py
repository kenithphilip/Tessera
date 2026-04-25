"""Algebraic-law property tests for the ProvenanceLabel lattice.

The lattice operations (join + readers intersection) MUST satisfy
the standard laws so v0.12 enforcement is composable across the
full call graph. Failure here is a security regression.

Laws tested
-----------

For ``join``:

- **Idempotence**: ``a.join(a) == a``.
- **Commutativity**: ``a.join(b) == b.join(a)``.
- **Associativity**: ``(a.join(b)).join(c) == a.join(b.join(c))``.

For ``join`` per dimension:

- **sources**: union (monotonically grows).
- **readers**: intersection (most restrictive wins).
- **integrity**: max (UNTRUSTED dominates).
- **secrecy**: max (REGULATED dominates).
- **capacity**: max (STRING dominates BOOL).

For ``declassify``:

- Cannot raise integrity (raise rejected).
- Returns a NEW label (immutable in place).

References
----------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.3
  (Label join semantics table).
- ``docs/adr/0006-arg-level-provenance-primary.md``.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tessera.labels import TrustLevel
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
    LabeledValue,
    ProvenanceLabel,
    Public,
    SecrecyLevel,
    SegmentRef,
    join_labels,
    label_of,
)


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------


@st.composite
def segment_refs(draw) -> SegmentRef:
    """A SegmentRef with a random id, URI, and trust level."""
    seg_id = draw(st.text(min_size=1, max_size=20))
    uri_kind = draw(st.sampled_from(["mcp", "user", "web", "tool"]))
    uri = f"{uri_kind}://example/{seg_id}"
    digest = draw(
        st.one_of(
            st.none(),
            st.text(
                alphabet="0123456789abcdef", min_size=64, max_size=64
            ).map(lambda s: f"sha256:{s}"),
        )
    )
    trust = draw(
        st.sampled_from(
            [
                TrustLevel.UNTRUSTED,
                TrustLevel.TOOL,
                TrustLevel.USER,
                TrustLevel.SYSTEM,
            ]
        )
    )
    return SegmentRef(
        segment_id=seg_id,
        origin_uri=uri,
        manifest_digest=digest,
        trust_level=trust,
    )


@st.composite
def readers_strategy(draw):
    """Either Public or a frozen set of principal IDs."""
    if draw(st.booleans()):
        return Public.PUBLIC
    principals = draw(
        st.lists(
            st.text(min_size=1, max_size=10, alphabet=st.characters(min_codepoint=97, max_codepoint=122)),
            min_size=0,
            max_size=4,
            unique=True,
        )
    )
    return frozenset(principals)


@st.composite
def labels(draw) -> ProvenanceLabel:
    """A ProvenanceLabel with all fields randomized."""
    return ProvenanceLabel(
        sources=frozenset(
            draw(st.lists(segment_refs(), min_size=0, max_size=4, unique=False))
        ),
        readers=draw(readers_strategy()),
        integrity=draw(st.sampled_from(list(IntegrityLevel))),
        secrecy=draw(st.sampled_from(list(SecrecyLevel))),
        capacity=draw(st.sampled_from(list(InformationCapacity))),
    )


# ---------------------------------------------------------------------------
# Algebraic-law tests
# ---------------------------------------------------------------------------


@given(labels())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_join_is_idempotent(a: ProvenanceLabel) -> None:
    """a.join(a) preserves every dimension of a."""
    joined = a.join(a)
    assert joined.sources == a.sources
    assert joined.integrity == a.integrity
    assert joined.secrecy == a.secrecy
    assert joined.capacity == a.capacity
    # Readers also idempotent under intersection with itself.
    assert joined.readers == a.readers


@given(labels(), labels())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_join_is_commutative(a: ProvenanceLabel, b: ProvenanceLabel) -> None:
    """a.join(b) == b.join(a) on every dimension."""
    ab = a.join(b)
    ba = b.join(a)
    assert ab.sources == ba.sources
    assert ab.readers == ba.readers
    assert ab.integrity == ba.integrity
    assert ab.secrecy == ba.secrecy
    assert ab.capacity == ba.capacity


@given(labels(), labels(), labels())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_join_is_associative(
    a: ProvenanceLabel, b: ProvenanceLabel, c: ProvenanceLabel
) -> None:
    """(a.join(b)).join(c) == a.join(b.join(c)) on every dimension."""
    left = (a.join(b)).join(c)
    right = a.join(b.join(c))
    assert left.sources == right.sources
    assert left.readers == right.readers
    assert left.integrity == right.integrity
    assert left.secrecy == right.secrecy
    assert left.capacity == right.capacity


# ---------------------------------------------------------------------------
# Per-dimension semantics
# ---------------------------------------------------------------------------


@given(labels(), labels())
@settings(max_examples=100)
def test_join_sources_is_union(
    a: ProvenanceLabel, b: ProvenanceLabel
) -> None:
    assert a.join(b).sources == (a.sources | b.sources)


@given(labels(), labels())
@settings(max_examples=100)
def test_join_integrity_is_max(
    a: ProvenanceLabel, b: ProvenanceLabel
) -> None:
    """UNTRUSTED dominates ENDORSED dominates TRUSTED."""
    assert a.join(b).integrity == IntegrityLevel(
        max(int(a.integrity), int(b.integrity))
    )


@given(labels(), labels())
@settings(max_examples=100)
def test_join_secrecy_is_max(
    a: ProvenanceLabel, b: ProvenanceLabel
) -> None:
    """REGULATED dominates PRIVATE dominates INTERNAL dominates PUBLIC."""
    assert a.join(b).secrecy == SecrecyLevel(
        max(int(a.secrecy), int(b.secrecy))
    )


@given(labels(), labels())
@settings(max_examples=100)
def test_join_capacity_is_max(
    a: ProvenanceLabel, b: ProvenanceLabel
) -> None:
    """STRING dominates NUMBER dominates ENUM dominates BOOL."""
    assert a.join(b).capacity == InformationCapacity(
        max(int(a.capacity), int(b.capacity))
    )


@given(readers_strategy(), readers_strategy())
@settings(max_examples=100)
def test_join_readers_is_intersection(a, b) -> None:
    """Public is the universal set; intersect with anything keeps that thing."""
    label_a = ProvenanceLabel(
        sources=frozenset(),
        readers=a,
        integrity=IntegrityLevel.TRUSTED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
    )
    label_b = ProvenanceLabel(
        sources=frozenset(),
        readers=b,
        integrity=IntegrityLevel.TRUSTED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
    )
    joined = label_a.join(label_b)
    if a is Public.PUBLIC and b is Public.PUBLIC:
        assert joined.readers is Public.PUBLIC
    elif a is Public.PUBLIC:
        assert joined.readers == b
    elif b is Public.PUBLIC:
        assert joined.readers == a
    else:
        # Both explicit sets.
        assert isinstance(joined.readers, frozenset)
        assert joined.readers == (a & b)


# ---------------------------------------------------------------------------
# Declassification rules
# ---------------------------------------------------------------------------


def test_declassify_cannot_raise_integrity() -> None:
    """ENDORSED -> TRUSTED is rejected even with a tighter capacity."""
    label = ProvenanceLabel(
        sources=frozenset(),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.ENDORSED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
    )
    with pytest.raises(ValueError, match="cannot raise integrity"):
        label.declassify(InformationCapacity.BOOL, IntegrityLevel.TRUSTED)


def test_declassify_returns_new_instance() -> None:
    """ProvenanceLabel is immutable; declassify never mutates in place."""
    label = ProvenanceLabel(
        sources=frozenset(),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.UNTRUSTED,
        secrecy=SecrecyLevel.INTERNAL,
        capacity=InformationCapacity.STRING,
    )
    declassified = label.declassify(
        InformationCapacity.BOOL, IntegrityLevel.ENDORSED
    )
    assert declassified is not label
    assert label.integrity == IntegrityLevel.UNTRUSTED  # unchanged
    assert declassified.integrity == IntegrityLevel.ENDORSED
    assert declassified.capacity == InformationCapacity.BOOL
    # Sources and secrecy preserved.
    assert declassified.sources == label.sources
    assert declassified.secrecy == label.secrecy


def test_declassify_can_keep_or_lower_integrity() -> None:
    """Same-level declassification is a permissible no-op for changing capacity only."""
    label = ProvenanceLabel(
        sources=frozenset(),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.UNTRUSTED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
    )
    same = label.declassify(InformationCapacity.NUMBER, IntegrityLevel.UNTRUSTED)
    assert same.integrity == IntegrityLevel.UNTRUSTED
    assert same.capacity == InformationCapacity.NUMBER


# ---------------------------------------------------------------------------
# Constructors and helpers
# ---------------------------------------------------------------------------


def test_trusted_user_default_label_shape() -> None:
    label = ProvenanceLabel.trusted_user("alice")
    assert label.integrity == IntegrityLevel.TRUSTED
    assert label.secrecy == SecrecyLevel.PUBLIC
    assert label.capacity == InformationCapacity.STRING
    assert label.readers is Public.PUBLIC
    assert len(label.sources) == 1
    only = next(iter(label.sources))
    assert only.origin_uri == "user://alice"


def test_untrusted_tool_output_default_label_shape() -> None:
    label = ProvenanceLabel.untrusted_tool_output(
        segment_id="seg-1",
        origin_uri="mcp://gmail/inbox",
        manifest_digest="sha256:" + "a" * 64,
    )
    assert label.integrity == IntegrityLevel.UNTRUSTED
    assert label.secrecy == SecrecyLevel.INTERNAL
    assert label.capacity == InformationCapacity.STRING
    only = next(iter(label.sources))
    assert only.manifest_digest == "sha256:" + "a" * 64


def test_label_of_returns_user_default_for_bare_value() -> None:
    label = label_of("hello")
    assert label.integrity == IntegrityLevel.TRUSTED


def test_label_of_returns_carried_label_for_labeled_value() -> None:
    v = LabeledValue.from_user("hello", "alice")
    label = label_of(v)
    assert label.integrity == IntegrityLevel.TRUSTED
    only = next(iter(label.sources))
    assert only.origin_uri == "user://alice"


def test_join_labels_empty_returns_trusted_identity() -> None:
    label = join_labels()
    assert label.integrity == IntegrityLevel.TRUSTED


def test_join_labels_chains_correctly() -> None:
    a = ProvenanceLabel.trusted_user("alice")
    b = ProvenanceLabel.untrusted_tool_output("s", "mcp://x")
    c = ProvenanceLabel(
        sources=frozenset(),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.ENDORSED,
        secrecy=SecrecyLevel.PRIVATE,
        capacity=InformationCapacity.NUMBER,
    )
    joined = join_labels(a, b, c)
    # max integrity is UNTRUSTED (b dominates c which dominates a).
    assert joined.integrity == IntegrityLevel.UNTRUSTED
    # max secrecy is PRIVATE (c dominates).
    assert joined.secrecy == SecrecyLevel.PRIVATE


# ---------------------------------------------------------------------------
# Backward-compat with the v0.7 trust_level scalar
# ---------------------------------------------------------------------------


def test_trust_level_property_returns_min_across_sources() -> None:
    label = ProvenanceLabel(
        sources=frozenset(
            {
                SegmentRef("s1", "u://1", trust_level=TrustLevel.USER),
                SegmentRef("s2", "u://2", trust_level=TrustLevel.UNTRUSTED),
                SegmentRef("s3", "u://3", trust_level=TrustLevel.TOOL),
            }
        ),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.UNTRUSTED,
        secrecy=SecrecyLevel.INTERNAL,
        capacity=InformationCapacity.STRING,
    )
    # Lowest of {USER, UNTRUSTED, TOOL} is UNTRUSTED.
    assert label.trust_level == TrustLevel.UNTRUSTED


def test_trust_level_property_returns_system_for_empty_sources() -> None:
    label = ProvenanceLabel(
        sources=frozenset(),
        readers=Public.PUBLIC,
        integrity=IntegrityLevel.TRUSTED,
        secrecy=SecrecyLevel.PUBLIC,
        capacity=InformationCapacity.STRING,
    )
    assert label.trust_level == TrustLevel.SYSTEM
