"""Prompt provenance primitives: content binding, ordering, and signing."""

from __future__ import annotations

from tessera.context import make_segment
from tessera.labels import Origin, TrustLevel
from tessera.provenance import ContextSegmentEnvelope, PromptProvenanceManifest

KEY = b"test-hmac-key-do-not-use-in-prod"


def test_context_segment_envelope_round_trips_from_segment():
    segment = make_segment("email bob", Origin.USER, "alice", KEY)

    envelope = ContextSegmentEnvelope.from_segment(
        segment,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
        delegating_user="user:alice@example.com",
        sensitivity=("internal",),
    )

    assert envelope.origin == Origin.USER
    assert envelope.principal == "alice"
    assert envelope.trust_level == TrustLevel.USER
    assert envelope.verify(segment.content, KEY) is True


def test_context_segment_envelope_rejects_tampered_content():
    envelope = ContextSegmentEnvelope.create(
        content="original",
        origin=Origin.WEB,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.UNTRUSTED,
        key=KEY,
    )

    assert envelope.verify("tampered", KEY) is False


def test_context_segment_envelope_rejects_wrong_key():
    envelope = ContextSegmentEnvelope.create(
        content="x",
        origin=Origin.TOOL,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.TOOL,
        key=KEY,
    )

    assert envelope.verify("x", b"other-key") is False


def test_prompt_provenance_manifest_round_trips_and_preserves_order():
    first = ContextSegmentEnvelope.create(
        content="user asks a question",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.USER,
        key=KEY,
    )
    second = ContextSegmentEnvelope.create(
        content="scraped page",
        origin=Origin.WEB,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.UNTRUSTED,
        key=KEY,
    )

    manifest = PromptProvenanceManifest.assemble(
        [first, second],
        assembled_by="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
    )

    assert manifest.verify([first, second], KEY) is True
    assert manifest.segments[0].segment_id == first.segment_id
    assert manifest.segments[1].segment_id == second.segment_id


def test_prompt_provenance_manifest_rejects_reordered_envelopes():
    first = ContextSegmentEnvelope.create(
        content="user asks a question",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.USER,
        key=KEY,
    )
    second = ContextSegmentEnvelope.create(
        content="tool result",
        origin=Origin.TOOL,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.TOOL,
        key=KEY,
    )
    manifest = PromptProvenanceManifest.assemble(
        [first, second],
        assembled_by="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
    )

    assert manifest.verify([second, first], KEY) is False


def test_prompt_provenance_manifest_uses_first_seen_principal_order():
    first = ContextSegmentEnvelope.create(
        content="first",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.USER,
        key=KEY,
    )
    second = ContextSegmentEnvelope.create(
        content="second",
        origin=Origin.TOOL,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.TOOL,
        key=KEY,
    )
    third = ContextSegmentEnvelope.create(
        content="third",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="bob",
        trust_level=TrustLevel.USER,
        key=KEY,
    )

    manifest = PromptProvenanceManifest.assemble(
        [first, second, third],
        assembled_by="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
    )

    assert manifest.principal_set == ("alice", "bob")


def test_prompt_provenance_manifest_rejects_tampered_signature():
    envelope = ContextSegmentEnvelope.create(
        content="x",
        origin=Origin.USER,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        principal="alice",
        trust_level=TrustLevel.USER,
        key=KEY,
    )
    manifest = PromptProvenanceManifest.assemble(
        [envelope],
        assembled_by="spiffe://example.org/ns/proxy/i/abcd",
        key=KEY,
    )
    tampered = PromptProvenanceManifest(
        manifest_id=manifest.manifest_id,
        session_id=manifest.session_id,
        principal_set=manifest.principal_set,
        segments=manifest.segments,
        assembled_by=manifest.assembled_by,
        assembled_at=manifest.assembled_at,
        schema_version=manifest.schema_version,
        signature="0" * len(manifest.signature),
    )

    assert tampered.verify([envelope], KEY) is False
