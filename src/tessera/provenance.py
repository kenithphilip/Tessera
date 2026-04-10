"""Signed prompt provenance primitives.

This module defines two content-bound metadata objects for carrying
provenance through an agent workflow:

- `ContextSegmentEnvelope`: signed metadata for one prompt segment
- `PromptProvenanceManifest`: signed ordered references for one prompt

The v0 implementation uses HMAC-SHA256 so the primitives compose with
Tessera's existing symmetric trust-label path. The important property is
that content is bound by digest, ordering is explicit, and signatures
cover the exact metadata the proxy and policy engine will rely on.
"""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import TYPE_CHECKING, Sequence

from tessera.labels import Origin, TrustLevel

if TYPE_CHECKING:
    from tessera.context import LabeledSegment


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _content_digest(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def _sign(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, sha256).hexdigest()


def _first_seen(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class ContextSegmentEnvelope:
    """Signed provenance for one prompt segment.

    The envelope is content-bound via `content_sha256`. Verification
    requires the original content bytes so a caller cannot swap in a
    different string while keeping the same envelope.
    """

    segment_id: str
    origin: Origin
    issuer: str
    principal: str
    trust_level: TrustLevel
    content_sha256: str
    parent_ids: tuple[str, ...] = ()
    delegating_user: str | None = None
    sensitivity: tuple[str, ...] = ()
    created_at: str = field(default_factory=_utcnow)
    schema_version: int = 1
    signature: str = ""

    @classmethod
    def create(
        cls,
        *,
        content: str,
        origin: Origin,
        issuer: str,
        principal: str,
        trust_level: TrustLevel,
        key: bytes,
        segment_id: str | None = None,
        parent_ids: Sequence[str] = (),
        delegating_user: str | None = None,
        sensitivity: Sequence[str] = (),
        created_at: str | None = None,
    ) -> "ContextSegmentEnvelope":
        """Create and sign an envelope for raw content."""
        envelope = cls(
            segment_id=segment_id or secrets.token_hex(16),
            origin=origin,
            issuer=issuer,
            principal=principal,
            trust_level=trust_level,
            content_sha256=_content_digest(content),
            parent_ids=tuple(parent_ids),
            delegating_user=delegating_user,
            sensitivity=tuple(sensitivity),
            created_at=created_at or _utcnow(),
        )
        return envelope.sign(key)

    @classmethod
    def from_segment(
        cls,
        segment: "LabeledSegment",
        *,
        issuer: str,
        key: bytes,
        segment_id: str | None = None,
        parent_ids: Sequence[str] = (),
        delegating_user: str | None = None,
        sensitivity: Sequence[str] = (),
        created_at: str | None = None,
    ) -> "ContextSegmentEnvelope":
        """Create and sign an envelope from an existing labeled segment."""
        return cls.create(
            content=segment.content,
            origin=segment.label.origin,
            issuer=issuer,
            principal=segment.label.principal,
            trust_level=segment.label.trust_level,
            key=key,
            segment_id=segment_id,
            parent_ids=parent_ids,
            delegating_user=delegating_user,
            sensitivity=sensitivity,
            created_at=created_at,
        )

    def canonical(self) -> bytes:
        """Return the exact bytes covered by `signature`."""
        return _stable_json(
            {
                "schema_version": self.schema_version,
                "segment_id": self.segment_id,
                "origin": str(self.origin),
                "issuer": self.issuer,
                "principal": self.principal,
                "trust_level": int(self.trust_level),
                "content_sha256": self.content_sha256,
                "parent_ids": list(self.parent_ids),
                "delegating_user": self.delegating_user,
                "sensitivity": list(self.sensitivity),
                "created_at": self.created_at,
            }
        )

    def sign(self, key: bytes) -> "ContextSegmentEnvelope":
        """Return a signed copy of the envelope."""
        return replace(self, signature=_sign(self.canonical(), key))

    def verify(self, content: str, key: bytes) -> bool:
        """Verify signature and content binding against the original bytes."""
        if not self.signature or self.content_sha256 != _content_digest(content):
            return False
        expected = _sign(self.canonical(), key)
        return hmac.compare_digest(expected, self.signature)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "segment_id": self.segment_id,
            "origin": str(self.origin),
            "issuer": self.issuer,
            "principal": self.principal,
            "trust_level": int(self.trust_level),
            "content_sha256": self.content_sha256,
            "parent_ids": list(self.parent_ids),
            "delegating_user": self.delegating_user,
            "sensitivity": list(self.sensitivity),
            "created_at": self.created_at,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class ManifestSegmentRef:
    """One ordered segment reference inside a provenance manifest."""

    segment_id: str
    position: int
    content_sha256: str

    @classmethod
    def from_envelope(
        cls, envelope: ContextSegmentEnvelope, position: int
    ) -> "ManifestSegmentRef":
        return cls(
            segment_id=envelope.segment_id,
            position=position,
            content_sha256=envelope.content_sha256,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_id": self.segment_id,
            "position": self.position,
            "content_sha256": self.content_sha256,
        }


@dataclass(frozen=True)
class PromptProvenanceManifest:
    """Signed ordered references for one assembled prompt."""

    manifest_id: str
    session_id: str
    principal_set: tuple[str, ...]
    segments: tuple[ManifestSegmentRef, ...]
    assembled_by: str
    assembled_at: str = field(default_factory=_utcnow)
    schema_version: int = 1
    signature: str = ""

    @classmethod
    def assemble(
        cls,
        envelopes: Sequence[ContextSegmentEnvelope],
        *,
        assembled_by: str,
        key: bytes,
        session_id: str | None = None,
        manifest_id: str | None = None,
        principal_set: Sequence[str] | None = None,
        assembled_at: str | None = None,
    ) -> "PromptProvenanceManifest":
        """Create and sign a manifest preserving the given segment order."""
        refs = tuple(
            ManifestSegmentRef.from_envelope(envelope, index)
            for index, envelope in enumerate(envelopes)
        )
        principals = tuple(principal_set) if principal_set is not None else _first_seen(
            [envelope.principal for envelope in envelopes]
        )
        manifest = cls(
            manifest_id=manifest_id or secrets.token_hex(16),
            session_id=session_id or secrets.token_hex(16),
            principal_set=principals,
            segments=refs,
            assembled_by=assembled_by,
            assembled_at=assembled_at or _utcnow(),
        )
        return manifest.sign(key)

    def canonical(self) -> bytes:
        """Return the exact bytes covered by `signature`."""
        return _stable_json(
            {
                "schema_version": self.schema_version,
                "manifest_id": self.manifest_id,
                "session_id": self.session_id,
                "principal_set": list(self.principal_set),
                "segments": [segment.to_dict() for segment in self.segments],
                "assembled_by": self.assembled_by,
                "assembled_at": self.assembled_at,
            }
        )

    def sign(self, key: bytes) -> "PromptProvenanceManifest":
        """Return a signed copy of the manifest."""
        return replace(self, signature=_sign(self.canonical(), key))

    def verify(self, envelopes: Sequence[ContextSegmentEnvelope], key: bytes) -> bool:
        """Verify signature and ordered segment references.

        This verifies manifest integrity and that the provided envelopes
        match the recorded order and content digests. Callers should
        verify each envelope's own signature separately when needed.
        """
        if not self.signature or len(envelopes) != len(self.segments):
            return False
        expected_refs = tuple(
            ManifestSegmentRef.from_envelope(envelope, index)
            for index, envelope in enumerate(envelopes)
        )
        if self.segments != expected_refs:
            return False
        expected = _sign(self.canonical(), key)
        return hmac.compare_digest(expected, self.signature)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "session_id": self.session_id,
            "principal_set": list(self.principal_set),
            "segments": [segment.to_dict() for segment in self.segments],
            "assembled_by": self.assembled_by,
            "assembled_at": self.assembled_at,
            "signature": self.signature,
        }
