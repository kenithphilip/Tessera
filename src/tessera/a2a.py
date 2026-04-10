"""A2A security carriage for delegation and prompt provenance.

This module defines a narrow, deterministic security wrapper for agent to
agent task exchange. It does not implement the full A2A protocol. Instead,
it standardizes how Tessera attaches and verifies delegation plus prompt
provenance on task payloads so callers can carry the same security context
across agent hops that they already use at the proxy and MCP layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from tessera.delegation import DelegationToken, verify_delegation
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLevel
from tessera.provenance import (
    ContextSegmentEnvelope,
    ManifestSegmentRef,
    PromptProvenanceManifest,
)


class A2AVerificationError(ValueError):
    """Raised when an A2A security context fails closed."""


@dataclass(frozen=True)
class A2APromptSegment:
    """One prompt segment carried inside an A2A task request."""

    segment_id: str
    role: str
    content: str

    def to_dict(self) -> dict[str, str]:
        return {
            "segment_id": self.segment_id,
            "role": self.role,
            "content": self.content,
        }


@dataclass(frozen=True)
class A2ASecurityContext:
    """Delegation and provenance metadata for one A2A task exchange."""

    delegation: DelegationToken | None = None
    provenance_manifest: PromptProvenanceManifest | None = None
    segment_envelopes: tuple[ContextSegmentEnvelope, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "delegation": None
            if self.delegation is None
            else {
                "subject": self.delegation.subject,
                "delegate": self.delegation.delegate,
                "audience": self.delegation.audience,
                "authorized_actions": list(self.delegation.authorized_actions),
                "constraints": self.delegation.constraints,
                "session_id": self.delegation.session_id,
                "expires_at": self.delegation.expires_at.isoformat(),
                "signature": self.delegation.signature,
            },
            "provenance_manifest": None
            if self.provenance_manifest is None
            else self.provenance_manifest.to_dict(),
            "segment_envelopes": [
                envelope.to_dict() for envelope in self.segment_envelopes
            ],
        }


@dataclass(frozen=True)
class A2ATaskRequest:
    """Minimal A2A-style task request with Tessera security metadata."""

    task_id: str
    intent: str
    input_segments: tuple[A2APromptSegment, ...]
    metadata: dict[str, Any] = field(default_factory=dict)
    security_context: A2ASecurityContext | None = None

    def to_dict(self) -> dict[str, Any]:
        metadata = dict(self.metadata)
        if self.security_context is not None:
            metadata["tessera_security_context"] = self.security_context.to_dict()
        return {
            "task_id": self.task_id,
            "intent": self.intent,
            "input_segments": [segment.to_dict() for segment in self.input_segments],
            "metadata": metadata,
        }

    def to_jsonrpc(self, *, request_id: str | int, method: str = "tasks.send") -> dict[str, Any]:
        """Render the task request as a JSON-RPC request body."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": self.to_dict(),
        }

    def verify_security(
        self,
        *,
        delegation_key: bytes | None = None,
        provenance_key: bytes | None = None,
        delegation_audience: str | None = None,
        expected_delegate: str | None = None,
    ) -> A2ASecurityContext | None:
        """Verify the embedded Tessera security metadata, if present."""
        return extract_security_context(
            self.to_dict(),
            delegation_key=delegation_key,
            provenance_key=provenance_key,
            delegation_audience=delegation_audience,
            expected_delegate=expected_delegate,
        )


def attach_security_context(
    payload: Mapping[str, Any],
    security_context: A2ASecurityContext,
) -> dict[str, Any]:
    """Attach a Tessera security context to an A2A-style payload."""
    metadata = dict(payload.get("metadata") or {})
    metadata["tessera_security_context"] = security_context.to_dict()
    enriched = dict(payload)
    enriched["metadata"] = metadata
    return enriched


def extract_security_context(
    payload: Mapping[str, Any],
    *,
    delegation_key: bytes | None = None,
    provenance_key: bytes | None = None,
    delegation_audience: str | None = None,
    expected_delegate: str | None = None,
) -> A2ASecurityContext | None:
    """Parse and verify Tessera security metadata from an A2A-style payload."""
    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    raw = metadata.get("tessera_security_context")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise A2AVerificationError("invalid tessera_security_context payload")

    delegation = _parse_delegation(raw.get("delegation"))
    if delegation is not None:
        if delegation_key is None:
            _emit_failure(
                EventKind.DELEGATION_VERIFY_FAILURE,
                principal=delegation.subject,
                detail={"error": "delegation present but no delegation key configured"},
            )
            raise A2AVerificationError("delegation present but no delegation key configured")
        if expected_delegate is None:
            _emit_failure(
                EventKind.DELEGATION_VERIFY_FAILURE,
                principal=delegation.subject,
                detail={"error": "delegation present but no local delegate identity configured"},
            )
            raise A2AVerificationError(
                "delegation present but no local delegate identity configured"
            )
        if not verify_delegation(
            delegation,
            delegation_key,
            audience=delegation_audience,
        ):
            _emit_failure(
                EventKind.DELEGATION_VERIFY_FAILURE,
                principal=delegation.subject,
                detail={
                    "delegate": delegation.delegate,
                    "audience": delegation.audience,
                },
            )
            raise A2AVerificationError("invalid delegation token")
        if delegation.delegate != expected_delegate:
            _emit_failure(
                EventKind.DELEGATION_VERIFY_FAILURE,
                principal=delegation.subject,
                detail={
                    "delegate": delegation.delegate,
                    "expected_delegate": expected_delegate,
                    "audience": delegation.audience,
                },
            )
            raise A2AVerificationError("delegation token bound to a different agent")

    manifest = _parse_manifest(raw.get("provenance_manifest"))
    envelopes = _parse_envelopes(raw.get("segment_envelopes"))
    if manifest is None and not envelopes:
        return A2ASecurityContext(delegation=delegation)
    if manifest is None or not envelopes:
        _emit_failure(
            EventKind.PROVENANCE_VERIFY_FAILURE,
            principal=delegation.subject if delegation is not None else None,
            detail={"error": "provenance manifest and segment envelopes must both be present"},
        )
        raise A2AVerificationError(
            "provenance manifest and segment envelopes must both be present"
        )
    if provenance_key is None:
        _emit_failure(
            EventKind.PROVENANCE_VERIFY_FAILURE,
            principal=delegation.subject if delegation is not None else None,
            detail={"error": "provenance present but no provenance key configured"},
        )
        raise A2AVerificationError("provenance present but no provenance key configured")

    ordered_segments = _parse_input_segments(payload)
    ordered_envelopes = _ordered_envelopes_for_segments(ordered_segments, envelopes)
    for segment, envelope in zip(ordered_segments, ordered_envelopes, strict=True):
        if not envelope.verify(segment.content, provenance_key):
            _emit_failure(
                EventKind.PROVENANCE_VERIFY_FAILURE,
                principal=envelope.principal,
                detail={
                    "segment_id": envelope.segment_id,
                    "issuer": envelope.issuer,
                },
            )
            raise A2AVerificationError("invalid provenance envelope")
    if not manifest.verify(ordered_envelopes, provenance_key):
        _emit_failure(
            EventKind.PROVENANCE_VERIFY_FAILURE,
            principal=delegation.subject if delegation is not None else None,
            detail={"manifest_id": manifest.manifest_id},
        )
        raise A2AVerificationError("invalid provenance manifest")
    return A2ASecurityContext(
        delegation=delegation,
        provenance_manifest=manifest,
        segment_envelopes=tuple(ordered_envelopes),
    )


def _parse_input_segments(payload: Mapping[str, Any]) -> tuple[A2APromptSegment, ...]:
    raw_segments = payload.get("input_segments")
    if not isinstance(raw_segments, list) or not raw_segments:
        raise A2AVerificationError("provenance requires non-empty input_segments")
    parsed: list[A2APromptSegment] = []
    seen_ids: set[str] = set()
    for raw_segment in raw_segments:
        if not isinstance(raw_segment, Mapping):
            raise A2AVerificationError("invalid input segment")
        try:
            segment = A2APromptSegment(
                segment_id=str(raw_segment["segment_id"]),
                role=str(raw_segment["role"]),
                content=str(raw_segment["content"]),
            )
        except KeyError as exc:
            raise A2AVerificationError("invalid input segment") from exc
        if segment.segment_id in seen_ids:
            raise A2AVerificationError("duplicate input segment_id")
        seen_ids.add(segment.segment_id)
        parsed.append(segment)
    return tuple(parsed)


def _ordered_envelopes_for_segments(
    segments: tuple[A2APromptSegment, ...],
    envelopes: tuple[ContextSegmentEnvelope, ...],
) -> tuple[ContextSegmentEnvelope, ...]:
    by_id: dict[str, ContextSegmentEnvelope] = {}
    for envelope in envelopes:
        if envelope.segment_id in by_id:
            raise A2AVerificationError("duplicate provenance envelope segment_id")
        by_id[envelope.segment_id] = envelope
    ordered: list[ContextSegmentEnvelope] = []
    for segment in segments:
        envelope = by_id.get(segment.segment_id)
        if envelope is None:
            raise A2AVerificationError(
                f"missing provenance envelope for segment {segment.segment_id!r}"
            )
        ordered.append(envelope)
    if len(ordered) != len(envelopes):
        raise A2AVerificationError("provenance envelope set does not match input segments")
    return tuple(ordered)


def _parse_delegation(raw: object) -> DelegationToken | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise A2AVerificationError("invalid delegation payload")
    try:
        return DelegationToken(
            subject=str(raw["subject"]),
            delegate=str(raw["delegate"]),
            audience=str(raw["audience"]),
            authorized_actions=tuple(str(item) for item in raw.get("authorized_actions", [])),
            constraints=dict(raw.get("constraints", {})),
            session_id=str(raw.get("session_id", "")),
            expires_at=datetime.fromisoformat(str(raw["expires_at"])),
            signature=str(raw.get("signature", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise A2AVerificationError("invalid delegation payload") from exc


def _parse_manifest(raw: object) -> PromptProvenanceManifest | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise A2AVerificationError("invalid provenance manifest")
    try:
        return PromptProvenanceManifest(
            manifest_id=str(raw["manifest_id"]),
            session_id=str(raw["session_id"]),
            principal_set=tuple(str(item) for item in raw.get("principal_set", [])),
            segments=tuple(_parse_manifest_ref(item) for item in raw.get("segments", [])),
            assembled_by=str(raw["assembled_by"]),
            assembled_at=str(raw["assembled_at"]),
            schema_version=int(raw.get("schema_version", 1)),
            signature=str(raw.get("signature", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise A2AVerificationError("invalid provenance manifest") from exc


def _parse_manifest_ref(raw: object) -> ManifestSegmentRef:
    if not isinstance(raw, Mapping):
        raise A2AVerificationError("invalid provenance manifest segment")
    try:
        return ManifestSegmentRef(
            segment_id=str(raw["segment_id"]),
            position=int(raw["position"]),
            content_sha256=str(raw["content_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise A2AVerificationError("invalid provenance manifest segment") from exc


def _parse_envelopes(raw: object) -> tuple[ContextSegmentEnvelope, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise A2AVerificationError("invalid provenance envelope set")
    parsed: list[ContextSegmentEnvelope] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise A2AVerificationError("invalid provenance envelope")
        try:
            parsed.append(
                ContextSegmentEnvelope(
                    segment_id=str(item["segment_id"]),
                    origin=Origin(str(item["origin"])),
                    issuer=str(item["issuer"]),
                    principal=str(item["principal"]),
                    trust_level=TrustLevel(int(item["trust_level"])),
                    content_sha256=str(item["content_sha256"]),
                    parent_ids=tuple(str(parent_id) for parent_id in item.get("parent_ids", [])),
                    delegating_user=(
                        None
                        if item.get("delegating_user") is None
                        else str(item["delegating_user"])
                    ),
                    sensitivity=tuple(
                        str(label) for label in item.get("sensitivity", [])
                    ),
                    created_at=str(item["created_at"]),
                    schema_version=int(item.get("schema_version", 1)),
                    signature=str(item.get("signature", "")),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise A2AVerificationError("invalid provenance envelope") from exc
    return tuple(parsed)


def _emit_failure(
    kind: EventKind,
    *,
    principal: str | None,
    detail: dict[str, Any],
) -> None:
    emit_event(SecurityEvent.now(kind=kind, principal=principal, detail=detail))
