"""Signed evidence bundles for security events."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from tessera.events import EvidenceBuffer

try:  # pragma: no cover - exercised when PyJWT is installed
    import jwt as pyjwt

    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False


class EvidenceSigningNotAvailable(RuntimeError):
    """Raised when JWT evidence signing is used without PyJWT installed."""


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


@dataclass(frozen=True)
class EvidenceBundle:
    """Portable event bundle for audit and incident workflows."""

    schema_version: str
    generated_at: str
    event_count: int
    dropped_events: int
    counts_by_kind: dict[str, int]
    events: tuple[dict[str, Any], ...]

    @classmethod
    def from_buffer(cls, buffer: EvidenceBuffer) -> "EvidenceBundle":
        return cls.from_dict(buffer.export())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceBundle":
        return cls(
            schema_version=str(data.get("schema_version", "tessera.evidence.v1")),
            generated_at=str(data["generated_at"]),
            event_count=int(data["event_count"]),
            dropped_events=int(data["dropped_events"]),
            counts_by_kind={
                str(key): int(value)
                for key, value in dict(data["counts_by_kind"]).items()
            },
            events=tuple(dict(event) for event in data["events"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "event_count": self.event_count,
            "dropped_events": self.dropped_events,
            "counts_by_kind": self.counts_by_kind,
            "events": list(self.events),
        }

    def canonical(self) -> bytes:
        return _canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        return sha256(self.canonical()).hexdigest()


@dataclass(frozen=True)
class SignedEvidenceBundle:
    """Evidence bundle plus detached signature metadata."""

    bundle: EvidenceBundle
    algorithm: str
    signature: str
    issuer: str | None = None
    key_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedEvidenceBundle":
        return cls(
            bundle=EvidenceBundle.from_dict(dict(data["bundle"])),
            algorithm=str(data["algorithm"]),
            signature=str(data["signature"]),
            issuer=None if data.get("issuer") is None else str(data["issuer"]),
            key_id=None if data.get("key_id") is None else str(data["key_id"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": self.bundle.to_dict(),
            "algorithm": self.algorithm,
            "signature": self.signature,
            "issuer": self.issuer,
            "key_id": self.key_id,
        }


@dataclass
class HMACEvidenceSigner:
    """Detached HMAC-SHA256 signer for evidence bundles."""

    key: bytes
    algorithm: str = "HMAC-SHA256"
    issuer: str | None = None
    key_id: str | None = None

    def sign(self, bundle: EvidenceBundle) -> SignedEvidenceBundle:
        signature = hmac.new(self.key, bundle.canonical(), sha256).hexdigest()
        return SignedEvidenceBundle(
            bundle=bundle,
            algorithm=self.algorithm,
            signature=signature,
            issuer=self.issuer,
            key_id=self.key_id,
        )


@dataclass
class HMACEvidenceVerifier:
    """Detached HMAC-SHA256 verifier for evidence bundles."""

    key: bytes
    algorithm: str = "HMAC-SHA256"

    def verify(self, signed: SignedEvidenceBundle) -> bool:
        if signed.algorithm != self.algorithm:
            return False
        expected = hmac.new(self.key, signed.bundle.canonical(), sha256).hexdigest()
        return hmac.compare_digest(expected, signed.signature)


def _require_pyjwt() -> None:
    if not _JWT_AVAILABLE:
        raise EvidenceSigningNotAvailable(
            "PyJWT is not installed. Install with: pip install tessera[spiffe]"
        )


def _evidence_claims(bundle: EvidenceBundle) -> dict[str, Any]:
    return {
        "typ": "tessera_evidence",
        "sch": bundle.schema_version,
        "bdh": bundle.digest,
    }


@dataclass
class JWTEvidenceSigner:
    """JWT-based detached signer for evidence bundles."""

    private_key: Any
    algorithm: str = "RS256"
    key_id: str | None = None
    issuer: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def sign(self, bundle: EvidenceBundle) -> SignedEvidenceBundle:
        claims = _evidence_claims(bundle)
        if self.issuer is not None:
            claims["iss"] = self.issuer
        headers = {"kid": self.key_id} if self.key_id else None
        token = pyjwt.encode(
            claims,
            self.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )
        return SignedEvidenceBundle(
            bundle=bundle,
            algorithm=self.algorithm,
            signature=token,
            issuer=self.issuer,
            key_id=self.key_id,
        )


@dataclass
class JWTEvidenceVerifier:
    """JWT-based verifier for evidence bundles."""

    public_key: Any
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    expected_issuer: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(self, signed: SignedEvidenceBundle) -> bool:
        try:
            decoded = pyjwt.decode(
                signed.signature,
                self.public_key,
                algorithms=self.algorithms,
                issuer=self.expected_issuer,
                options={"require": []},
            )
        except pyjwt.PyJWTError:
            return False
        for key, value in _evidence_claims(signed.bundle).items():
            if decoded.get(key) != value:
                return False
        return True
