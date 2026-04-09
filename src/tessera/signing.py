"""SPIFFE-compatible JWT-SVID label signing.

The v0 HMAC signer requires every workload that issues or verifies labels
to share a symmetric key. That does not scale past one workload. This
module adds asymmetric signing via JWT, so a retrieval service can mint
labeled segments with its private key and the proxy verifies them with
the corresponding public key (or a JWKS from a trust domain).

PyJWT and cryptography are optional dependencies. Install with:

    pip install tessera[spiffe]

If PyJWT is not installed, the signers and verifiers raise
`SigningNotAvailable` on construction rather than failing silently.

Shape of a JWT-signed label:

    The label's `signature` field holds a compact JWS. The JWS claims are:

        iss: optional issuer (use a spiffe:// URI with SPIRE)
        orig: label.origin
        prn: label.principal
        lvl: label.trust_level
        non: label.nonce
        cdh: sha256 hex digest of the content

    The `kid` header is set when provided, so JWKS-based verifiers can
    look up the right public key by id.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta
from hashlib import sha256
from typing import Any, Callable, Protocol

from tessera.labels import TrustLabel, sign_label, verify_label

try:  # pragma: no cover - exercised when PyJWT is installed
    import jwt as pyjwt

    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False


class SigningNotAvailable(RuntimeError):
    """Raised when JWT signing is used without PyJWT installed."""


class LabelSigner(Protocol):
    def sign(self, label: TrustLabel, content: str) -> TrustLabel: ...


class LabelVerifier(Protocol):
    def verify(self, label: TrustLabel, content: str) -> bool: ...


@dataclass
class HMACSigner:
    """Symmetric HMAC-SHA256 signer. The v0 default.

    Thin wrapper around `tessera.labels.sign_label` so HMAC keys satisfy
    the `LabelSigner` protocol alongside JWT-based signers.
    """

    key: bytes

    def sign(self, label: TrustLabel, content: str) -> TrustLabel:
        return sign_label(label, content, self.key)


@dataclass
class HMACVerifier:
    """Symmetric HMAC-SHA256 verifier. The v0 default."""

    key: bytes

    def verify(self, label: TrustLabel, content: str) -> bool:
        return verify_label(label, content, self.key)


def _content_digest(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def _claims_for(label: TrustLabel, content: str) -> dict[str, Any]:
    return {
        "orig": str(label.origin),
        "prn": label.principal,
        "lvl": int(label.trust_level),
        "non": label.nonce,
        "cdh": _content_digest(content),
    }


def _require_pyjwt() -> None:
    if not _JWT_AVAILABLE:
        raise SigningNotAvailable(
            "PyJWT is not installed. Install with: pip install tessera[spiffe]"
        )


@dataclass
class JWTSigner:
    """Asymmetric signer using RS256 or ES256.

    `private_key` is anything PyJWT accepts: PEM bytes, a cryptography key
    object, or a JWK dict. `key_id` becomes the JWS `kid` header so
    receiving verifiers can resolve the public key from a JWKS.
    """

    private_key: Any
    algorithm: str = "RS256"
    key_id: str | None = None
    issuer: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def sign(self, label: TrustLabel, content: str) -> TrustLabel:
        claims = _claims_for(label, content)
        if self.issuer:
            claims["iss"] = self.issuer
        headers = {"kid": self.key_id} if self.key_id else None
        token = pyjwt.encode(
            claims,
            self.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )
        return replace(label, signature=token)


@dataclass
class JWTVerifier:
    """Verifier holding a single public key.

    `leeway` gives JWT's `nbf`/`exp` validation a tolerance window to
    survive normal clock skew between the signing workload and the
    verifier. SPIRE mints short-lived SVIDs, so zero leeway will flake
    under drift.
    """

    public_key: Any
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    expected_issuer: str | None = None
    leeway: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(self, label: TrustLabel, content: str) -> bool:
        if not label.signature:
            return False
        try:
            decoded = pyjwt.decode(
                label.signature,
                self.public_key,
                algorithms=self.algorithms,
                issuer=self.expected_issuer,
                leeway=self.leeway,
                options={"require": []},
            )
        except pyjwt.PyJWTError:
            return False
        return _claims_match(decoded, label, content)


@dataclass
class JWKSVerifier:
    """Verifier that resolves the signing key from a JWKS by `kid`.

    Use with SPIRE JWT-SVIDs: point `fetch_jwks` at a callable that returns
    the trust domain's bundle JWKS as a dict. `fetch_jwks` is kept as a
    callable so this module does not pick an HTTP library for you.
    """

    fetch_jwks: Callable[[], dict[str, Any]]
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    expected_issuer: str | None = None
    leeway: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(self, label: TrustLabel, content: str) -> bool:
        if not label.signature:
            return False
        try:
            header = pyjwt.get_unverified_header(label.signature)
            kid = header.get("kid")
            if not kid:
                return False
            jwks = self.fetch_jwks()
            key_dict = next(
                (k for k in jwks.get("keys", []) if k.get("kid") == kid),
                None,
            )
            if key_dict is None:
                return False
            public_key = pyjwt.PyJWK(key_dict).key
            decoded = pyjwt.decode(
                label.signature,
                public_key,
                algorithms=self.algorithms,
                issuer=self.expected_issuer,
                leeway=self.leeway,
                options={"require": []},
            )
        except pyjwt.PyJWTError:
            return False
        except (KeyError, ValueError):
            return False
        return _claims_match(decoded, label, content)


def _claims_match(decoded: dict[str, Any], label: TrustLabel, content: str) -> bool:
    """Check that JWT claims match the label they were issued for."""
    expected = _claims_for(label, content)
    for key, value in expected.items():
        if decoded.get(key) != value:
            return False
    return True
