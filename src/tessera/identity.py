"""Workload identity and proof-of-possession for inbound agent traffic.

This module adds a real caller-identity path for the proxy and other
HTTP transports. The compact credential is a JWT with a SPIFFE subject
and optional proof key binding in `cnf.jkt`. A separate DPoP-style proof
JWT binds that credential to one HTTP request and can be replay-checked.

WIMSE alignment (draft-ietf-wimse-workload-identity-bcp and
draft-klrc-aiagent-auth): the three new types at the bottom of this
module map Tessera's existing identity primitives to the WIMSE wire
format without changing any existing caller-visible behaviour.

- ``WorkloadIdentity`` -- local structured representation of a workload.
- ``WIMSEIdentityClaim`` -- WIMSE ID claim set (RFC 9068 profile).
- ``WorkloadIdentityToken`` -- WIT envelope (typ: wit+jwt).
- ``OAuthTransactionToken`` -- shim that serialises a ``DelegationToken``
  as a draft OAuth Transaction Token (txn_token claim) for interop.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import json
import secrets
from hashlib import sha256
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from tessera.signing import SigningNotAvailable

if TYPE_CHECKING:
    from tessera.delegation import DelegationToken

try:  # pragma: no cover - exercised when PyJWT is installed
    import jwt as pyjwt

    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False


def _require_pyjwt() -> None:
    if not _JWT_AVAILABLE:
        raise SigningNotAvailable(
            "PyJWT is not installed. Install with: pip install tessera[spiffe]"
        )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _base64url(data: bytes) -> str:
    return pyjwt.utils.base64url_encode(data).decode("ascii")


def _timestamp(value: datetime) -> int:
    return int(_utc(value).timestamp())


def _datetime_claim(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc)
    raise ValueError("invalid datetime claim")


def _normalize_audience(value: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, tuple):
        return value
    return tuple(value)


def _claim_audience(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError("invalid audience claim")


def _validate_spiffe_id(value: str) -> tuple[str, str] | None:
    if not value.startswith("spiffe://"):
        return None
    parsed = urlparse(value)
    if not parsed.netloc or not parsed.path or parsed.path == "/":
        return None
    return parsed.netloc, parsed.path


def _thumbprint_members(jwk: Mapping[str, Any]) -> dict[str, Any]:
    kty = jwk.get("kty")
    if kty == "RSA":
        keys = ("e", "kty", "n")
    elif kty == "EC":
        keys = ("crv", "kty", "x", "y")
    elif kty == "OKP":
        keys = ("crv", "kty", "x")
    elif kty == "oct":
        keys = ("k", "kty")
    else:
        raise ValueError("unsupported JWK key type")
    if any(key not in jwk for key in keys):
        raise ValueError("incomplete JWK for thumbprint")
    return {key: jwk[key] for key in keys}


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """Return the RFC 7638 JWK thumbprint in base64url form."""
    _require_pyjwt()
    canonical = json.dumps(
        _thumbprint_members(jwk),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _base64url(sha256(canonical).digest())


def _token_hash(token: str) -> str:
    return _base64url(sha256(token.encode("utf-8")).digest())


@dataclass(frozen=True)
class AgentIdentity:
    """A verified workload identity for one calling agent."""

    agent_id: str
    trust_domain: str
    issuer: str | None
    audience: tuple[str, ...]
    valid_from: datetime | None
    valid_until: datetime
    key_binding: str | None = None
    software_identity: dict[str, str] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "trust_domain": self.trust_domain,
            "issuer": self.issuer,
            "audience": list(self.audience),
            "valid_from": None if self.valid_from is None else self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "key_binding": self.key_binding,
            "software_identity": self.software_identity,
        }


class AgentIdentityVerifier(Protocol):
    def verify(
        self,
        token: str,
        *,
        audience: str | tuple[str, ...] | list[str],
    ) -> AgentIdentity | None: ...


@dataclass
class JWTAgentIdentitySigner:
    """Sign compact workload identity JWTs for tests and reference setups."""

    private_key: Any
    algorithm: str = "RS256"
    key_id: str | None = None
    issuer: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def sign(
        self,
        *,
        agent_id: str,
        audience: str | tuple[str, ...] | list[str],
        valid_until: datetime,
        valid_from: datetime | None = None,
        software_identity: Mapping[str, str] | None = None,
        confirmation_key: Mapping[str, Any] | None = None,
        additional_claims: Mapping[str, Any] | None = None,
    ) -> str:
        parsed = _validate_spiffe_id(agent_id)
        if parsed is None:
            raise ValueError("agent_id must be a SPIFFE ID")
        claims: dict[str, Any] = {
            "sub": agent_id,
            "aud": list(_normalize_audience(audience)),
            "exp": _timestamp(valid_until),
        }
        if self.issuer:
            claims["iss"] = self.issuer
        if valid_from is not None:
            claims["nbf"] = _timestamp(valid_from)
            claims["iat"] = _timestamp(valid_from)
        if software_identity is not None:
            claims["software_identity"] = dict(software_identity)
        if confirmation_key is not None:
            claims["cnf"] = {"jkt": jwk_thumbprint(confirmation_key)}
        if additional_claims is not None:
            claims.update(additional_claims)
        headers = {"kid": self.key_id} if self.key_id else None
        return pyjwt.encode(
            claims,
            self.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )


@dataclass
class JWTAgentIdentityVerifier:
    """Verify one workload identity JWT against one public key."""

    public_key: Any
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    expected_issuer: str | None = None
    expected_trust_domain: str | None = None
    leeway: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(
        self,
        token: str,
        *,
        audience: str | tuple[str, ...] | list[str],
    ) -> AgentIdentity | None:
        try:
            decoded = pyjwt.decode(
                token,
                self.public_key,
                algorithms=self.algorithms,
                audience=list(_normalize_audience(audience)),
                issuer=self.expected_issuer,
                leeway=self.leeway,
                options={"require": ["sub", "aud", "exp"]},
            )
        except pyjwt.PyJWTError:
            return None
        return _claims_to_identity(
            decoded,
            expected_trust_domain=self.expected_trust_domain,
        )


@dataclass
class JWKSAgentIdentityVerifier:
    """Verify workload identity JWTs by resolving a key from a JWKS."""

    fetch_jwks: Callable[[], dict[str, Any]]
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    expected_issuer: str | None = None
    expected_trust_domain: str | None = None
    leeway: timedelta = field(default_factory=lambda: timedelta(seconds=30))

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(
        self,
        token: str,
        *,
        audience: str | tuple[str, ...] | list[str],
    ) -> AgentIdentity | None:
        try:
            header = pyjwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                return None
            jwks = self.fetch_jwks()
            key_dict = next(
                (key for key in jwks.get("keys", []) if key.get("kid") == kid),
                None,
            )
            if key_dict is None:
                return None
            public_key = pyjwt.PyJWK(key_dict).key
            decoded = pyjwt.decode(
                token,
                public_key,
                algorithms=self.algorithms,
                audience=list(_normalize_audience(audience)),
                issuer=self.expected_issuer,
                leeway=self.leeway,
                options={"require": ["sub", "aud", "exp"]},
            )
        except pyjwt.PyJWTError:
            return None
        except (KeyError, ValueError):
            return None
        return _claims_to_identity(
            decoded,
            expected_trust_domain=self.expected_trust_domain,
        )


def _claims_to_identity(
    decoded: Mapping[str, Any],
    *,
    expected_trust_domain: str | None,
) -> AgentIdentity | None:
    try:
        agent_id = str(decoded["sub"])
        audience = _claim_audience(decoded["aud"])
        valid_until = _datetime_claim(decoded["exp"])
        if valid_until is None:
            return None
        valid_from = _datetime_claim(decoded.get("nbf")) or _datetime_claim(
            decoded.get("iat")
        )
    except (KeyError, TypeError, ValueError):
        return None

    parsed = _validate_spiffe_id(agent_id)
    if parsed is None:
        return None
    trust_domain, _ = parsed
    if expected_trust_domain is not None and trust_domain != expected_trust_domain:
        return None

    software_identity_raw = decoded.get("software_identity", {})
    if not isinstance(software_identity_raw, Mapping):
        return None
    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in software_identity_raw.items()
    ):
        return None

    cnf = decoded.get("cnf", {})
    if not isinstance(cnf, Mapping):
        return None
    key_binding = cnf.get("jkt")
    if key_binding is None and "jwk" in cnf:
        try:
            key_binding = jwk_thumbprint(cnf["jwk"])
        except (TypeError, ValueError):
            return None
    if key_binding is not None and not isinstance(key_binding, str):
        return None

    return AgentIdentity(
        agent_id=agent_id,
        trust_domain=trust_domain,
        issuer=str(decoded["iss"]) if "iss" in decoded else None,
        audience=audience,
        valid_from=valid_from,
        valid_until=valid_until,
        key_binding=key_binding,
        software_identity=dict(software_identity_raw),
        claims=dict(decoded),
    )


@dataclass
class AgentProofReplayCache:
    """Small in-memory replay cache for proof JWT `jti` values."""

    entries: dict[str, datetime] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def check_and_store(
        self,
        jti: str,
        *,
        expires_at: datetime,
        now: datetime | None = None,
    ) -> bool:
        effective_now = _utc(now or datetime.now(timezone.utc))
        with self.lock:
            self._prune(effective_now)
            existing = self.entries.get(jti)
            if existing is not None and existing > effective_now:
                return False
            self.entries[jti] = expires_at
            return True

    def _prune(self, now: datetime) -> None:
        stale = [jti for jti, expiry in self.entries.items() if expiry <= now]
        for jti in stale:
            del self.entries[jti]


@dataclass
class AgentProofSigner:
    """Mint a DPoP-style proof JWT bound to one HTTP request."""

    private_key: Any
    public_jwk: Mapping[str, Any]
    algorithm: str = "RS256"

    def __post_init__(self) -> None:
        _require_pyjwt()

    def sign(
        self,
        *,
        identity_token: str,
        method: str,
        url: str,
        issued_at: datetime | None = None,
        jti: str | None = None,
        nonce: str | None = None,
    ) -> str:
        effective_issued_at = _utc(issued_at or datetime.now(timezone.utc))
        claims: dict[str, Any] = {
            "htm": method.upper(),
            "htu": url,
            "iat": _timestamp(effective_issued_at),
            "jti": jti or secrets.token_urlsafe(16),
            "ath": _token_hash(identity_token),
        }
        if nonce is not None:
            claims["nonce"] = nonce
        return pyjwt.encode(
            claims,
            self.private_key,
            algorithm=self.algorithm,
            headers={"typ": "dpop+jwt", "jwk": dict(self.public_jwk)},
        )


@dataclass
class AgentProofVerifier:
    """Verify a DPoP-style proof JWT against one HTTP request."""

    max_age: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    leeway: timedelta = field(default_factory=lambda: timedelta(seconds=30))
    replay_cache: AgentProofReplayCache | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(
        self,
        token: str,
        *,
        identity_token: str,
        expected_method: str,
        expected_url: str,
        expected_key_binding: str,
        now: datetime | None = None,
    ) -> bool:
        effective_now = _utc(now or datetime.now(timezone.utc))
        try:
            header = pyjwt.get_unverified_header(token)
            jwk = header.get("jwk")
            if not isinstance(jwk, Mapping):
                return False
            if header.get("typ") not in (None, "dpop+jwt", "asm-agent-proof+jwt"):
                return False
            if jwk_thumbprint(jwk) != expected_key_binding:
                return False
            algorithm = header.get("alg")
            if not isinstance(algorithm, str) or not algorithm:
                return False
            key = pyjwt.PyJWK.from_dict(dict(jwk)).key
            decoded = pyjwt.decode(
                token,
                key,
                algorithms=[algorithm],
                options={"verify_aud": False, "require": ["iat", "jti", "htm", "htu", "ath"]},
            )
            issued_at = _datetime_claim(decoded["iat"])
            if issued_at is None:
                return False
            if issued_at > effective_now + self.leeway:
                return False
            if issued_at < effective_now - self.max_age - self.leeway:
                return False
            if str(decoded["htm"]).upper() != expected_method.upper():
                return False
            if str(decoded["htu"]) != expected_url:
                return False
            if str(decoded["ath"]) != _token_hash(identity_token):
                return False
            if self.replay_cache is not None and not self.replay_cache.check_and_store(
                str(decoded["jti"]),
                expires_at=issued_at + self.max_age + self.leeway,
                now=effective_now,
            ):
                return False
        except pyjwt.PyJWTError:
            return False
        except (KeyError, TypeError, ValueError):
            return False
        return True


# ---------------------------------------------------------------------------
# WIMSE alignment
#
# References:
#   draft-ietf-wimse-workload-identity-bcp (WIMSE BCP)
#   draft-klrc-aiagent-auth (AI Agent Auth extension to WIMSE)
#   RFC 9068 (JWT Profile for Access Tokens, used as claim basis)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkloadIdentity:
    """Structured representation of a local workload before tokenisation.

    This is the Tessera-internal form; use ``WIMSEIdentityClaim.from_workload_identity``
    to produce the WIMSE wire-format claim set.

    Args:
        spiffe_id: SPIFFE ID of the workload (e.g. ``spiffe://trust.example/svc/foo``).
        trust_domain: Trust domain extracted from the SPIFFE ID.
        issuer: JWT ``iss`` value for the WIT (typically the SPIRE server URI).
        audience: Intended audience(s) for the WIT.
        tenant: Optional tenant / namespace for multi-tenant deployments
            (``tenant`` claim in draft-klrc-aiagent-auth).
        issued_at: Token issuance time. Defaults to now.
        expires_at: Token expiry. Defaults to 1 hour from ``issued_at``.
    """

    spiffe_id: str
    trust_domain: str
    issuer: str
    audience: tuple[str, ...]
    tenant: str | None = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=1)
    )


@dataclass(frozen=True)
class WIMSEIdentityClaim:
    """WIMSE workload identity claim set.

    Maps to the claim set defined in draft-ietf-wimse-workload-identity-bcp
    and extended by draft-klrc-aiagent-auth for AI-agent contexts.

    Fields:
        iss: Issuer -- the SPIRE server or WIMSE-capable issuer URI.
        sub: Subject -- the SPIFFE ID of the workload.
        aud: Audience -- one or more intended recipients.
        wimse_id: The canonical WIMSE workload identifier (mirrors ``sub``
            for SPIFFE-backed deployments, but may differ for non-SPIFFE).
        tenant: Optional tenant / namespace (draft-klrc-aiagent-auth
            ``tenant`` claim).
        created_at: Issuance time (maps to JWT ``iat``).
        expires_at: Expiry time (maps to JWT ``exp``).
    """

    iss: str
    sub: str
    aud: tuple[str, ...]
    wimse_id: str
    tenant: str | None
    created_at: datetime
    expires_at: datetime

    @classmethod
    def from_workload_identity(cls, workload_id: WorkloadIdentity) -> WIMSEIdentityClaim:
        """Build a WIMSE claim set from a local workload descriptor.

        The ``wimse_id`` is set to the SPIFFE ID, matching the convention in
        draft-ietf-wimse-workload-identity-bcp Section 4.

        Args:
            workload_id: Local workload descriptor.

        Returns:
            A frozen ``WIMSEIdentityClaim`` ready for tokenisation.
        """
        return cls(
            iss=workload_id.issuer,
            sub=workload_id.spiffe_id,
            aud=workload_id.audience,
            wimse_id=workload_id.spiffe_id,
            tenant=workload_id.tenant,
            created_at=_utc(workload_id.issued_at),
            expires_at=_utc(workload_id.expires_at),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JWT-compatible claim dict."""
        payload: dict[str, Any] = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": list(self.aud),
            "wimse_id": self.wimse_id,
            "iat": int(self.created_at.timestamp()),
            "exp": int(self.expires_at.timestamp()),
        }
        if self.tenant is not None:
            payload["tenant"] = self.tenant
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> WIMSEIdentityClaim:
        """Deserialise from a JWT claim dict.

        Args:
            data: Raw claim dict (e.g. from a decoded JWT payload).

        Returns:
            A ``WIMSEIdentityClaim`` instance.

        Raises:
            ValueError: If required claims are missing or have wrong types.
        """
        try:
            iss = str(data["iss"])
            sub = str(data["sub"])
            raw_aud = data["aud"]
            aud = (raw_aud,) if isinstance(raw_aud, str) else tuple(raw_aud)
            wimse_id = str(data["wimse_id"])
            created_at = datetime.fromtimestamp(float(data["iat"]), timezone.utc)
            expires_at = datetime.fromtimestamp(float(data["exp"]), timezone.utc)
        except (KeyError, TypeError) as exc:
            raise ValueError(f"missing or malformed WIMSE claim: {exc}") from exc
        return cls(
            iss=iss,
            sub=sub,
            aud=aud,
            wimse_id=wimse_id,
            tenant=str(data["tenant"]) if "tenant" in data else None,
            created_at=created_at,
            expires_at=expires_at,
        )


class _WITSigner(Protocol):
    """Minimal signer interface for WorkloadIdentityToken."""

    def sign_bytes(self, data: bytes) -> str: ...


class _WITVerifier(Protocol):
    """Minimal verifier interface for WorkloadIdentityToken."""

    def verify_bytes(self, data: bytes, signature: str) -> bool: ...


@dataclass(frozen=True)
class WorkloadIdentityToken:
    """WIT (Workload Identity Token) envelope.

    The WIT is a signed wrapper for a ``WIMSEIdentityClaim``.  In production
    SPIFFE deployments this is a JWT-SVID with ``typ: wit+jwt``; in Tessera's
    reference implementation we use HMAC-SHA256 over the canonical JSON
    payload so the test suite has no external key-management dependency.

    The ``typ`` header value follows draft-ietf-wimse-workload-identity-bcp:
    ``wit+jwt``.

    Args:
        claims: The WIMSE claim set carried by this token.
        alg: Algorithm identifier (informational; actual signing uses the
            provided signer object).
        signature: Hex-encoded HMAC-SHA256 over the canonical payload, or an
            empty string for unsigned tokens.
    """

    claims: WIMSEIdentityClaim
    alg: str = "HS256"
    signature: str = ""

    def _canonical(self) -> bytes:
        """Canonical bytes covered by the signature."""
        return json.dumps(
            self.claims.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def sign(self, key: bytes) -> WorkloadIdentityToken:
        """Return a signed copy using HMAC-SHA256.

        Args:
            key: Raw HMAC key bytes.

        Returns:
            A new ``WorkloadIdentityToken`` with ``signature`` set.
        """
        mac = hmac.new(key, self._canonical(), sha256).hexdigest()
        return WorkloadIdentityToken(claims=self.claims, alg=self.alg, signature=mac)

    def verify(self, key: bytes) -> WIMSEIdentityClaim:
        """Verify the HMAC and return the claim set on success.

        Args:
            key: Raw HMAC key bytes.

        Returns:
            The embedded ``WIMSEIdentityClaim`` when verification succeeds.

        Raises:
            ValueError: If the signature is missing or does not match.
        """
        if not self.signature:
            raise ValueError("WorkloadIdentityToken has no signature")
        expected = hmac.new(key, self._canonical(), sha256).hexdigest()
        if not hmac.compare_digest(expected, self.signature):
            raise ValueError("WorkloadIdentityToken signature mismatch")
        return self.claims


@dataclass(frozen=True)
class OAuthTransactionToken:
    """Shim that presents a ``DelegationToken`` as a draft OAuth Transaction Token.

    draft-ietf-oauth-transaction-tokens defines a ``txn_token`` JWT claim set
    for conveying caller identity and authorization context across service
    boundaries.  This adapter wraps Tessera's existing ``DelegationToken``
    without altering its canonical form or HMAC key material.

    The canonical-form HMAC of the underlying ``DelegationToken`` is
    preserved byte-for-byte; no new signing round-trip occurs.

    Args:
        delegation: The wrapped ``DelegationToken``.
    """

    delegation: DelegationToken

    def to_txn_token_claims(self) -> dict[str, Any]:
        """Serialise to a draft OAuth Transaction Token claim dict.

        Maps ``DelegationToken`` fields as follows:

        - ``sub`` <- ``delegation.delegate``
        - ``azp`` (authorised party) <- ``delegation.subject``
        - ``aud`` <- ``[delegation.audience]``
        - ``txn_token.authorized_actions`` <- sorted actions
        - ``txn_token.constraints`` <- constraints dict
        - ``txn_token.session_id`` <- session_id
        - ``exp`` <- ``delegation.expires_at`` as a Unix timestamp

        Returns:
            A dict suitable for JSON serialisation or JWT payload construction.
        """
        d = self.delegation
        claims: dict[str, Any] = {
            "sub": d.delegate,
            "azp": d.subject,
            "aud": [d.audience],
            "exp": int(_utc(d.expires_at).timestamp()),
            "txn_token": {
                "authorized_actions": sorted(d.authorized_actions),
                "constraints": d.constraints,
                "session_id": d.session_id,
            },
        }
        return claims


__all__ = [
    # Pre-existing
    "AgentIdentity",
    "AgentIdentityVerifier",
    "JWTAgentIdentitySigner",
    "JWTAgentIdentityVerifier",
    "JWKSAgentIdentityVerifier",
    "AgentProofReplayCache",
    "AgentProofSigner",
    "AgentProofVerifier",
    "jwk_thumbprint",
    # WIMSE alignment (Wave 2I)
    "WorkloadIdentity",
    "WIMSEIdentityClaim",
    "WorkloadIdentityToken",
    "OAuthTransactionToken",
]
