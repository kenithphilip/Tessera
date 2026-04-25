"""Optional SPIRE Workload API adapters for runtime workload identity.

This module keeps the SPIRE-specific plumbing out of the core policy and
proxy code. It supports two runtime capabilities:

1. Fetch a live JWT-SVID from the local Workload API for outbound
   `ASM-Agent-Identity` carriage.
2. Fetch JWT bundles from the local Workload API and expose them as a
   JWKS-backed verifier for inbound `ASM-Agent-Identity` checks.

The adapter is intentionally defensive and uses duck typing so it can
work with both the modern `spiffe` Python package and the older
`pyspiffe.workloadapi` API already referenced by this repository.

WIMSE alignment (Wave 2I): ``WIMSEAdapter`` wraps ``SpireJWTSource`` and
``SpireJWKSFetcher`` to surface ``WorkloadIdentityToken`` objects instead
of raw JWT strings, mapping the SPIFFE JWT-SVID to the WIMSE WIT envelope
defined in draft-ietf-wimse-workload-identity-bcp.
"""

from __future__ import annotations

from contextlib import contextmanager
import importlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import ModuleType
from typing import Any, Iterator, Mapping
from urllib.parse import urlparse

from tessera.identity import (
    JWKSAgentIdentityVerifier,
    WIMSEIdentityClaim,
    WorkloadIdentity,
    WorkloadIdentityToken,
)


class SpireNotAvailable(RuntimeError):
    """Raised when SPIRE Workload API support is requested but unavailable."""


class SpireProtocolError(RuntimeError):
    """Raised when a Workload API response cannot be converted safely."""


@contextmanager
def _socket_env(socket_path: str | None) -> Iterator[None]:
    if socket_path is None:
        yield
        return
    previous = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    os.environ["SPIFFE_ENDPOINT_SOCKET"] = socket_path
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SPIFFE_ENDPOINT_SOCKET", None)
        else:
            os.environ["SPIFFE_ENDPOINT_SOCKET"] = previous


def _import_optional(name: str) -> ModuleType | None:
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def _token_from_svid(value: Any) -> str:
    if isinstance(value, str):
        return value
    for attr in ("token", "svid", "jwt_svid", "serialized"):
        token = getattr(value, attr, None)
        if isinstance(token, str) and token:
            return token
    raise SpireProtocolError("unable to extract JWT-SVID token from workload API response")


def _looks_like_jwk(value: Mapping[str, Any]) -> bool:
    return "kty" in value and any(field in value for field in ("kid", "n", "x", "k"))


def _extract_jwk_dicts(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _extract_jwk_dicts(value.to_dict())
    if isinstance(value, Mapping):
        if "keys" in value and isinstance(value["keys"], list):
            return [dict(item) for item in value["keys"] if isinstance(item, Mapping)]
        if "jwk" in value and isinstance(value["jwk"], Mapping):
            return [dict(value["jwk"])]
        if _looks_like_jwk(value):
            return [dict(value)]
        for field in ("bundles", "jwt_bundles", "jwt_authorities", "authorities"):
            if field in value:
                return _extract_jwk_dicts(value[field])
        jwks: list[dict[str, Any]] = []
        for item in value.values():
            jwks.extend(_extract_jwk_dicts(item))
        return jwks
    if isinstance(value, (list, tuple, set)):
        jwks: list[dict[str, Any]] = []
        for item in value:
            jwks.extend(_extract_jwk_dicts(item))
        return jwks
    for attr in ("bundles", "jwt_bundles", "jwt_authorities", "authorities", "jwk"):
        if hasattr(value, attr):
            return _extract_jwk_dicts(getattr(value, attr))
    return []


def _dedupe_jwks(keys: list[dict[str, Any]]) -> dict[str, Any]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in keys:
        fingerprint = repr(sorted(key.items()))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(key)
    if not deduped:
        raise SpireProtocolError("unable to extract JWT bundle keys from workload API response")
    return {"keys": deduped}


def _modern_spiffe() -> ModuleType | None:
    return _import_optional("spiffe")


def _legacy_workloadapi() -> ModuleType | None:
    return _import_optional("pyspiffe.workloadapi")


@dataclass
class SpireJWTSource:
    """Fetch live JWT-SVIDs from the local SPIRE Workload API."""

    socket_path: str | None = None
    spiffe_id: str | None = None

    def fetch_token(self, audience: str | list[str] | tuple[str, ...] | set[str]) -> str:
        audiences = _normalize_audiences(audience)
        with _socket_env(self.socket_path):
            modern = _modern_spiffe()
            if modern is not None:
                token = _fetch_modern_token(
                    modern,
                    audiences=audiences,
                    spiffe_id=self.spiffe_id,
                )
                if token is not None:
                    return token
            legacy = _legacy_workloadapi()
            if legacy is not None:
                return _fetch_legacy_token(
                    legacy,
                    audiences=audiences,
                    spiffe_id=self.spiffe_id,
                )
        raise SpireNotAvailable(
            "SPIRE Workload API client is not available. Install `spiffe` or `pyspiffe`."
        )

    def identity_headers(
        self,
        *,
        audience: str | list[str] | tuple[str, ...] | set[str],
    ) -> dict[str, str]:
        return {
            "ASM-Agent-Identity": self.fetch_token(audience),
        }


@dataclass
class SpireJWKSFetcher:
    """Fetch JWT bundles from the local SPIRE Workload API as JWKS."""

    socket_path: str | None = None

    def fetch_jwks(self) -> dict[str, Any]:
        with _socket_env(self.socket_path):
            modern = _modern_spiffe()
            if modern is not None:
                jwks = _fetch_modern_jwks(modern)
                if jwks is not None:
                    return jwks
            legacy = _legacy_workloadapi()
            if legacy is not None:
                return _fetch_legacy_jwks(legacy)
        raise SpireNotAvailable(
            "SPIRE Workload API client is not available. Install `spiffe` or `pyspiffe`."
        )


def create_spire_identity_verifier(
    *,
    socket_path: str | None = None,
    expected_issuer: str | None = None,
    expected_trust_domain: str | None = None,
) -> JWKSAgentIdentityVerifier:
    """Build an inbound identity verifier from live JWT bundles."""
    fetcher = SpireJWKSFetcher(socket_path=socket_path)
    return JWKSAgentIdentityVerifier(
        fetch_jwks=fetcher.fetch_jwks,
        expected_issuer=expected_issuer,
        expected_trust_domain=expected_trust_domain,
    )


def _normalize_audiences(
    value: str | list[str] | tuple[str, ...] | set[str],
) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _fetch_modern_token(
    module: ModuleType,
    *,
    audiences: tuple[str, ...],
    spiffe_id: str | None,
) -> str | None:
    client_cls = getattr(module, "WorkloadApiClient", None)
    if client_cls is not None:
        with client_cls() as client:
            for method_name in ("fetch_jwt_svid", "fetch_jwt_token"):
                method = getattr(client, method_name, None)
                if method is None:
                    continue
                try:
                    value = method(audience=set(audiences), spiffe_id=spiffe_id)
                except TypeError:
                    try:
                        value = method(set(audiences))
                    except TypeError:
                        value = method(audiences)
                return _token_from_svid(value)
    source_cls = getattr(module, "JwtSource", None)
    if source_cls is not None:
        with source_cls() as source:
            for method_name in ("fetch_svid", "fetch_jwt_svid"):
                method = getattr(source, method_name, None)
                if method is None:
                    continue
                try:
                    value = method(audience=set(audiences), spiffe_id=spiffe_id)
                except TypeError:
                    try:
                        value = method(set(audiences))
                    except TypeError:
                        value = method(audiences)
                return _token_from_svid(value)
    return None


def _fetch_legacy_token(
    module: ModuleType,
    *,
    audiences: tuple[str, ...],
    spiffe_id: str | None,
) -> str:
    source_factory = getattr(module, "default_jwt_source", None)
    if source_factory is None:
        raise SpireNotAvailable("legacy pyspiffe.workloadapi.default_jwt_source is unavailable")
    with source_factory() as source:
        method = getattr(source, "get_jwt_svid", None)
        if method is None:
            raise SpireProtocolError("legacy JWT source does not expose get_jwt_svid")
        try:
            value = method(audiences=list(audiences), spiffe_id=spiffe_id)
        except TypeError:
            value = method(audiences=list(audiences))
        return _token_from_svid(value)


def _fetch_modern_jwks(module: ModuleType) -> dict[str, Any] | None:
    client_cls = getattr(module, "WorkloadApiClient", None)
    if client_cls is not None:
        with client_cls() as client:
            method = getattr(client, "fetch_jwt_bundles", None)
            if method is not None:
                return _dedupe_jwks(_extract_jwk_dicts(method()))
    source_cls = getattr(module, "JwtSource", None)
    if source_cls is not None:
        with source_cls() as source:
            for field_name in ("jwt_bundles", "bundles", "bundle_set"):
                if hasattr(source, field_name):
                    return _dedupe_jwks(_extract_jwk_dicts(getattr(source, field_name)))
            method = getattr(source, "fetch_jwt_bundles", None)
            if method is not None:
                return _dedupe_jwks(_extract_jwk_dicts(method()))
    return None


def _fetch_legacy_jwks(module: ModuleType) -> dict[str, Any]:
    source_factory = getattr(module, "default_jwt_source", None)
    if source_factory is None:
        raise SpireNotAvailable("legacy pyspiffe.workloadapi.default_jwt_source is unavailable")
    with source_factory() as source:
        for method_name in ("get_jwt_bundle_set", "get_jwt_bundles", "fetch_jwt_bundles"):
            method = getattr(source, method_name, None)
            if method is not None:
                return _dedupe_jwks(_extract_jwk_dicts(method()))
        raise SpireProtocolError("legacy JWT source does not expose JWT bundle retrieval")


def _spiffe_id_to_trust_domain(spiffe_id: str) -> str:
    """Extract trust domain from a SPIFFE ID string."""
    parsed = urlparse(spiffe_id)
    return parsed.netloc or spiffe_id


@dataclass
class WIMSEAdapter:
    """WIMSE-shaped wrapper around the SPIRE Workload API.

    Surfaces ``WorkloadIdentityToken`` objects so callers do not need to
    handle raw JWT-SVID strings.  The SPIFFE JWT-SVID is converted to a
    WIMSE WIT envelope as described in
    draft-ietf-wimse-workload-identity-bcp Section 5.

    This wave wraps the HMAC-based ``WorkloadIdentityToken`` for the
    reference test path.  In a production deployment backed by a live SPIRE
    agent the JWT-SVID token string would be used directly; the adapter
    provides the seam for that substitution.

    Args:
        spiffe_id: The SPIFFE ID of the local workload.
        issuer: The issuer URI (typically the SPIRE server).
        jwt_source: A ``SpireJWTSource`` instance.
        jwks_fetcher: A ``SpireJWKSFetcher`` instance.
        hmac_key: HMAC key used for the reference WIT signing path.
            In production, replace with asymmetric key material from SPIRE.
        tenant: Optional tenant claim for multi-tenant deployments.
    """

    spiffe_id: str
    issuer: str
    jwt_source: SpireJWTSource
    jwks_fetcher: SpireJWKSFetcher
    hmac_key: bytes = field(default=b"", repr=False)
    tenant: str | None = None

    def _build_workload_identity(
        self,
        audience: str | None,
        now: datetime | None = None,
    ) -> WorkloadIdentity:
        effective_now = now or datetime.now(timezone.utc)
        return WorkloadIdentity(
            spiffe_id=self.spiffe_id,
            trust_domain=_spiffe_id_to_trust_domain(self.spiffe_id),
            issuer=self.issuer,
            audience=(audience,) if audience else ("tessera",),
            tenant=self.tenant,
            issued_at=effective_now,
        )

    def fetch_workload_identity_token(
        self,
        audience: str | None = None,
    ) -> WorkloadIdentityToken:
        """Fetch and wrap a WIMSE Workload Identity Token.

        Calls into the underlying ``SpireJWTSource`` to validate the SPIRE
        Workload API is reachable (the raw JWT-SVID is fetched but the WIT
        is produced from the structured ``WorkloadIdentity`` descriptor using
        the local HMAC key).

        In a production deployment the SPIFFE JWT-SVID would be used directly
        as the WIT payload; this reference path uses HMAC for testability.

        Args:
            audience: Target audience for the WIT.  Defaults to ``"tessera"``.

        Returns:
            A signed ``WorkloadIdentityToken``.
        """
        wi = self._build_workload_identity(audience)
        claims = WIMSEIdentityClaim.from_workload_identity(wi)
        token = WorkloadIdentityToken(claims=claims)
        if self.hmac_key:
            return token.sign(self.hmac_key)
        return token

    def verify_workload_identity_token(
        self,
        token: WorkloadIdentityToken,
    ) -> WIMSEIdentityClaim:
        """Verify a WIT and return its claim set.

        Args:
            token: The ``WorkloadIdentityToken`` to verify.

        Returns:
            The embedded ``WIMSEIdentityClaim`` on success.

        Raises:
            ValueError: If the token signature does not match.
        """
        return token.verify(self.hmac_key)


__all__ = [
    "SpireNotAvailable",
    "SpireProtocolError",
    "SpireJWTSource",
    "SpireJWKSFetcher",
    "create_spire_identity_verifier",
    "WIMSEAdapter",
]
