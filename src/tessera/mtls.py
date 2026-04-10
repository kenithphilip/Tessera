"""mTLS transport identity extraction for SPIFFE-aware proxies.

This module validates the caller identity carried by the transport
session rather than by an application token. It supports two sources:

1. The ASGI TLS extension, when the server exposes a verified client
   certificate chain in the request scope.
2. Envoy-style `X-Forwarded-Client-Cert` headers, but only when the
   request arrived from an explicitly trusted proxy host.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Mapping

from tessera.identity import _validate_spiffe_id

try:  # pragma: no cover - exercised when cryptography is installed
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    _X509_AVAILABLE = True
except ImportError:  # pragma: no cover
    x509 = None  # type: ignore[assignment]
    ExtensionOID = None  # type: ignore[assignment]
    _X509_AVAILABLE = False


class MTLSPeerVerificationError(ValueError):
    """Raised when transport identity is required but cannot be trusted."""


@dataclass(frozen=True)
class MTLSPeerIdentity:
    """The verified SPIFFE identity of the caller's transport session."""

    agent_id: str
    trust_domain: str
    source: str
    subject: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "agent_id": self.agent_id,
            "trust_domain": self.trust_domain,
            "source": self.source,
            "subject": self.subject,
        }


def extract_peer_identity(
    *,
    scope: Mapping[str, Any],
    headers: Mapping[str, str],
    trusted_proxy_hosts: Iterable[str] = (),
    trust_xfcc: bool = False,
    allowed_trust_domains: Iterable[str] = (),
) -> MTLSPeerIdentity | None:
    """Return the transport identity if one is present and acceptable."""
    peer = _from_asgi_tls_extension(scope)
    if peer is None and trust_xfcc:
        peer = _from_xfcc_header(
            headers,
            client_host=_client_host(scope),
            trusted_proxy_hosts=set(trusted_proxy_hosts),
        )
    if peer is None:
        return None
    if not _trust_domain_allowed(peer.trust_domain, allowed_trust_domains):
        raise MTLSPeerVerificationError(
            f"transport identity trust domain {peer.trust_domain!r} is not allowed"
        )
    return peer


def _from_asgi_tls_extension(scope: Mapping[str, Any]) -> MTLSPeerIdentity | None:
    extensions = scope.get("extensions", {})
    if not isinstance(extensions, Mapping):
        return None
    tls = extensions.get("tls")
    if not isinstance(tls, Mapping):
        return None
    error = tls.get("client_cert_error")
    if error:
        raise MTLSPeerVerificationError(
            f"client certificate verification failed in transport: {error}"
        )
    chain = tls.get("client_cert_chain") or ()
    cert_pem = _first_string(chain)
    if cert_pem is None:
        return None
    agent_id = _spiffe_id_from_pem(cert_pem)
    if agent_id is None:
        raise MTLSPeerVerificationError(
            "client certificate does not contain a SPIFFE URI SAN"
        )
    trust_domain, _path = _validate_spiffe_id(agent_id)
    return MTLSPeerIdentity(
        agent_id=agent_id,
        trust_domain=trust_domain,
        source="asgi_tls_extension",
        subject=_optional_str(tls.get("client_cert_name")),
    )


def _from_xfcc_header(
    headers: Mapping[str, str],
    *,
    client_host: str | None,
    trusted_proxy_hosts: set[str],
) -> MTLSPeerIdentity | None:
    header = headers.get("x-forwarded-client-cert")
    if header is None:
        return None
    if client_host is None or client_host not in trusted_proxy_hosts:
        raise MTLSPeerVerificationError(
            "X-Forwarded-Client-Cert is present but the immediate client is not trusted"
        )
    agent_id = _spiffe_id_from_xfcc(header)
    if agent_id is None:
        raise MTLSPeerVerificationError(
            "X-Forwarded-Client-Cert does not contain a SPIFFE URI"
        )
    trust_domain, _path = _validate_spiffe_id(agent_id)
    return MTLSPeerIdentity(
        agent_id=agent_id,
        trust_domain=trust_domain,
        source="xfcc",
        subject=None,
    )


def _trust_domain_allowed(
    trust_domain: str,
    allowed_trust_domains: Iterable[str],
) -> bool:
    allowed = tuple(allowed_trust_domains)
    if not allowed:
        return True
    return trust_domain in allowed


def _client_host(scope: Mapping[str, Any]) -> str | None:
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        host = client[0]
        return host if isinstance(host, str) else None
    return None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else None


def _first_string(values: object) -> str | None:
    if isinstance(values, str):
        return values
    if isinstance(values, Iterable):
        for value in values:
            if isinstance(value, str):
                return value
    return None


def _spiffe_id_from_pem(cert_pem: str) -> str | None:
    if not _X509_AVAILABLE:
        raise MTLSPeerVerificationError(
            "cryptography is required for client certificate parsing"
        )
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if _validate_spiffe_id(uri) is not None:
            return uri
    return None


_XFCC_URI_RE = re.compile(r"(?:^|[;,])\s*URI=(?P<quote>\"?)(?P<uri>spiffe://[^\";,]+)(?P=quote)")


def _spiffe_id_from_xfcc(header: str) -> str | None:
    match = _XFCC_URI_RE.search(header)
    if match is None:
        return None
    candidate = match.group("uri")
    if _validate_spiffe_id(candidate) is None:
        return None
    return candidate
