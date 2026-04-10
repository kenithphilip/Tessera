"""mTLS transport identity parsing and verification."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tessera.mtls import MTLSPeerVerificationError, extract_peer_identity


def _client_cert_pem(*, agent_id: str | None) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "caller.example.org")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(minutes=5))
    )
    if agent_id is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(agent_id)]
            ),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def test_extract_peer_identity_from_asgi_tls_extension() -> None:
    scope = {
        "extensions": {
            "tls": {
                "server_cert": None,
                "client_cert_chain": [
                    _client_cert_pem(
                        agent_id="spiffe://example.org/ns/agents/sa/caller"
                    )
                ],
                "client_cert_name": "CN=caller.example.org",
                "client_cert_error": None,
            }
        }
    }

    identity = extract_peer_identity(scope=scope, headers={})

    assert identity is not None
    assert identity.agent_id == "spiffe://example.org/ns/agents/sa/caller"
    assert identity.trust_domain == "example.org"
    assert identity.source == "asgi_tls_extension"


def test_extract_peer_identity_rejects_non_spiffe_certificate() -> None:
    scope = {
        "extensions": {
            "tls": {
                "server_cert": None,
                "client_cert_chain": [_client_cert_pem(agent_id=None)],
                "client_cert_error": None,
            }
        }
    }

    with pytest.raises(MTLSPeerVerificationError, match="SPIFFE URI SAN"):
        extract_peer_identity(scope=scope, headers={})


def test_extract_peer_identity_from_trusted_xfcc() -> None:
    scope = {"client": ("testclient", 50000)}
    headers = {
        "x-forwarded-client-cert": (
            'By=spiffe://example.org/ns/proxy/sa/envoy;'
            'Hash=deadbeef;Subject="CN=caller";'
            "URI=spiffe://example.org/ns/agents/sa/caller"
        )
    }

    identity = extract_peer_identity(
        scope=scope,
        headers=headers,
        trust_xfcc=True,
        trusted_proxy_hosts=("testclient",),
        allowed_trust_domains=("example.org",),
    )

    assert identity is not None
    assert identity.agent_id == "spiffe://example.org/ns/agents/sa/caller"
    assert identity.source == "xfcc"


def test_extract_peer_identity_rejects_untrusted_xfcc_source() -> None:
    scope = {"client": ("evil-proxy", 50000)}
    headers = {
        "x-forwarded-client-cert": "URI=spiffe://example.org/ns/agents/sa/caller"
    }

    with pytest.raises(MTLSPeerVerificationError, match="not trusted"):
        extract_peer_identity(
            scope=scope,
            headers=headers,
            trust_xfcc=True,
            trusted_proxy_hosts=("testclient",),
        )
