"""JWT-SVID label signing and verification.

Uses an RSA keypair generated in-test so there is no external dependency
on a live SPIRE agent or static test key file. Skipped when PyJWT is not
installed.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from tessera.labels import Origin, TrustLabel, TrustLevel  # noqa: E402
from tessera.signing import (  # noqa: E402
    JWKSVerifier,
    JWTSigner,
    JWTVerifier,
)


def _rsa_keypair() -> tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _label() -> TrustLabel:
    return TrustLabel(
        origin=Origin.USER,
        principal="spiffe://example.org/retrieval",
        trust_level=TrustLevel.USER,
    )


def test_jwt_round_trip():
    priv, pub = _rsa_keypair()
    signer = JWTSigner(private_key=priv, algorithm="RS256", issuer="spiffe://example.org/retrieval")
    verifier = JWTVerifier(public_key=pub, expected_issuer="spiffe://example.org/retrieval")
    signed = signer.sign(_label(), "hello")
    assert verifier.verify(signed, "hello") is True


def test_jwt_tampered_content_rejected():
    priv, pub = _rsa_keypair()
    signer = JWTSigner(private_key=priv)
    verifier = JWTVerifier(public_key=pub)
    signed = signer.sign(_label(), "original")
    assert verifier.verify(signed, "tampered") is False


def test_jwt_wrong_key_rejected():
    priv1, _ = _rsa_keypair()
    _, pub2 = _rsa_keypair()
    signer = JWTSigner(private_key=priv1)
    verifier = JWTVerifier(public_key=pub2)
    signed = signer.sign(_label(), "x")
    assert verifier.verify(signed, "x") is False


def test_jwt_wrong_issuer_rejected():
    priv, pub = _rsa_keypair()
    signer = JWTSigner(private_key=priv, issuer="spiffe://example.org/retrieval")
    verifier = JWTVerifier(public_key=pub, expected_issuer="spiffe://example.org/other")
    signed = signer.sign(_label(), "x")
    assert verifier.verify(signed, "x") is False


def test_jwt_unsigned_label_rejected():
    _, pub = _rsa_keypair()
    verifier = JWTVerifier(public_key=pub)
    assert verifier.verify(_label(), "x") is False


def test_jwks_verifier_resolves_by_kid():
    import jwt as pyjwt

    priv, _ = _rsa_keypair()
    signer = JWTSigner(private_key=priv, algorithm="RS256", key_id="retrieval-1")

    # Build a JWKS from the RSA private key we just generated.
    # PyJWT exposes the algorithm to produce the JWK dict directly.
    alg = pyjwt.algorithms.RSAAlgorithm(pyjwt.algorithms.RSAAlgorithm.SHA256)
    from cryptography.hazmat.primitives import serialization as ser

    priv_key_obj = ser.load_pem_private_key(priv, password=None)
    public_jwk_json = alg.to_jwk(priv_key_obj.public_key())
    public_jwk = json.loads(public_jwk_json)
    public_jwk["kid"] = "retrieval-1"
    public_jwk["alg"] = "RS256"
    public_jwk["use"] = "sig"
    jwks = {"keys": [public_jwk]}

    verifier = JWKSVerifier(fetch_jwks=lambda: jwks)
    signed = signer.sign(_label(), "hello")
    assert verifier.verify(signed, "hello") is True


def test_jwks_verifier_rejects_unknown_kid():
    priv, _ = _rsa_keypair()
    signer = JWTSigner(private_key=priv, key_id="retrieval-1")
    verifier = JWKSVerifier(fetch_jwks=lambda: {"keys": []})
    signed = signer.sign(_label(), "hello")
    assert verifier.verify(signed, "hello") is False


def test_jwt_verifier_has_default_leeway():
    """Default leeway guards against clock drift between SPIRE and verifier."""
    from datetime import timedelta

    _, pub = _rsa_keypair()
    verifier = JWTVerifier(public_key=pub)
    assert verifier.leeway == timedelta(seconds=30)
