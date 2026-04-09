"""Unified signer API: make_segment and LabeledSegment.verify.

Validates that the signer/verifier abstraction is wired correctly, HMAC
still works via bytes, and JWT works via LabelSigner/LabelVerifier.
"""

from __future__ import annotations

import pytest

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from tessera.signing import (  # noqa: E402
    HMACSigner,
    HMACVerifier,
    JWTSigner,
    JWTVerifier,
)

KEY = b"test-hmac-key-do-not-use-in-prod"


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


def test_make_segment_rejects_both_key_and_signer():
    with pytest.raises(ValueError):
        make_segment(
            content="x",
            origin=Origin.USER,
            principal="alice",
            key=KEY,
            signer=HMACSigner(KEY),
        )


def test_make_segment_rejects_neither_key_nor_signer():
    with pytest.raises(ValueError):
        make_segment(
            content="x",
            origin=Origin.USER,
            principal="alice",
        )


def test_hmac_signer_via_make_segment_round_trips():
    seg = make_segment(
        content="hello",
        origin=Origin.USER,
        principal="alice",
        signer=HMACSigner(KEY),
    )
    assert seg.verify(KEY) is True
    assert seg.verify(HMACVerifier(KEY)) is True


def test_jwt_signer_via_make_segment_round_trips():
    priv, pub = _rsa_keypair()
    seg = make_segment(
        content="hello",
        origin=Origin.USER,
        principal="spiffe://example.org/retrieval",
        signer=JWTSigner(private_key=priv, algorithm="RS256"),
    )
    assert seg.verify(JWTVerifier(public_key=pub)) is True


def test_jwt_segment_rejects_hmac_key():
    priv, _ = _rsa_keypair()
    seg = make_segment(
        content="hello",
        origin=Origin.USER,
        principal="alice",
        signer=JWTSigner(private_key=priv),
    )
    # Passing an HMAC key to a JWT-signed segment must fail closed.
    assert seg.verify(KEY) is False


def test_context_principal_picks_first_user_segment():
    ctx = Context()
    ctx.add(make_segment("scraped", Origin.WEB, "alice", KEY))
    ctx.add(make_segment("do thing", Origin.USER, "alice", KEY))
    ctx.add(make_segment("other user", Origin.USER, "bob", KEY))
    assert ctx.principal == "alice"


def test_context_principal_none_when_no_user_segment():
    ctx = Context()
    ctx.add(make_segment("scraped", Origin.WEB, "alice", KEY))
    assert ctx.principal is None


def test_labeled_segment_verify_accepts_bytearray():
    seg = make_segment(
        content="x",
        origin=Origin.USER,
        principal="alice",
        key=KEY,
    )
    # bytearray also flows through the HMAC fast path.
    assert seg.verify(bytearray(KEY)) is True
