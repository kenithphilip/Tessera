"""Signed evidence bundle tests."""

from __future__ import annotations

import pytest

from tessera.evidence import (
    EvidenceBundle,
    HMACEvidenceSigner,
    HMACEvidenceVerifier,
    JWTEvidenceSigner,
    JWTEvidenceVerifier,
    SignedEvidenceBundle,
)
from tessera.events import EvidenceBuffer, EventKind, SecurityEvent

KEY = b"test-evidence-key-do-not-use-in-prod"


def _buffer() -> EvidenceBuffer:
    buffer = EvidenceBuffer()
    buffer(
        SecurityEvent.now(
            kind=EventKind.POLICY_DENY,
            principal="alice",
            detail={"tool": "send_email"},
        )
    )
    buffer(
        SecurityEvent.now(
            kind=EventKind.PROOF_VERIFY_FAILURE,
            principal="alice",
            detail={"error": "invalid proof"},
        )
    )
    return buffer


def test_evidence_bundle_round_trips_from_buffer_export():
    bundle = EvidenceBundle.from_buffer(_buffer())

    payload = bundle.to_dict()

    assert payload["schema_version"] == "tessera.evidence.v1"
    assert payload["event_count"] == 2
    assert payload["counts_by_kind"] == {
        "policy_deny": 1,
        "proof_verify_failure": 1,
    }
    assert EvidenceBundle.from_dict(payload) == bundle


def test_hmac_evidence_signature_round_trip():
    buffer = _buffer()
    bundle = EvidenceBundle.from_buffer(buffer)
    signer = HMACEvidenceSigner(KEY, issuer="spiffe://example.org/ns/proxy/i/abcd")
    verifier = HMACEvidenceVerifier(KEY)

    signed = buffer.sign(signer)

    assert verifier.verify(signed)
    assert signed.issuer == "spiffe://example.org/ns/proxy/i/abcd"
    assert signed.bundle.counts_by_kind == bundle.counts_by_kind
    assert signed.bundle.event_count == bundle.event_count


def test_hmac_evidence_signature_rejects_tampered_payload():
    bundle = EvidenceBundle.from_buffer(_buffer())
    signed = HMACEvidenceSigner(KEY).sign(bundle)
    tampered = SignedEvidenceBundle(
        bundle=EvidenceBundle.from_dict(
            {
                **bundle.to_dict(),
                "event_count": 99,
            }
        ),
        algorithm=signed.algorithm,
        signature=signed.signature,
        issuer=signed.issuer,
        key_id=signed.key_id,
    )

    assert not HMACEvidenceVerifier(KEY).verify(tampered)


def test_signed_evidence_bundle_to_dict_round_trip():
    bundle = EvidenceBundle.from_buffer(_buffer())
    signed = HMACEvidenceSigner(KEY, key_id="kid-1").sign(bundle)

    assert SignedEvidenceBundle.from_dict(signed.to_dict()) == signed


def test_jwt_evidence_signature_round_trip():
    pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    bundle = EvidenceBundle.from_buffer(_buffer())
    signed = JWTEvidenceSigner(
        private_key=private_pem,
        issuer="spiffe://example.org/ns/proxy/i/abcd",
        key_id="evidence-1",
    ).sign(bundle)

    assert JWTEvidenceVerifier(
        public_key=public_pem,
        expected_issuer="spiffe://example.org/ns/proxy/i/abcd",
    ).verify(signed)
