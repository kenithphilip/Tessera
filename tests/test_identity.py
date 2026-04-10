"""Workload identity and proof-of-possession tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from tessera.identity import (
    AgentProofReplayCache,
    AgentProofSigner,
    AgentProofVerifier,
    JWTAgentIdentitySigner,
    JWTAgentIdentityVerifier,
)


def _rsa_material() -> tuple[object, dict[str, str]]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return key, public_jwk


def test_jwt_agent_identity_verifier_accepts_valid_spiffe_identity():
    identity_key, proof_jwk = _rsa_material()
    token = JWTAgentIdentitySigner(
        private_key=identity_key,
        issuer="spiffe://example.org",
    ).sign(
        agent_id="spiffe://example.org/ns/agents/sa/caller",
        audience="spiffe://example.org/ns/proxy/i/abcd",
        valid_until=datetime.now(timezone.utc) + timedelta(minutes=5),
        valid_from=datetime.now(timezone.utc) - timedelta(seconds=5),
        software_identity={"framework": "pytest", "version": "1.0"},
        confirmation_key=proof_jwk,
    )

    identity = JWTAgentIdentityVerifier(
        public_key=identity_key.public_key(),
        expected_issuer="spiffe://example.org",
        expected_trust_domain="example.org",
    ).verify(token, audience="spiffe://example.org/ns/proxy/i/abcd")

    assert identity is not None
    assert identity.agent_id == "spiffe://example.org/ns/agents/sa/caller"
    assert identity.trust_domain == "example.org"
    assert identity.software_identity["framework"] == "pytest"
    assert identity.key_binding is not None


def test_jwt_agent_identity_verifier_rejects_non_spiffe_subject():
    identity_key, proof_jwk = _rsa_material()
    token = JWTAgentIdentitySigner(
        private_key=identity_key,
        issuer="spiffe://example.org",
    ).sign(
        agent_id="spiffe://example.org/ns/agents/sa/caller",
        audience="proxy://tessera",
        valid_until=datetime.now(timezone.utc) + timedelta(minutes=5),
        confirmation_key=proof_jwk,
        additional_claims={"sub": "https://example.org/caller"},
    )

    identity = JWTAgentIdentityVerifier(
        public_key=identity_key.public_key(),
        expected_issuer="spiffe://example.org",
    ).verify(token, audience="proxy://tessera")

    assert identity is None


def test_agent_proof_verifier_accepts_bound_request_and_rejects_replay():
    identity_key, _identity_jwk = _rsa_material()
    proof_key, proof_jwk = _rsa_material()
    identity_token = JWTAgentIdentitySigner(
        private_key=identity_key,
        issuer="spiffe://example.org",
    ).sign(
        agent_id="spiffe://example.org/ns/agents/sa/caller",
        audience="proxy://tessera",
        valid_until=datetime.now(timezone.utc) + timedelta(minutes=5),
        confirmation_key=proof_jwk,
    )
    identity = JWTAgentIdentityVerifier(
        public_key=identity_key.public_key(),
        expected_issuer="spiffe://example.org",
    ).verify(identity_token, audience="proxy://tessera")
    proof_token = AgentProofSigner(
        private_key=proof_key,
        public_jwk=proof_jwk,
    ).sign(
        identity_token=identity_token,
        method="POST",
        url="https://proxy.example.org/v1/chat/completions",
        jti="proof-replay-test",
    )
    verifier = AgentProofVerifier(replay_cache=AgentProofReplayCache())

    assert identity is not None
    assert verifier.verify(
        proof_token,
        identity_token=identity_token,
        expected_method="POST",
        expected_url="https://proxy.example.org/v1/chat/completions",
        expected_key_binding=identity.key_binding,
    )
    assert not verifier.verify(
        proof_token,
        identity_token=identity_token,
        expected_method="POST",
        expected_url="https://proxy.example.org/v1/chat/completions",
        expected_key_binding=identity.key_binding,
    )


def test_agent_proof_verifier_rejects_request_binding_mismatch():
    identity_key, _identity_jwk = _rsa_material()
    proof_key, proof_jwk = _rsa_material()
    identity_token = JWTAgentIdentitySigner(
        private_key=identity_key,
        issuer="spiffe://example.org",
    ).sign(
        agent_id="spiffe://example.org/ns/agents/sa/caller",
        audience="proxy://tessera",
        valid_until=datetime.now(timezone.utc) + timedelta(minutes=5),
        confirmation_key=proof_jwk,
    )
    identity = JWTAgentIdentityVerifier(
        public_key=identity_key.public_key(),
        expected_issuer="spiffe://example.org",
    ).verify(identity_token, audience="proxy://tessera")
    proof_token = AgentProofSigner(
        private_key=proof_key,
        public_jwk=proof_jwk,
    ).sign(
        identity_token=identity_token,
        method="POST",
        url="https://proxy.example.org/v1/chat/completions",
    )

    assert identity is not None
    assert not AgentProofVerifier().verify(
        proof_token,
        identity_token=identity_token,
        expected_method="GET",
        expected_url="https://proxy.example.org/v1/chat/completions",
        expected_key_binding=identity.key_binding,
    )
