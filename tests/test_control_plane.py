"""Reference control-plane tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest

import tessera.cli as cli
from tessera.control_plane import (
    AgentHeartbeat,
    ControlPlaneState,
    HMACControlPlaneSigner,
    HMACControlPlaneVerifier,
    PolicyDistributionInput,
    RegistryDistributionInput,
    SignedControlPlaneDocument,
    create_control_plane_app,
)

AUTH_HEADER = {"Authorization": "Bearer control-plane-token"}
SIGNING_KEY = b"control-plane-signing-key"
HEARTBEAT_AUDIENCE = "tessera://control-plane/heartbeat"


def _match_headers(client: TestClient, path: str) -> dict[str, str]:
    response = client.get(path, headers=AUTH_HEADER)
    assert response.status_code == 200
    return {**AUTH_HEADER, "If-Match": response.headers["etag"]}


def _heartbeat_identity_verifier_and_headers(
    path: str,
    *,
    method: str = "POST",
    audience: str = HEARTBEAT_AUDIENCE,
    proof_url: str | None = None,
    agent_id: str = "spiffe://example.org/ns/agents/sa/gateway-1",
) -> tuple[Any, dict[str, str]]:
    pytest.importorskip("jwt")
    pytest.importorskip("cryptography")
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from tessera.identity import (
        AgentProofSigner,
        JWTAgentIdentitySigner,
        JWTAgentIdentityVerifier,
    )

    identity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proof_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    proof_jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(proof_key.public_key()))
    identity_token = JWTAgentIdentitySigner(
        private_key=identity_key,
        issuer="spiffe://example.org",
    ).sign(
        agent_id=agent_id,
        audience=audience,
        valid_until=datetime.now(UTC) + timedelta(minutes=5),
        valid_from=datetime.now(UTC) - timedelta(seconds=5),
        software_identity={"component": "gateway", "runtime": "pytest"},
        confirmation_key=proof_jwk,
    )
    proof_token = AgentProofSigner(
        private_key=proof_key,
        public_jwk=proof_jwk,
    ).sign(
        identity_token=identity_token,
        method=method,
        url=proof_url or f"http://testserver{path}",
    )
    return (
        JWTAgentIdentityVerifier(
            public_key=identity_key.public_key(),
            expected_issuer="spiffe://example.org",
            expected_trust_domain="example.org",
        ),
        {
            "ASM-Agent-Identity": identity_token,
            "ASM-Agent-Proof": proof_token,
        },
    )


def _client_cert_pem(*, agent_id: str | None) -> str:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(minutes=5))
    )
    if agent_id is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(agent_id)]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _make_control_plane_client(
    *,
    bearer_token: str | None = "control-plane-token",
    heartbeat_identity_verifier: Any | None = None,
    heartbeat_identity_audience: str = HEARTBEAT_AUDIENCE,
    require_heartbeat_proof: bool = False,
    require_heartbeat_mtls: bool = False,
    heartbeat_trust_xfcc: bool = False,
    heartbeat_trusted_proxy_hosts: tuple[str, ...] = (),
    heartbeat_mtls_trust_domains: tuple[str, ...] = (),
    tls_extension: dict[str, Any] | None = None,
    injected_client_host: str | None = None,
) -> TestClient:
    app = create_control_plane_app(
        bearer_token=bearer_token,
        heartbeat_identity_verifier=heartbeat_identity_verifier,
        heartbeat_identity_audience=heartbeat_identity_audience,
        require_heartbeat_proof=require_heartbeat_proof,
        require_heartbeat_mtls=require_heartbeat_mtls,
        heartbeat_trust_xfcc=heartbeat_trust_xfcc,
        heartbeat_trusted_proxy_hosts=heartbeat_trusted_proxy_hosts,
        heartbeat_mtls_trust_domains=heartbeat_mtls_trust_domains,
    )
    if tls_extension is not None or injected_client_host is not None:

        @app.middleware("http")
        async def _inject_transport_scope(request, call_next):
            if tls_extension is not None:
                request.scope.setdefault("extensions", {})["tls"] = tls_extension
            if injected_client_host is not None:
                port = 50000
                client = request.scope.get("client")
                if isinstance(client, tuple) and len(client) == 2:
                    port = client[1]
                request.scope["client"] = (injected_client_host, port)
            return await call_next(request)

    return TestClient(app)


def test_control_plane_policy_distribution_sets_revision_and_etag():
    client = TestClient(create_control_plane_app(bearer_token="control-plane-token"))

    response = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={
            "default_required_trust": 100,
            "tool_requirements": {"send_email": 100, "web_search": 50},
            "opa": {
                "base_url": "https://opa.example.org",
                "bundle_revisions": {"security": "rev-123"},
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["tool_requirements"] == {"send_email": 100, "web_search": 50}
    assert body["opa"]["bundle_revisions"] == {"security": "rev-123"}
    assert response.headers["etag"] == f'"{body["revision"]}"'

    cached = client.get(
        "/v1/control/policy",
        headers={**AUTH_HEADER, "If-None-Match": response.headers["etag"]},
    )
    assert cached.status_code == 304


def test_control_plane_policy_revision_is_stable_for_identical_payload():
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now)

    first = state.update_policy(
        PolicyDistributionInput(tool_requirements={"send_email": 100})
    )
    state.now_factory = lambda: now + timedelta(minutes=5)
    second = state.update_policy(
        PolicyDistributionInput(tool_requirements={"send_email": 100})
    )

    assert first["revision"] == second["revision"]
    assert first["updated_at"] == second["updated_at"]


def test_control_plane_signed_policy_distribution_round_trip():
    signer = HMACControlPlaneSigner(
        SIGNING_KEY,
        issuer="spiffe://example.org/ns/control/sa/istiod",
        key_id="control-1",
    )
    client = TestClient(
        create_control_plane_app(
            bearer_token="control-plane-token",
            distribution_signer=signer,
        )
    )

    updated = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"send_email": 100}},
    )
    revision = updated.json()["revision"]

    response = client.get("/v1/control/policy/signed", headers=AUTH_HEADER)

    assert response.status_code == 200
    signed = SignedControlPlaneDocument.from_dict(response.json())
    assert signed.document_type == "policy"
    assert signed.document["revision"] == revision
    assert signed.issuer == "spiffe://example.org/ns/control/sa/istiod"
    assert signed.key_id == "control-1"
    assert HMACControlPlaneVerifier(SIGNING_KEY).verify(signed)
    assert response.headers["etag"] == f'"{revision}"'

    cached = client.get(
        "/v1/control/policy/signed",
        headers={**AUTH_HEADER, "If-None-Match": response.headers["etag"]},
    )
    assert cached.status_code == 304


def test_control_plane_serves_historical_policy_revisions():
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now)
    client = TestClient(create_control_plane_app(state, bearer_token="control-plane-token"))

    first = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"send_email": 100}},
    ).json()
    state.now_factory = lambda: now + timedelta(minutes=1)
    second = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"web_search": 50}},
    ).json()

    history = client.get("/v1/control/policy/history", headers=AUTH_HEADER).json()
    historical = client.get(
        f"/v1/control/policy?revision={first['revision']}",
        headers=AUTH_HEADER,
    ).json()

    assert first["revision"] != second["revision"]
    assert history["current_revision"] == second["revision"]
    assert history["revision_count"] == 2
    assert historical["tool_requirements"] == {"send_email": 100}
    assert historical["revision"] == first["revision"]


def test_control_plane_signed_policy_distribution_supports_historical_revision():
    signer = HMACControlPlaneSigner(SIGNING_KEY)
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now)
    client = TestClient(
        create_control_plane_app(
            state,
            bearer_token="control-plane-token",
            distribution_signer=signer,
        )
    )

    first = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"send_email": 100}},
    ).json()
    state.now_factory = lambda: now + timedelta(minutes=1)
    client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"web_search": 50}},
    )

    response = client.get(
        f"/v1/control/policy/signed?revision={first['revision']}",
        headers=AUTH_HEADER,
    )

    assert response.status_code == 200
    signed = SignedControlPlaneDocument.from_dict(response.json())
    assert signed.document["revision"] == first["revision"]
    assert signed.document["tool_requirements"] == {"send_email": 100}
    assert HMACControlPlaneVerifier(SIGNING_KEY).verify(signed)


def test_control_plane_signed_revisions_distribution_round_trip():
    signer = HMACControlPlaneSigner(SIGNING_KEY)
    client = TestClient(
        create_control_plane_app(
            bearer_token="control-plane-token",
            distribution_signer=signer,
        )
    )

    policy = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"send_email": 100}},
    ).json()
    registry = client.put(
        "/v1/control/registry",
        headers=_match_headers(client, "/v1/control/registry"),
        json={"external_tools": ["fetch_url"]},
    ).json()

    response = client.get("/v1/control/revisions/signed", headers=AUTH_HEADER)

    assert response.status_code == 200
    signed = SignedControlPlaneDocument.from_dict(response.json())
    assert signed.document_type == "revisions"
    assert signed.document["policy"]["current_revision"] == policy["revision"]
    assert signed.document["registry"]["current_revision"] == registry["revision"]
    assert HMACControlPlaneVerifier(SIGNING_KEY).verify(signed)

    cached = client.get(
        "/v1/control/revisions/signed",
        headers={**AUTH_HEADER, "If-None-Match": response.headers["etag"]},
    )
    assert cached.status_code == 304


def test_control_plane_registry_and_revisions_track_agent_acknowledgement():
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now)
    client = TestClient(create_control_plane_app(state, bearer_token="control-plane-token"))

    policy = client.put(
        "/v1/control/policy",
        headers=_match_headers(client, "/v1/control/policy"),
        json={"tool_requirements": {"send_email": 100}},
    ).json()
    registry = client.put(
        "/v1/control/registry",
        headers=_match_headers(client, "/v1/control/registry"),
        json={"external_tools": ["fetch_url", "web_search"]},
    ).json()

    heartbeat = client.post(
        "/v1/control/agents/heartbeat",
        headers=AUTH_HEADER,
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True, "a2a": True},
            "applied_policy_revision": policy["revision"],
            "applied_registry_revision": registry["revision"],
        },
    )
    assert heartbeat.status_code == 200

    revisions = client.get("/v1/control/revisions", headers=AUTH_HEADER).json()
    assert revisions["policy"]["acked_agents"] == 1
    assert revisions["registry"]["acked_agents"] == 1

    agents = client.get("/v1/control/agents", headers=AUTH_HEADER).json()
    assert agents["agent_count"] == 1
    assert agents["agents"][0]["stale"] is False
    assert revisions["policy"]["history_length"] == 1
    assert revisions["registry"]["history_length"] == 1
    assert revisions["policy"]["previous_revision"] is not None


def test_control_plane_status_marks_stale_agents():
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now, agent_ttl=timedelta(seconds=30))
    state.record_heartbeat(
        AgentHeartbeat(
            agent_id="spiffe://example.org/ns/agents/sa/gateway-1",
            agent_name="gateway-1",
            capabilities={"chat": True},
            status="ready",
            applied_policy_revision=None,
            applied_registry_revision=None,
            metadata={},
        )
    )
    state.now_factory = lambda: now + timedelta(minutes=1)
    client = TestClient(create_control_plane_app(state, bearer_token="control-plane-token"))

    status = client.get("/v1/control/status", headers=AUTH_HEADER).json()
    assert status["agent_count"] == 1
    assert status["stale_agent_count"] == 1
    assert status["agents_by_status"] == {"ready": 1}


def test_control_plane_rejects_missing_auth():
    client = TestClient(create_control_plane_app(bearer_token="control-plane-token"))

    response = client.get("/v1/control/status")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_control_plane_heartbeat_requires_workload_identity_when_configured():
    verifier, _headers = _heartbeat_identity_verifier_and_headers(
        "/v1/control/agents/heartbeat"
    )
    client = TestClient(
        create_control_plane_app(
            bearer_token="control-plane-token",
            heartbeat_identity_verifier=verifier,
            heartbeat_identity_audience=HEARTBEAT_AUDIENCE,
            require_heartbeat_proof=True,
        )
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing required heartbeat agent identity"


def test_control_plane_heartbeat_accepts_valid_workload_identity_and_proof():
    verifier, headers = _heartbeat_identity_verifier_and_headers(
        "/v1/control/agents/heartbeat"
    )
    client = TestClient(
        create_control_plane_app(
            bearer_token="control-plane-token",
            heartbeat_identity_verifier=verifier,
            heartbeat_identity_audience=HEARTBEAT_AUDIENCE,
            require_heartbeat_proof=True,
        )
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        headers=headers,
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
            "applied_policy_revision": "rev-policy-1",
            "applied_registry_revision": "rev-registry-1",
        },
    )

    assert response.status_code == 200
    agents = client.get("/v1/control/agents", headers=AUTH_HEADER).json()
    assert agents["agent_count"] == 1
    assert agents["agents"][0]["agent_id"] == "spiffe://example.org/ns/agents/sa/gateway-1"


def test_control_plane_heartbeat_rejects_payload_identity_mismatch():
    verifier, headers = _heartbeat_identity_verifier_and_headers(
        "/v1/control/agents/heartbeat"
    )
    client = TestClient(
        create_control_plane_app(
            bearer_token="control-plane-token",
            heartbeat_identity_verifier=verifier,
            heartbeat_identity_audience=HEARTBEAT_AUDIENCE,
            require_heartbeat_proof=True,
        )
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        headers=headers,
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/other",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
        },
    )

    assert response.status_code == 401
    assert (
        response.json()["detail"]
        == "heartbeat payload agent_id does not match verified identity"
    )


def test_control_plane_heartbeat_requires_transport_identity_when_mtls_is_enabled():
    client = _make_control_plane_client(
        require_heartbeat_mtls=True,
        heartbeat_mtls_trust_domains=("example.org",),
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing required transport client certificate identity"


def test_control_plane_heartbeat_accepts_verified_transport_identity_without_headers():
    client = _make_control_plane_client(
        require_heartbeat_mtls=True,
        heartbeat_mtls_trust_domains=("example.org",),
        tls_extension={
            "server_cert": None,
            "client_cert_chain": [
                _client_cert_pem(
                    agent_id="spiffe://example.org/ns/agents/sa/gateway-1"
                )
            ],
            "client_cert_name": "CN=caller.example.org",
            "client_cert_error": None,
        },
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
        },
    )

    assert response.status_code == 200
    agents = client.get("/v1/control/agents", headers=AUTH_HEADER).json()
    assert agents["agent_count"] == 1
    assert agents["agents"][0]["agent_id"] == "spiffe://example.org/ns/agents/sa/gateway-1"


def test_control_plane_heartbeat_rejects_transport_identity_mismatch():
    verifier, headers = _heartbeat_identity_verifier_and_headers(
        "/v1/control/agents/heartbeat"
    )
    client = _make_control_plane_client(
        heartbeat_identity_verifier=verifier,
        heartbeat_identity_audience=HEARTBEAT_AUDIENCE,
        require_heartbeat_proof=True,
        require_heartbeat_mtls=True,
        heartbeat_mtls_trust_domains=("example.org",),
        tls_extension={
            "server_cert": None,
            "client_cert_chain": [
                _client_cert_pem(
                    agent_id="spiffe://example.org/ns/agents/sa/other"
                )
            ],
            "client_cert_error": None,
        },
    )

    response = client.post(
        "/v1/control/agents/heartbeat",
        headers=headers,
        json={
            "agent_id": "spiffe://example.org/ns/agents/sa/gateway-1",
            "agent_name": "gateway-1",
            "capabilities": {"chat": True},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "transport identity does not match heartbeat agent identity"


def test_control_plane_policy_write_requires_if_match():
    client = TestClient(create_control_plane_app(bearer_token="control-plane-token"))

    missing = client.put(
        "/v1/control/policy",
        headers=AUTH_HEADER,
        json={"tool_requirements": {"send_email": 100}},
    )
    assert missing.status_code == 428

    mismatch = client.put(
        "/v1/control/policy",
        headers={**AUTH_HEADER, "If-Match": '"bogus"'},
        json={"tool_requirements": {"send_email": 100}},
    )
    assert mismatch.status_code == 412


def test_control_plane_persists_state_and_reloads(tmp_path: Path):
    now = datetime(2026, 4, 10, tzinfo=UTC)
    storage_file = tmp_path / "control-state.json"
    state = ControlPlaneState(
        storage_path=storage_file,
        now_factory=lambda: now,
    )
    policy = state.update_policy(
        PolicyDistributionInput(tool_requirements={"send_email": 100})
    )
    registry = state.update_registry(
        RegistryDistributionInput(external_tools=["fetch_url"])
    )
    state.record_heartbeat(
        AgentHeartbeat(
            agent_id="spiffe://example.org/ns/agents/sa/gateway-1",
            agent_name="gateway-1",
            capabilities={"chat": True},
            applied_policy_revision=policy["revision"],
            applied_registry_revision=registry["revision"],
        )
    )

    reloaded = ControlPlaneState(storage_path=storage_file, now_factory=lambda: now)
    agents = reloaded.list_agents()
    status = reloaded.status()
    revisions = reloaded.revisions()

    assert storage_file.exists()
    assert reloaded.policy_document()["tool_requirements"] == {"send_email": 100}
    assert reloaded.registry_document()["external_tools"] == ["fetch_url"]
    assert agents["agent_count"] == 1
    assert agents["agents"][0]["agent_id"] == "spiffe://example.org/ns/agents/sa/gateway-1"
    assert status["persistence"]["enabled"] is True
    assert status["persistence"]["loaded_from_disk"] is True
    assert revisions["policy"]["history_length"] == 1
    assert revisions["registry"]["history_length"] == 1


def test_control_plane_app_requires_auth_by_default():
    try:
        create_control_plane_app()
    except ValueError as exc:
        assert "control plane auth is required" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected auth requirement failure")


def test_control_plane_cli_runs_with_seed_files(
    monkeypatch,
    tmp_path: Path,
):
    captured: dict[str, Any] = {}
    policy_file = tmp_path / "policy.json"
    registry_file = tmp_path / "registry.json"
    storage_file = tmp_path / "control-state.json"
    policy_file.write_text(json.dumps({"tool_requirements": {"send_email": 100}}))
    registry_file.write_text(json.dumps({"external_tools": ["fetch_url"]}))

    def fake_create_control_plane_app(
        state: Any,
        *,
        bearer_token: str | None = None,
        allow_unauthenticated: bool = False,
        distribution_signer: Any = None,
        heartbeat_identity_verifier: Any = None,
        heartbeat_identity_audience: str = HEARTBEAT_AUDIENCE,
        require_heartbeat_proof: bool = False,
        require_heartbeat_mtls: bool = False,
        heartbeat_trust_xfcc: bool = False,
        heartbeat_trusted_proxy_hosts: tuple[str, ...] = (),
        heartbeat_mtls_trust_domains: tuple[str, ...] = (),
    ) -> str:
        captured["state"] = state
        captured["bearer_token"] = bearer_token
        captured["allow_unauthenticated"] = allow_unauthenticated
        captured["distribution_signer"] = distribution_signer
        captured["heartbeat_identity_verifier"] = heartbeat_identity_verifier
        captured["heartbeat_identity_audience"] = heartbeat_identity_audience
        captured["require_heartbeat_proof"] = require_heartbeat_proof
        captured["require_heartbeat_mtls"] = require_heartbeat_mtls
        captured["heartbeat_trust_xfcc"] = heartbeat_trust_xfcc
        captured["heartbeat_trusted_proxy_hosts"] = heartbeat_trusted_proxy_hosts
        captured["heartbeat_mtls_trust_domains"] = heartbeat_mtls_trust_domains
        return "control-app"

    def fake_run(app: Any, *, host: str, port: int) -> None:
        captured["app"] = app
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(cli, "create_control_plane_app", fake_create_control_plane_app)
    monkeypatch.setattr(cli.uvicorn, "run", fake_run)

    exit_code = cli.main(
        [
            "control-plane",
            "--host",
            "0.0.0.0",
            "--port",
            "9090",
            "--auth-token",
            "control-plane-token",
            "--storage-file",
            str(storage_file),
            "--policy-file",
            str(policy_file),
            "--registry-file",
            str(registry_file),
            "--agent-ttl-seconds",
            "42",
            "--signing-hmac-key",
            "control-plane-hmac",
            "--signing-issuer",
            "spiffe://example.org/ns/control/sa/istiod",
            "--signing-key-id",
            "control-1",
        ]
    )

    assert exit_code == 0
    assert captured["app"] == "control-app"
    assert captured["bearer_token"] == "control-plane-token"
    assert captured["allow_unauthenticated"] is False
    assert isinstance(captured["distribution_signer"], HMACControlPlaneSigner)
    assert captured["distribution_signer"].issuer == "spiffe://example.org/ns/control/sa/istiod"
    assert captured["distribution_signer"].key_id == "control-1"
    assert captured["heartbeat_identity_verifier"] is None
    assert captured["heartbeat_identity_audience"] == HEARTBEAT_AUDIENCE
    assert captured["require_heartbeat_proof"] is False
    assert captured["require_heartbeat_mtls"] is False
    assert captured["heartbeat_trust_xfcc"] is False
    assert captured["heartbeat_trusted_proxy_hosts"] == ()
    assert captured["heartbeat_mtls_trust_domains"] == ()
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9090
    assert captured["state"].policy_document()["tool_requirements"] == {"send_email": 100}
    assert captured["state"].registry_document()["external_tools"] == ["fetch_url"]
    assert captured["state"].storage_path == storage_file
    assert captured["state"].agent_ttl == timedelta(seconds=42)


def test_control_plane_cli_requires_auth_token(monkeypatch) -> None:
    called: dict[str, Any] = {"ran": False}

    def fake_run(*args: Any, **kwargs: Any) -> None:
        called["ran"] = True

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)

    exit_code = cli.main(["control-plane"])

    assert exit_code == 2
    assert called["ran"] is False


def test_control_plane_cli_rejects_conflicting_signing_options(monkeypatch) -> None:
    called: dict[str, Any] = {"ran": False}

    def fake_run(*args: Any, **kwargs: Any) -> None:
        called["ran"] = True

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)

    exit_code = cli.main(
        [
            "control-plane",
            "--auth-token",
            "control-plane-token",
            "--signing-hmac-key",
            "one",
            "--signing-private-key-file",
            "/tmp/other.pem",
        ]
    )

    assert exit_code == 2
    assert called["ran"] is False
