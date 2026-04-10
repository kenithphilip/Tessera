"""Reference control-plane tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

import tessera.cli as cli
from tessera.control_plane import AgentHeartbeat, ControlPlaneState, create_control_plane_app

AUTH_HEADER = {"Authorization": "Bearer control-plane-token"}


def test_control_plane_policy_distribution_sets_revision_and_etag():
    client = TestClient(create_control_plane_app(bearer_token="control-plane-token"))

    response = client.put(
        "/v1/control/policy",
        headers=AUTH_HEADER,
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


def test_control_plane_registry_and_revisions_track_agent_acknowledgement():
    now = datetime(2026, 4, 10, tzinfo=UTC)
    state = ControlPlaneState(now_factory=lambda: now)
    client = TestClient(create_control_plane_app(state, bearer_token="control-plane-token"))

    policy = client.put(
        "/v1/control/policy",
        headers=AUTH_HEADER,
        json={"tool_requirements": {"send_email": 100}},
    ).json()
    registry = client.put(
        "/v1/control/registry",
        headers=AUTH_HEADER,
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
    policy_file.write_text(json.dumps({"tool_requirements": {"send_email": 100}}))
    registry_file.write_text(json.dumps({"external_tools": ["fetch_url"]}))

    def fake_create_control_plane_app(
        state: Any,
        *,
        bearer_token: str | None = None,
        allow_unauthenticated: bool = False,
    ) -> str:
        captured["state"] = state
        captured["bearer_token"] = bearer_token
        captured["allow_unauthenticated"] = allow_unauthenticated
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
            "--policy-file",
            str(policy_file),
            "--registry-file",
            str(registry_file),
            "--agent-ttl-seconds",
            "42",
        ]
    )

    assert exit_code == 0
    assert captured["app"] == "control-app"
    assert captured["bearer_token"] == "control-plane-token"
    assert captured["allow_unauthenticated"] is False
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9090
    assert captured["state"].policy_document()["tool_requirements"] == {"send_email": 100}
    assert captured["state"].registry_document()["external_tools"] == ["fetch_url"]
    assert captured["state"].agent_ttl == timedelta(seconds=42)


def test_control_plane_cli_requires_auth_token(monkeypatch) -> None:
    called: dict[str, Any] = {"ran": False}

    def fake_run(*args: Any, **kwargs: Any) -> None:
        called["ran"] = True

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)

    exit_code = cli.main(["control-plane"])

    assert exit_code == 2
    assert called["ran"] is False
