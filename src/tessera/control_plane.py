"""Reference control-plane surfaces for policy and registry distribution."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Lock
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request, Response, status as http_status
from pydantic import BaseModel, Field, field_validator

from tessera.labels import TrustLevel
from tessera.registry import ToolRegistry


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _revision_for(value: dict[str, Any]) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _etag_for(revision: str) -> str:
    return f'"{revision}"'


def _trust_value(value: int) -> int:
    allowed = {int(level) for level in TrustLevel}
    if value not in allowed:
        raise ValueError(f"trust level must be one of {sorted(allowed)}")
    return value


class OPAControlConfig(BaseModel):
    base_url: str
    decision_path: str = "/v1/data/tessera/authz/allow"
    include_provenance: bool = True
    fail_closed_backend_errors: bool = True
    bundle_revisions: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDistributionInput(BaseModel):
    default_required_trust: int = int(TrustLevel.USER)
    tool_requirements: dict[str, int] = Field(default_factory=dict)
    opa: OPAControlConfig | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("default_required_trust")
    @classmethod
    def _validate_default_trust(cls, value: int) -> int:
        return _trust_value(value)

    @field_validator("tool_requirements")
    @classmethod
    def _validate_tool_requirements(cls, value: dict[str, int]) -> dict[str, int]:
        normalized: dict[str, int] = {}
        for name, trust in value.items():
            tool = str(name).strip()
            if not tool:
                raise ValueError("tool requirement names must not be empty")
            normalized[tool] = _trust_value(int(trust))
        return normalized


class RegistryDistributionInput(BaseModel):
    external_tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("external_tools")
    @classmethod
    def _validate_external_tools(cls, value: list[str]) -> list[str]:
        registry = ToolRegistry.from_dict({"external_tools": value})
        return sorted(registry.external_tools)


class AgentHeartbeat(BaseModel):
    agent_id: str
    agent_name: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    status: str = "ready"
    applied_policy_revision: str | None = None
    applied_registry_revision: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("agent_id must not be empty")
        return normalized


@dataclass
class ControlPlaneState:
    """In-memory control-plane state with revisioned documents."""

    agent_ttl: timedelta = timedelta(minutes=5)
    now_factory: Callable[[], datetime] = _utc_now
    _policy: PolicyDistributionInput = field(default_factory=PolicyDistributionInput)
    _registry: RegistryDistributionInput = field(default_factory=RegistryDistributionInput)
    _policy_updated_at: datetime = field(default_factory=_utc_now)
    _registry_updated_at: datetime = field(default_factory=_utc_now)
    _agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def policy_document(self) -> dict[str, Any]:
        with self._lock:
            body = self._policy_body()
        return {**body, "revision": _revision_for(body)}

    def registry_document(self) -> dict[str, Any]:
        with self._lock:
            body = self._registry_body()
        return {**body, "revision": _revision_for(body)}

    def update_policy(self, value: PolicyDistributionInput) -> dict[str, Any]:
        with self._lock:
            self._policy = value
            self._policy_updated_at = self.now_factory()
            body = self._policy_body()
        return {**body, "revision": _revision_for(body)}

    def update_registry(self, value: RegistryDistributionInput) -> dict[str, Any]:
        with self._lock:
            self._registry = value
            self._registry_updated_at = self.now_factory()
            body = self._registry_body()
        return {**body, "revision": _revision_for(body)}

    def record_heartbeat(self, heartbeat: AgentHeartbeat) -> dict[str, Any]:
        now = self.now_factory()
        with self._lock:
            record = {
                "agent_id": heartbeat.agent_id,
                "agent_name": heartbeat.agent_name,
                "capabilities": heartbeat.capabilities,
                "status": heartbeat.status,
                "applied_policy_revision": heartbeat.applied_policy_revision,
                "applied_registry_revision": heartbeat.applied_registry_revision,
                "metadata": heartbeat.metadata,
                "last_seen": _iso(now),
            }
            self._agents[heartbeat.agent_id] = record
        return record

    def list_agents(self) -> dict[str, Any]:
        now = self.now_factory()
        with self._lock:
            agents = [self._agent_view(agent, now) for agent in self._agents.values()]
        agents.sort(key=lambda agent: agent["agent_id"])
        return {
            "schema_version": "tessera.control.agents.v1",
            "generated_at": _iso(now),
            "agent_count": len(agents),
            "agents": agents,
        }

    def revisions(self) -> dict[str, Any]:
        now = self.now_factory()
        policy = self.policy_document()
        registry = self.registry_document()
        with self._lock:
            agents = list(self._agents.values())
        return {
            "schema_version": "tessera.control.revisions.v1",
            "generated_at": _iso(now),
            "policy": {
                "revision": policy["revision"],
                "updated_at": policy["updated_at"],
                "acked_agents": sum(
                    1
                    for agent in agents
                    if agent.get("applied_policy_revision") == policy["revision"]
                ),
            },
            "registry": {
                "revision": registry["revision"],
                "updated_at": registry["updated_at"],
                "acked_agents": sum(
                    1
                    for agent in agents
                    if agent.get("applied_registry_revision") == registry["revision"]
                ),
            },
        }

    def status(self) -> dict[str, Any]:
        now = self.now_factory()
        policy = self.policy_document()
        registry = self.registry_document()
        with self._lock:
            agents = [self._agent_view(agent, now) for agent in self._agents.values()]
        counts = Counter(agent["status"] for agent in agents)
        stale = sum(1 for agent in agents if agent["stale"])
        return {
            "schema_version": "tessera.control.status.v1",
            "generated_at": _iso(now),
            "policy_revision": policy["revision"],
            "registry_revision": registry["revision"],
            "policy_updated_at": policy["updated_at"],
            "registry_updated_at": registry["updated_at"],
            "agent_count": len(agents),
            "stale_agent_count": stale,
            "agents_by_status": dict(counts),
        }

    def _policy_body(self) -> dict[str, Any]:
        return {
            "schema_version": "tessera.control.policy.v1",
            "updated_at": _iso(self._policy_updated_at),
            "default_required_trust": int(self._policy.default_required_trust),
            "tool_requirements": {
                name: int(trust)
                for name, trust in sorted(self._policy.tool_requirements.items())
            },
            "opa": None if self._policy.opa is None else self._policy.opa.model_dump(),
            "metadata": self._policy.metadata,
        }

    def _registry_body(self) -> dict[str, Any]:
        registry = ToolRegistry.from_dict(
            {"external_tools": self._registry.external_tools}
        )
        return {
            "schema_version": "tessera.control.registry.v1",
            "updated_at": _iso(self._registry_updated_at),
            "external_tools": sorted(registry.external_tools),
            "metadata": self._registry.metadata,
        }

    def _agent_view(self, record: dict[str, Any], now: datetime) -> dict[str, Any]:
        last_seen = datetime.fromisoformat(record["last_seen"])
        stale = now - last_seen > self.agent_ttl
        return {**record, "stale": stale}


def create_control_plane_app(
    state: ControlPlaneState | None = None,
    *,
    bearer_token: str | None = None,
    allow_unauthenticated: bool = False,
) -> FastAPI:
    """Create a FastAPI app exposing minimal control-plane surfaces."""
    if bearer_token is None and not allow_unauthenticated:
        raise ValueError(
            "control plane auth is required, set bearer_token or allow_unauthenticated=True"
        )
    state = state or ControlPlaneState()
    app = FastAPI(title="Tessera Control Plane", version="0.1.0")

    def authorize(request: Request) -> None:
        if allow_unauthenticated:
            return
        expected = f"Bearer {bearer_token}"
        if request.headers.get("authorization") != expected:
            raise HTTPException(
                status_code=http_status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid control-plane bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/.well-known/tessera-control.json")
    async def discovery() -> dict[str, Any]:
        return {
            "service": "tessera-control-plane",
            "version": "0.1.0",
            "auth": {
                "required": not allow_unauthenticated,
                "scheme": None if allow_unauthenticated else "bearer",
            },
            "paths": {
                "status": "/v1/control/status",
                "revisions": "/v1/control/revisions",
                "policy": "/v1/control/policy",
                "registry": "/v1/control/registry",
                "agents": "/v1/control/agents",
                "heartbeat": "/v1/control/agents/heartbeat",
            },
        }

    @app.get("/v1/control/status")
    async def status(request: Request) -> dict[str, Any]:
        authorize(request)
        return state.status()

    @app.get("/v1/control/revisions")
    async def revisions(request: Request) -> dict[str, Any]:
        authorize(request)
        return state.revisions()

    @app.get("/v1/control/policy", response_model=None)
    async def get_policy(request: Request, response: Response) -> dict[str, Any] | Response:
        authorize(request)
        return _conditional_document(request, response, state.policy_document())

    @app.put("/v1/control/policy")
    async def put_policy(
        request: Request,
        payload: PolicyDistributionInput,
        response: Response,
    ) -> dict[str, Any]:
        authorize(request)
        document = state.update_policy(payload)
        response.headers["ETag"] = _etag_for(document["revision"])
        return document

    @app.get("/v1/control/registry", response_model=None)
    async def get_registry(request: Request, response: Response) -> dict[str, Any] | Response:
        authorize(request)
        return _conditional_document(request, response, state.registry_document())

    @app.put("/v1/control/registry")
    async def put_registry(
        request: Request,
        payload: RegistryDistributionInput,
        response: Response,
    ) -> dict[str, Any]:
        authorize(request)
        document = state.update_registry(payload)
        response.headers["ETag"] = _etag_for(document["revision"])
        return document

    @app.post("/v1/control/agents/heartbeat")
    async def heartbeat(request: Request, payload: AgentHeartbeat) -> dict[str, Any]:
        authorize(request)
        return state.record_heartbeat(payload)

    @app.get("/v1/control/agents")
    async def agents(request: Request) -> dict[str, Any]:
        authorize(request)
        return state.list_agents()

    return app


def _conditional_document(
    request: Request,
    response: Response,
    document: dict[str, Any],
) -> dict[str, Any] | Response:
    etag = _etag_for(document["revision"])
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return document
