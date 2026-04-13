"""Reference control plane for signed policy and registry distribution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Protocol

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.identity import AgentIdentity, AgentProofReplayCache, AgentProofVerifier
from tessera.mtls import MTLSPeerVerificationError, extract_peer_identity

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tessera.identity import AgentIdentityVerifier

try:  # pragma: no cover - exercised when PyJWT is installed
    import jwt as pyjwt

    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    pyjwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False


class ControlPlaneSigningNotAvailable(RuntimeError):
    """Raised when JWT signing or verification is requested without PyJWT."""


def _require_pyjwt() -> None:
    if not _JWT_AVAILABLE:
        raise ControlPlaneSigningNotAvailable(
            "PyJWT is not installed. Install with: pip install tessera[spiffe]"
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _etag(revision: str) -> str:
    return f'"{revision}"'


def _revision_for(document_type: str, payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(
        _canonical_json({"document_type": document_type, "payload": payload})
    ).hexdigest()
    return f"rev-{digest[:16]}"


class OPAControlConfig(BaseModel):
    """Portable OPA metadata distributed by the control plane."""

    base_url: str | None = None
    decision_path: str | None = None
    bundle_revisions: dict[str, str] = Field(default_factory=dict)


class PolicyDistributionInput(BaseModel):
    """Policy distribution document consumed by gateways."""

    default_required_trust: int = 100
    tool_requirements: dict[str, int] = Field(default_factory=dict)
    opa: OPAControlConfig | None = None


class RegistryDistributionInput(BaseModel):
    """Registry distribution document consumed by gateways."""

    external_tools: list[str] = Field(default_factory=list)


class AgentHeartbeat(BaseModel):
    """Rollout acknowledgement and liveness update from a data plane."""

    agent_id: str
    agent_name: str
    capabilities: dict[str, Any] = Field(default_factory=dict)
    status: str = "ready"
    applied_policy_revision: str | None = None
    applied_registry_revision: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class SignedControlPlaneDocument:
    """Detached signature envelope for control-plane documents."""

    document_type: str
    document: dict[str, Any]
    algorithm: str
    signature: str
    issued_at: str
    issuer: str | None = None
    key_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedControlPlaneDocument":
        return cls(
            document_type=str(data["document_type"]),
            document=dict(data["document"]),
            algorithm=str(data["algorithm"]),
            signature=str(data["signature"]),
            issued_at=str(data["issued_at"]),
            issuer=None if data.get("issuer") is None else str(data["issuer"]),
            key_id=None if data.get("key_id") is None else str(data["key_id"]),
        )

    def signing_payload(self) -> dict[str, Any]:
        return {
            "document_type": self.document_type,
            "document": self.document,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "key_id": self.key_id,
        }

    def canonical(self) -> bytes:
        return _canonical_json(self.signing_payload())

    @property
    def document_sha256(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_type": self.document_type,
            "document": self.document,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "key_id": self.key_id,
        }


class ControlPlaneSigner(Protocol):
    """Signer protocol for distribution endpoints."""

    def sign(
        self,
        document_type: str,
        document: dict[str, Any],
    ) -> SignedControlPlaneDocument: ...


@dataclass
class HMACControlPlaneSigner:
    """Detached HMAC-SHA256 signer for control-plane documents."""

    key: bytes
    algorithm: str = "HMAC-SHA256"
    issuer: str | None = None
    key_id: str | None = None

    def sign(
        self,
        document_type: str,
        document: dict[str, Any],
    ) -> SignedControlPlaneDocument:
        signed = SignedControlPlaneDocument(
            document_type=document_type,
            document=document,
            algorithm=self.algorithm,
            signature="",
            issued_at=_utc_now().isoformat(),
            issuer=self.issuer,
            key_id=self.key_id,
        )
        signature = hmac.new(self.key, signed.canonical(), hashlib.sha256).hexdigest()
        return SignedControlPlaneDocument(
            document_type=signed.document_type,
            document=signed.document,
            algorithm=signed.algorithm,
            signature=signature,
            issued_at=signed.issued_at,
            issuer=signed.issuer,
            key_id=signed.key_id,
        )


@dataclass
class HMACControlPlaneVerifier:
    """Detached HMAC-SHA256 verifier for control-plane documents."""

    key: bytes
    algorithm: str = "HMAC-SHA256"

    def verify(self, signed: SignedControlPlaneDocument) -> bool:
        if signed.algorithm != self.algorithm:
            return False
        expected = hmac.new(self.key, signed.canonical(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signed.signature)


def _control_plane_claims(signed: SignedControlPlaneDocument) -> dict[str, Any]:
    return {
        "typ": "tessera_control_plane",
        "doc_type": signed.document_type,
        "doc_sha256": signed.document_sha256,
        "iat": int(datetime.fromisoformat(signed.issued_at).timestamp()),
    }


@dataclass
class JWTControlPlaneSigner:
    """JWT-based detached signer for control-plane documents."""

    private_key: Any
    algorithm: str = "RS256"
    issuer: str | None = None
    key_id: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def sign(
        self,
        document_type: str,
        document: dict[str, Any],
    ) -> SignedControlPlaneDocument:
        unsigned = SignedControlPlaneDocument(
            document_type=document_type,
            document=document,
            algorithm=self.algorithm,
            signature="",
            issued_at=_utc_now().isoformat(),
            issuer=self.issuer,
            key_id=self.key_id,
        )
        claims = _control_plane_claims(unsigned)
        if self.issuer is not None:
            claims["iss"] = self.issuer
        headers = {"kid": self.key_id} if self.key_id else None
        token = pyjwt.encode(
            claims,
            self.private_key,
            algorithm=self.algorithm,
            headers=headers,
        )
        return SignedControlPlaneDocument(
            document_type=unsigned.document_type,
            document=unsigned.document,
            algorithm=self.algorithm,
            signature=token,
            issued_at=unsigned.issued_at,
            issuer=self.issuer,
            key_id=self.key_id,
        )


@dataclass
class JWTControlPlaneVerifier:
    """JWT-based verifier for control-plane documents."""

    public_key: Any
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256", "HS256"])
    expected_issuer: str | None = None

    def __post_init__(self) -> None:
        _require_pyjwt()

    def verify(self, signed: SignedControlPlaneDocument) -> bool:
        try:
            decoded = pyjwt.decode(
                signed.signature,
                self.public_key,
                algorithms=self.algorithms,
                issuer=self.expected_issuer,
                options={"require": ["iat"]},
            )
        except pyjwt.PyJWTError:
            return False
        for key, value in _control_plane_claims(signed).items():
            if decoded.get(key) != value:
                return False
        return True


@dataclass
class ControlPlaneState:
    """Persistent state and revision tracking for the reference control plane."""

    storage_path: Path | None = None
    now_factory: Any = _utc_now
    agent_ttl: timedelta = timedelta(minutes=5)
    _policy_current_revision: str = field(init=False)
    _registry_current_revision: str = field(init=False)
    _policy_documents: dict[str, dict[str, Any]] = field(init=False, default_factory=dict)
    _registry_documents: dict[str, dict[str, Any]] = field(init=False, default_factory=dict)
    _policy_history: list[str] = field(init=False, default_factory=list)
    _registry_history: list[str] = field(init=False, default_factory=list)
    _agents: dict[str, dict[str, Any]] = field(init=False, default_factory=dict)
    _loaded_from_disk: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self.storage_path = None if self.storage_path is None else Path(self.storage_path)
        self._initialize_defaults()
        self._load_from_disk()

    def _initialize_defaults(self) -> None:
        now = self._now_iso()
        policy_payload = PolicyDistributionInput().model_dump(exclude_none=True)
        registry_payload = RegistryDistributionInput().model_dump(exclude_none=True)
        self._policy_current_revision = _revision_for("policy", policy_payload)
        self._registry_current_revision = _revision_for("registry", registry_payload)
        self._policy_documents = {
            self._policy_current_revision: {
                **policy_payload,
                "revision": self._policy_current_revision,
                "previous_revision": self._policy_current_revision,
                "updated_at": now,
            }
        }
        self._registry_documents = {
            self._registry_current_revision: {
                **registry_payload,
                "revision": self._registry_current_revision,
                "previous_revision": self._registry_current_revision,
                "updated_at": now,
            }
        }
        self._policy_history = []
        self._registry_history = []
        self._agents = {}
        self._loaded_from_disk = False

    def _now(self) -> datetime:
        return _normalize_timestamp(self.now_factory())

    def _now_iso(self) -> str:
        return self._now().isoformat()

    def _load_from_disk(self) -> None:
        if self.storage_path is None or not self.storage_path.exists():
            return
        data = json.loads(self.storage_path.read_text(encoding="utf-8"))
        self._policy_current_revision = str(data["policy"]["current_revision"])
        self._policy_documents = {
            str(key): dict(value)
            for key, value in dict(data["policy"]["documents"]).items()
        }
        self._policy_history = [str(value) for value in data["policy"]["history"]]
        self._registry_current_revision = str(data["registry"]["current_revision"])
        self._registry_documents = {
            str(key): dict(value)
            for key, value in dict(data["registry"]["documents"]).items()
        }
        self._registry_history = [str(value) for value in data["registry"]["history"]]
        self._agents = {
            str(key): dict(value) for key, value in dict(data.get("agents", {})).items()
        }
        self._loaded_from_disk = True

    def _persist(self) -> None:
        if self.storage_path is None:
            return
        payload = {
            "schema_version": "tessera.control_plane.v1",
            "policy": {
                "current_revision": self._policy_current_revision,
                "documents": self._policy_documents,
                "history": self._policy_history,
            },
            "registry": {
                "current_revision": self._registry_current_revision,
                "documents": self._registry_documents,
                "history": self._registry_history,
            },
            "agents": self._agents,
        }
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.storage_path.parent,
            delete=False,
        ) as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            temp_path = Path(handle.name)
        temp_path.replace(self.storage_path)

    def _update_document(
        self,
        *,
        document_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if document_type == "policy":
            current_revision = self._policy_current_revision
            documents = self._policy_documents
            history = self._policy_history
        else:
            current_revision = self._registry_current_revision
            documents = self._registry_documents
            history = self._registry_history
        current = documents[current_revision]
        current_payload = {
            key: value
            for key, value in current.items()
            if key not in {"revision", "previous_revision", "updated_at"}
        }
        if current_payload == payload:
            return dict(current)
        revision = _revision_for(document_type, payload)
        existing = documents.get(revision)
        if existing is not None:
            if document_type == "policy":
                self._policy_current_revision = revision
                if revision not in self._policy_history:
                    self._policy_history.append(revision)
            else:
                self._registry_current_revision = revision
                if revision not in self._registry_history:
                    self._registry_history.append(revision)
            self._persist()
            return dict(existing)
        document = {
            **payload,
            "revision": revision,
            "previous_revision": current_revision,
            "updated_at": self._now_iso(),
        }
        documents[revision] = document
        history.append(revision)
        if document_type == "policy":
            self._policy_current_revision = revision
        else:
            self._registry_current_revision = revision
        self._persist()
        return dict(document)

    def update_policy(self, value: PolicyDistributionInput) -> dict[str, Any]:
        payload = value.model_dump(exclude_none=True)
        return self._update_document(document_type="policy", payload=payload)

    def update_registry(self, value: RegistryDistributionInput) -> dict[str, Any]:
        payload = value.model_dump(exclude_none=True)
        return self._update_document(document_type="registry", payload=payload)

    def _document(
        self,
        document_type: str,
        *,
        revision: str | None = None,
    ) -> dict[str, Any]:
        if document_type == "policy":
            current_revision = self._policy_current_revision
            documents = self._policy_documents
        else:
            current_revision = self._registry_current_revision
            documents = self._registry_documents
        effective_revision = current_revision if revision is None else revision
        try:
            document = documents[effective_revision]
        except KeyError as exc:
            raise KeyError(
                f"unknown {document_type} revision {effective_revision!r}"
            ) from exc
        return dict(document)

    def policy_document(self, revision: str | None = None) -> dict[str, Any]:
        return self._document("policy", revision=revision)

    def registry_document(self, revision: str | None = None) -> dict[str, Any]:
        return self._document("registry", revision=revision)

    def document_at_revision(
        self,
        document_type: str,
        revision: str,
    ) -> dict[str, Any]:
        return self._document(document_type, revision=revision)

    def signed_document(
        self,
        document_type: str,
        signer: ControlPlaneSigner,
        *,
        revision: str | None = None,
    ) -> SignedControlPlaneDocument:
        document = self._document(document_type, revision=revision)
        return signer.sign(document_type, document)

    def record_heartbeat(self, heartbeat: AgentHeartbeat) -> dict[str, Any]:
        snapshot = heartbeat.model_dump(mode="json")
        snapshot["last_seen"] = self._now_iso()
        self._agents[heartbeat.agent_id] = snapshot
        self._persist()
        return dict(snapshot)

    def _agent_snapshot(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        last_seen = datetime.fromisoformat(str(snapshot["last_seen"]))
        stale = self._now() - _normalize_timestamp(last_seen) > self.agent_ttl
        return {**snapshot, "stale": stale}

    def list_agents(self) -> dict[str, Any]:
        agents = [
            self._agent_snapshot(snapshot)
            for snapshot in sorted(
                self._agents.values(),
                key=lambda value: (value.get("agent_name", ""), value["agent_id"]),
            )
        ]
        return {"agent_count": len(agents), "agents": agents}

    def _acked_agents(self, kind: str, revision: str) -> int:
        field = "applied_policy_revision" if kind == "policy" else "applied_registry_revision"
        return sum(1 for agent in self._agents.values() if agent.get(field) == revision)

    def revisions(self) -> dict[str, Any]:
        policy = self.policy_document()
        registry = self.registry_document()
        return {
            "policy": {
                "current_revision": policy["revision"],
                "previous_revision": policy["previous_revision"],
                "history_length": len(self._policy_history),
                "acked_agents": self._acked_agents("policy", policy["revision"]),
            },
            "registry": {
                "current_revision": registry["revision"],
                "previous_revision": registry["previous_revision"],
                "history_length": len(self._registry_history),
                "acked_agents": self._acked_agents("registry", registry["revision"]),
            },
        }

    def _history(self, document_type: str) -> dict[str, Any]:
        if document_type == "policy":
            history = [dict(self._policy_documents[revision]) for revision in self._policy_history]
            current_revision = self._policy_current_revision
        else:
            history = [
                dict(self._registry_documents[revision]) for revision in self._registry_history
            ]
            current_revision = self._registry_current_revision
        return {
            "current_revision": current_revision,
            "revision_count": len(history),
            "history": history,
        }

    def policy_history(self) -> dict[str, Any]:
        return self._history("policy")

    def registry_history(self) -> dict[str, Any]:
        return self._history("registry")

    def status(self) -> dict[str, Any]:
        agents = self.list_agents()["agents"]
        agents_by_status: dict[str, int] = {}
        for agent in agents:
            status = str(agent.get("status", "unknown"))
            agents_by_status[status] = agents_by_status.get(status, 0) + 1
        return {
            "agent_count": len(agents),
            "stale_agent_count": sum(1 for agent in agents if agent["stale"]),
            "agents_by_status": agents_by_status,
            "policy_revision": self._policy_current_revision,
            "registry_revision": self._registry_current_revision,
            "persistence": {
                "enabled": self.storage_path is not None,
                "loaded_from_disk": self._loaded_from_disk,
                "path": None if self.storage_path is None else str(self.storage_path),
            },
        }


def create_control_plane_app(
    state: ControlPlaneState | None = None,
    *,
    bearer_token: str | None = None,
    allow_unauthenticated: bool = False,
    distribution_signer: ControlPlaneSigner | None = None,
    heartbeat_identity_verifier: "AgentIdentityVerifier | None" = None,
    heartbeat_identity_audience: str = "tessera://control-plane/heartbeat",
    require_heartbeat_identity: bool | None = None,
    require_heartbeat_proof: bool | None = None,
    heartbeat_proof_max_age: timedelta = timedelta(minutes=5),
    require_heartbeat_mtls: bool = False,
    heartbeat_trust_xfcc: bool = False,
    heartbeat_trusted_proxy_hosts: tuple[str, ...] = (),
    heartbeat_mtls_trust_domains: tuple[str, ...] = (),
) -> FastAPI:
    """Build the authenticated reference control-plane API."""

    if bearer_token is None and not allow_unauthenticated:
        raise ValueError(
            "control plane auth is required, set bearer_token or allow_unauthenticated"
        )
    effective_require_heartbeat_identity = (
        heartbeat_identity_verifier is not None
        if require_heartbeat_identity is None
        else require_heartbeat_identity
    )
    effective_require_heartbeat_proof = (
        effective_require_heartbeat_identity
        if require_heartbeat_proof is None
        else require_heartbeat_proof
    )
    if (
        effective_require_heartbeat_identity or effective_require_heartbeat_proof
    ) and heartbeat_identity_verifier is None:
        raise ValueError(
            "heartbeat identity verification requires heartbeat_identity_verifier"
        )
    if heartbeat_trust_xfcc and not heartbeat_trusted_proxy_hosts:
        raise ValueError(
            "heartbeat_trusted_proxy_hosts is required when heartbeat_trust_xfcc is enabled"
        )
    if (
        require_heartbeat_mtls or heartbeat_trust_xfcc
    ) and not heartbeat_mtls_trust_domains:
        raise ValueError(
            "heartbeat_mtls_trust_domains is required when heartbeat mTLS is enabled"
        )
    app = FastAPI(title="Tessera Control Plane")
    control_state = state or ControlPlaneState()
    proof_verifier = (
        AgentProofVerifier(
            max_age=heartbeat_proof_max_age,
            replay_cache=AgentProofReplayCache(),
        )
        if heartbeat_identity_verifier is not None
        else None
    )

    def _authorize(authorization: str | None = Header(default=None)) -> None:
        if allow_unauthenticated:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(token, bearer_token or ""):
            raise HTTPException(
                status_code=401,
                detail="invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def _if_match_required(if_match: str | None, revision: str) -> None:
        if if_match is None:
            raise HTTPException(status_code=428, detail="If-Match is required")
        if if_match != _etag(revision):
            raise HTTPException(status_code=412, detail="stale revision")

    def _maybe_not_modified(if_none_match: str | None, revision: str) -> Response | None:
        if if_none_match == _etag(revision):
            return Response(status_code=304, headers={"ETag": _etag(revision)})
        return None

    def _signed_response(
        document_type: str,
        *,
        revision: str | None = None,
        if_none_match: str | None = None,
    ) -> Response:
        if distribution_signer is None:
            raise HTTPException(
                status_code=503,
                detail="signed distribution is not configured",
            )
        document = control_state.document_at_revision(
            document_type,
            revision or control_state._document(document_type)["revision"],
        )
        cached = _maybe_not_modified(if_none_match, document["revision"])
        if cached is not None:
            return cached
        signed = control_state.signed_document(
            document_type,
            distribution_signer,
            revision=document["revision"],
        )
        return Response(
            content=json.dumps(signed.to_dict(), separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(document["revision"])},
            )

    def _transport_agent_identity(request: Request) -> AgentIdentity | None:
        try:
            peer_identity = extract_peer_identity(
                scope=request.scope,
                headers=request.headers,
                trusted_proxy_hosts=heartbeat_trusted_proxy_hosts,
                trust_xfcc=heartbeat_trust_xfcc,
                allowed_trust_domains=heartbeat_mtls_trust_domains,
            )
        except MTLSPeerVerificationError as exc:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=None,
                    detail={"error": str(exc)},
                )
            )
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if peer_identity is None:
            if not require_heartbeat_mtls:
                return None
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=None,
                    detail={"error": "missing required transport client certificate identity"},
                )
            )
            raise HTTPException(
                status_code=401,
                detail="missing required transport client certificate identity",
            )
        return AgentIdentity(
            agent_id=peer_identity.agent_id,
            trust_domain=peer_identity.trust_domain,
            issuer=None,
            audience=(),
            valid_from=None,
            valid_until=_utc_now() + heartbeat_proof_max_age,
            claims={"transport_source": peer_identity.source},
        )

    def _verify_heartbeat_identity(
        request: Request,
        *,
        identity_header: str | None,
        proof_header: str | None,
    ) -> AgentIdentity | None:
        transport_identity = _transport_agent_identity(request)
        if identity_header is None and proof_header is None:
            if transport_identity is not None:
                return transport_identity
            if not effective_require_heartbeat_identity:
                return None
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=None,
                    detail={"error": "missing required heartbeat agent identity"},
                )
            )
            raise HTTPException(status_code=401, detail="missing required heartbeat agent identity")
        if identity_header is None and proof_header is not None:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.PROOF_VERIFY_FAILURE,
                    principal=None,
                    detail={"error": "heartbeat agent proof provided without agent identity"},
                )
            )
            raise HTTPException(status_code=401, detail="heartbeat agent proof requires agent identity")
        verifier = heartbeat_identity_verifier
        if verifier is None:
            error = (
                "heartbeat agent proof header provided but no verifier configured"
                if proof_header is not None
                else "heartbeat agent identity header provided but no verifier configured"
            )
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=None,
                    detail={"error": error},
                )
            )
            raise HTTPException(status_code=400, detail=error)
        identity = verifier.verify(identity_header, audience=heartbeat_identity_audience)
        if identity is None:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=None,
                    detail={"audience": heartbeat_identity_audience},
                )
            )
            raise HTTPException(status_code=401, detail="invalid heartbeat agent identity")
        if effective_require_heartbeat_proof or proof_header is not None:
            if proof_verifier is None:
                raise HTTPException(
                    status_code=400,
                    detail="heartbeat agent proof verifier is not configured",
                )
            if proof_header is None:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.PROOF_VERIFY_FAILURE,
                        principal=identity.agent_id,
                        detail={"error": "missing required heartbeat agent proof"},
                    )
                )
                raise HTTPException(
                    status_code=401,
                    detail="missing required heartbeat agent proof",
                )
            if identity.key_binding is None:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.PROOF_VERIFY_FAILURE,
                        principal=identity.agent_id,
                        detail={"error": "heartbeat identity token is missing proof-of-possession binding"},
                    )
                )
                raise HTTPException(
                    status_code=401,
                    detail="heartbeat identity token is missing proof-of-possession binding",
                )
            if not proof_verifier.verify(
                proof_header,
                identity_token=identity_header,
                expected_method=request.method,
                expected_url=str(request.url),
                expected_key_binding=identity.key_binding,
            ):
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.PROOF_VERIFY_FAILURE,
                        principal=identity.agent_id,
                        detail={"method": request.method, "url": str(request.url)},
                    )
                )
                raise HTTPException(
                    status_code=401,
                    detail="invalid heartbeat agent proof",
                )
        if (
            transport_identity is not None
            and transport_identity.agent_id != identity.agent_id
        ):
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=identity.agent_id,
                    detail={
                        "error": "transport identity does not match heartbeat agent identity",
                        "transport_agent_id": transport_identity.agent_id,
                        "identity_agent_id": identity.agent_id,
                    },
                )
            )
            raise HTTPException(
                status_code=401,
                detail="transport identity does not match heartbeat agent identity",
            )
        return identity

    @app.get("/.well-known/tessera-control.json")
    def discovery(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _authorize(authorization)
        return {
            "version": "0.1.0",
            "status_path": "/v1/control/status",
            "revisions_path": "/v1/control/revisions",
            "policy_path": "/v1/control/policy",
            "policy_signed_path": "/v1/control/policy/signed",
            "registry_path": "/v1/control/registry",
            "registry_signed_path": "/v1/control/registry/signed",
            "agents_path": "/v1/control/agents",
            "heartbeat_path": "/v1/control/agents/heartbeat",
            "signed_distribution": distribution_signer is not None,
            "heartbeat_auth": {
                "operator_bearer_fallback": (
                    heartbeat_identity_verifier is None and not require_heartbeat_mtls
                ),
                "workload_identity": (
                    heartbeat_identity_verifier is not None or require_heartbeat_mtls
                ),
                "required": effective_require_heartbeat_identity,
                "audience": (
                    heartbeat_identity_audience
                    if heartbeat_identity_verifier is not None
                    else None
                ),
                "proof_of_possession": effective_require_heartbeat_proof,
                "mtls": {
                    "required": require_heartbeat_mtls,
                    "trust_xfcc": heartbeat_trust_xfcc,
                    "trust_domains": list(heartbeat_mtls_trust_domains),
                },
            },
        }

    @app.get("/v1/control/status")
    def status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _authorize(authorization)
        return control_state.status()

    @app.get("/v1/control/revisions")
    def revisions(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _authorize(authorization)
        return control_state.revisions()

    @app.get("/v1/control/revisions/signed")
    def signed_revisions(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    ) -> Response:
        _authorize(authorization)
        revision = hashlib.sha256(
            _canonical_json(control_state.revisions())
        ).hexdigest()[:16]
        cached = _maybe_not_modified(if_none_match, f"rev-{revision}")
        if cached is not None:
            return cached
        if distribution_signer is None:
            raise HTTPException(
                status_code=503,
                detail="signed distribution is not configured",
            )
        signed = distribution_signer.sign("revisions", control_state.revisions())
        return Response(
            content=json.dumps(signed.to_dict(), separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(f"rev-{revision}")},
        )

    @app.get("/v1/control/policy")
    def get_policy(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        revision: str | None = None,
    ) -> Response:
        _authorize(authorization)
        document = control_state.policy_document(revision)
        cached = _maybe_not_modified(if_none_match, document["revision"])
        if cached is not None:
            return cached
        return Response(
            content=json.dumps(document, separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(document["revision"])},
        )

    @app.put("/v1/control/policy")
    def put_policy(
        payload: PolicyDistributionInput,
        authorization: str | None = Header(default=None),
        if_match: str | None = Header(default=None, alias="If-Match"),
    ) -> Response:
        _authorize(authorization)
        _if_match_required(if_match, control_state.policy_document()["revision"])
        document = control_state.update_policy(payload)
        return Response(
            content=json.dumps(document, separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(document["revision"])},
        )

    @app.get("/v1/control/policy/signed")
    def get_signed_policy(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        revision: str | None = None,
    ) -> Response:
        _authorize(authorization)
        return _signed_response("policy", revision=revision, if_none_match=if_none_match)

    @app.get("/v1/control/policy/history")
    def policy_history(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _authorize(authorization)
        return control_state.policy_history()

    @app.get("/v1/control/registry")
    def get_registry(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        revision: str | None = None,
    ) -> Response:
        _authorize(authorization)
        document = control_state.registry_document(revision)
        cached = _maybe_not_modified(if_none_match, document["revision"])
        if cached is not None:
            return cached
        return Response(
            content=json.dumps(document, separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(document["revision"])},
        )

    @app.put("/v1/control/registry")
    def put_registry(
        payload: RegistryDistributionInput,
        authorization: str | None = Header(default=None),
        if_match: str | None = Header(default=None, alias="If-Match"),
    ) -> Response:
        _authorize(authorization)
        _if_match_required(if_match, control_state.registry_document()["revision"])
        document = control_state.update_registry(payload)
        return Response(
            content=json.dumps(document, separators=(",", ":"), sort_keys=True),
            media_type="application/json",
            headers={"ETag": _etag(document["revision"])},
        )

    @app.get("/v1/control/registry/signed")
    def get_signed_registry(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        revision: str | None = None,
    ) -> Response:
        _authorize(authorization)
        return _signed_response("registry", revision=revision, if_none_match=if_none_match)

    @app.get("/v1/control/registry/history")
    def registry_history(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _authorize(authorization)
        return control_state.registry_history()

    @app.post("/v1/control/agents/heartbeat")
    def heartbeat(
        payload: AgentHeartbeat,
        request: Request,
        asm_agent_identity: str | None = Header(default=None, alias="ASM-Agent-Identity"),
        asm_agent_proof: str | None = Header(default=None, alias="ASM-Agent-Proof"),
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        identity = _verify_heartbeat_identity(
            request,
            identity_header=asm_agent_identity,
            proof_header=asm_agent_proof,
        )
        if identity is None:
            _authorize(authorization)
            return control_state.record_heartbeat(payload)
        if payload.agent_id != identity.agent_id:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.IDENTITY_VERIFY_FAILURE,
                    principal=identity.agent_id,
                    detail={
                        "error": "heartbeat payload agent_id does not match verified identity",
                        "payload_agent_id": payload.agent_id,
                        "verified_agent_id": identity.agent_id,
                    },
                )
            )
            raise HTTPException(
                status_code=401,
                detail="heartbeat payload agent_id does not match verified identity",
            )
        return control_state.record_heartbeat(payload)

    @app.get("/v1/control/agents")
    def agents(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        _authorize(authorization)
        return control_state.list_agents()

    return app
