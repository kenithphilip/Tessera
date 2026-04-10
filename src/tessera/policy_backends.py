"""Portable external policy backends for Tessera.

The local taint floor remains authoritative. External policy backends are
deny-only refinements that can add attribute-based denies after the local
trust and delegation checks have already passed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Any, Callable, Protocol
from uuid import uuid4

import httpx

from tessera.context import Context
from tessera.delegation import DelegationToken
from tessera.labels import TrustLevel


class PolicyBackendError(RuntimeError):
    """Raised when an external policy backend cannot be evaluated."""


@dataclass(frozen=True)
class PolicySegmentSummary:
    """Compact, privacy-preserving metadata for one context segment."""

    index: int
    origin: str
    principal: str
    trust_level: TrustLevel
    content_sha256: str
    content_length: int

    @classmethod
    def from_context(cls, context: Context) -> tuple["PolicySegmentSummary", ...]:
        return tuple(
            cls(
                index=index,
                origin=str(segment.label.origin),
                principal=segment.label.principal,
                trust_level=segment.label.trust_level,
                content_sha256=sha256(segment.content.encode("utf-8")).hexdigest(),
                content_length=len(segment.content),
            )
            for index, segment in enumerate(context.segments)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "origin": self.origin,
            "principal": self.principal,
            "trust_level": int(self.trust_level),
            "content_sha256": self.content_sha256,
            "content_length": self.content_length,
        }


@dataclass(frozen=True)
class PolicyDelegationSummary:
    """Serializable summary of a delegation token for backend policy."""

    subject: str
    delegate: str
    audience: str
    authorized_actions: tuple[str, ...]
    constraints: dict[str, Any]
    session_id: str
    expires_at: str

    @classmethod
    def from_token(cls, token: DelegationToken) -> "PolicyDelegationSummary":
        return cls(
            subject=token.subject,
            delegate=token.delegate,
            audience=token.audience,
            authorized_actions=tuple(token.authorized_actions),
            constraints=token.constraints,
            session_id=token.session_id,
            expires_at=token.expires_at.isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "delegate": self.delegate,
            "audience": self.audience,
            "authorized_actions": list(self.authorized_actions),
            "constraints": self.constraints,
            "session_id": self.session_id,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class PolicyInput:
    """Normalized policy input for external authorization backends."""

    tool: str
    args: dict[str, Any] | None
    principal: str | None
    required_trust: TrustLevel
    observed_trust: TrustLevel
    min_trust_passed: bool
    default_required_trust: TrustLevel
    base_required_trust: TrustLevel
    request_required_trust: TrustLevel | None
    expected_delegate: str | None
    origin_counts: dict[str, int]
    segment_summary: tuple[PolicySegmentSummary, ...]
    delegation: PolicyDelegationSummary | None

    @classmethod
    def from_evaluation(
        cls,
        *,
        context: Context,
        tool: str,
        args: dict[str, Any] | None,
        required_trust: TrustLevel,
        observed_trust: TrustLevel,
        default_required_trust: TrustLevel,
        base_required_trust: TrustLevel,
        request_required_trust: TrustLevel | None,
        delegation: DelegationToken | None,
        expected_delegate: str | None,
    ) -> "PolicyInput":
        segment_summary = PolicySegmentSummary.from_context(context)
        origin_counts = Counter(segment.origin for segment in segment_summary)
        return cls(
            tool=tool,
            args=args,
            principal=context.principal,
            required_trust=required_trust,
            observed_trust=observed_trust,
            min_trust_passed=observed_trust >= required_trust,
            default_required_trust=default_required_trust,
            base_required_trust=base_required_trust,
            request_required_trust=request_required_trust,
            expected_delegate=expected_delegate,
            origin_counts=dict(origin_counts),
            segment_summary=segment_summary,
            delegation=(
                None
                if delegation is None
                else PolicyDelegationSummary.from_token(delegation)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "principal": self.principal,
            "required_trust": int(self.required_trust),
            "observed_trust": int(self.observed_trust),
            "min_trust_passed": self.min_trust_passed,
            "default_required_trust": int(self.default_required_trust),
            "base_required_trust": int(self.base_required_trust),
            "request_required_trust": (
                None
                if self.request_required_trust is None
                else int(self.request_required_trust)
            ),
            "expected_delegate": self.expected_delegate,
            "origin_counts": self.origin_counts,
            "segment_summary": [
                segment.to_dict() for segment in self.segment_summary
            ],
            "delegation": (
                None if self.delegation is None else self.delegation.to_dict()
            ),
        }


@dataclass(frozen=True)
class PolicyBackendDecision:
    """Decision returned by an external backend."""

    allow: bool
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyBackend(Protocol):
    """Deny-only external policy backend."""

    name: str

    def evaluate(self, policy_input: PolicyInput) -> PolicyBackendDecision:
        """Return whether the already-local-allowed request stays allowed."""


@dataclass(frozen=True)
class OPAStatus:
    """Summarized OPA runtime status for audit and control-plane correlation."""

    version: str | None
    build_commit: str | None
    bundle_revisions: dict[str, str]
    plugin_states: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "build_commit": self.build_commit,
            "bundle_revisions": self.bundle_revisions,
            "plugin_states": self.plugin_states,
        }


def _default_decision_id() -> str:
    return uuid4().hex


@dataclass
class OPAPolicyBackend:
    """OPA Data API adapter for external deny-only policy checks."""

    base_url: str
    decision_path: str = "/v1/data/tessera/authz/allow"
    status_path: str = "/v1/status"
    timeout: float = 5.0
    bearer_token: str | None = None
    include_provenance: bool = True
    decision_id_factory: Callable[[], str] | None = _default_decision_id
    client_factory: Any = httpx.Client

    name: str = "opa"

    def evaluate(self, policy_input: PolicyInput) -> PolicyBackendDecision:
        url = self._decision_url()
        headers = self._headers()
        params: dict[str, Any] = {}
        issued_decision_id = (
            None if self.decision_id_factory is None else self.decision_id_factory()
        )
        if issued_decision_id is not None:
            params["decision_id"] = issued_decision_id
        if self.include_provenance:
            params["provenance"] = "true"
        try:
            with self.client_factory(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    headers=headers,
                    params=params,
                    json={"input": policy_input.to_dict()},
                )
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001 - normalize external failures
            raise PolicyBackendError(f"OPA query failed: {exc}") from exc

        decision = _parse_opa_response(payload)
        metadata = dict(decision.metadata)
        if issued_decision_id is not None and "decision_id" not in metadata:
            metadata["decision_id"] = issued_decision_id
        provenance = payload.get("provenance")
        if isinstance(provenance, dict):
            metadata["opa_provenance"] = provenance
            bundles = provenance.get("bundles")
            if isinstance(bundles, dict):
                metadata["opa_bundle_revisions"] = {
                    str(name): str(bundle.get("revision"))
                    for name, bundle in bundles.items()
                    if isinstance(bundle, dict) and bundle.get("revision") is not None
                }
        return replace(decision, metadata=metadata)

    def status(self) -> OPAStatus:
        url = self._status_url()
        try:
            with self.client_factory(timeout=self.timeout) as client:
                response = client.get(url, headers=self._headers())
                response.raise_for_status()
                payload = response.json()
        except Exception as exc:  # noqa: BLE001 - normalize external failures
            raise PolicyBackendError(f"OPA status query failed: {exc}") from exc
        return _parse_opa_status(payload)

    def _decision_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.decision_path.lstrip('/')}"

    def _status_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.status_path.lstrip('/')}"

    def _headers(self) -> dict[str, str]:
        return (
            {}
            if self.bearer_token is None
            else {"Authorization": f"Bearer {self.bearer_token}"}
        )


def _parse_opa_response(payload: dict[str, Any]) -> PolicyBackendDecision:
    result = payload.get("result")
    if isinstance(result, bool):
        return PolicyBackendDecision(
            allow=result,
            reason=None if result else "denied by OPA policy",
        )
    if result is None:
        return PolicyBackendDecision(
            allow=False,
            reason="OPA decision was undefined",
        )
    if not isinstance(result, dict):
        raise PolicyBackendError("OPA result must be a boolean or object")
    allow = result.get("allow")
    if not isinstance(allow, bool):
        raise PolicyBackendError("OPA object result must contain boolean 'allow'")
    reason = result.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise PolicyBackendError("OPA object result field 'reason' must be a string")
    metadata = result.get("metadata", {})
    if not isinstance(metadata, dict):
        raise PolicyBackendError("OPA object result field 'metadata' must be an object")
    if "decision_id" in payload and "decision_id" not in metadata:
        metadata = {**metadata, "decision_id": payload["decision_id"]}
    return PolicyBackendDecision(
        allow=allow,
        reason=reason if reason else None,
        metadata=metadata,
    )


def _parse_opa_status(payload: dict[str, Any]) -> OPAStatus:
    result = payload.get("result")
    if not isinstance(result, dict):
        raise PolicyBackendError("OPA status result must be an object")
    labels = result.get("labels", {})
    bundles = result.get("bundles", {})
    plugins = result.get("plugins", {})
    if not isinstance(labels, dict) or not isinstance(bundles, dict) or not isinstance(plugins, dict):
        raise PolicyBackendError("OPA status payload is malformed")
    return OPAStatus(
        version=None if labels.get("version") is None else str(labels["version"]),
        build_commit=(
            None if labels.get("build_commit") is None else str(labels["build_commit"])
        ),
        bundle_revisions={
            str(name): str(bundle.get("active_revision"))
            for name, bundle in bundles.items()
            if isinstance(bundle, dict) and bundle.get("active_revision") is not None
        },
        plugin_states={
            str(name): str(plugin.get("state"))
            for name, plugin in plugins.items()
            if isinstance(plugin, dict) and plugin.get("state") is not None
        },
    )
