"""Encrypted in-memory session store for pending approvals.

When a tool call requires human approval, the proxy stores the
pending decision in a session. The approval webhook response resolves
the session. Expired sessions auto-resolve as DENY (fail closed).

Sessions are encrypted at rest using Fernet symmetric encryption when
an encryption key is provided. Without a key, sessions are stored in
plaintext (suitable for development but not production).
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from tessera.policy import Decision, DecisionKind
from tessera.events import EventKind, SecurityEvent, emit as emit_event


@dataclass
class PendingApproval:
    """One suspended tool-call decision awaiting human review."""

    session_id: str
    tool: str
    principal: str
    decision: Decision
    context_summary: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tool": self.tool,
            "principal": self.principal,
            "decision": {
                "kind": str(self.decision.kind),
                "reason": self.decision.reason,
                "tool": self.decision.tool,
                "required_trust": int(self.decision.required_trust),
                "observed_trust": int(self.decision.observed_trust),
            },
            "context_summary": self.context_summary,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingApproval:
        """Reconstruct from serialized dict."""
        from tessera.labels import TrustLevel

        d = data["decision"]
        decision = Decision(
            kind=DecisionKind(d["kind"]),
            reason=d["reason"],
            tool=d["tool"],
            required_trust=TrustLevel(d["required_trust"]),
            observed_trust=TrustLevel(d["observed_trust"]),
        )
        return cls(
            session_id=data["session_id"],
            tool=data["tool"],
            principal=data["principal"],
            decision=decision,
            context_summary=data["context_summary"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


class SessionStore:
    """Thread-safe session store with optional Fernet encryption."""

    def __init__(
        self,
        ttl: timedelta = timedelta(minutes=5),
        encryption_key: bytes | None = None,
    ) -> None:
        self._ttl = ttl
        self._lock = Lock()
        self._sessions: dict[str, bytes | str] = {}
        self._fernet: Any = None
        if encryption_key is not None:
            try:
                from cryptography.fernet import Fernet
                import base64

                # Fernet requires a 32-byte key, base64url-encoded.
                raw = encryption_key[:32].ljust(32, b"\0")
                key = base64.urlsafe_b64encode(raw)
                self._fernet = Fernet(key)
            except ImportError:
                pass

    def _serialize(self, approval: PendingApproval) -> bytes | str:
        payload = json.dumps(approval.to_dict())
        if self._fernet is not None:
            return self._fernet.encrypt(payload.encode("utf-8"))
        return payload

    def _deserialize(self, raw: bytes | str) -> PendingApproval:
        if self._fernet is not None:
            payload = self._fernet.decrypt(raw).decode("utf-8")  # type: ignore[arg-type]
        else:
            payload = raw  # type: ignore[assignment]
        return PendingApproval.from_dict(json.loads(payload))

    def store(self, approval: PendingApproval) -> str:
        """Store a pending approval. Returns the session_id."""
        with self._lock:
            self._sessions[approval.session_id] = self._serialize(approval)
        return approval.session_id

    def retrieve(
        self,
        session_id: str,
        scan_on_load: bool = False,
        scan_threshold: float = 0.75,
    ) -> PendingApproval | None:
        """Retrieve and return None if not found, expired, or tainted.

        Args:
            session_id: Session to look up.
            scan_on_load: If True, re-scan the stored context_summary
                for injection before returning. Catches cross-session
                memory poisoning where an attacker plants content in a
                previous session.
            scan_threshold: Heuristic injection score above which the
                session is rejected. Only used when scan_on_load is True.

        Returns:
            PendingApproval if valid, None if not found, expired, or
            injection was detected in the stored context.
        """
        with self._lock:
            raw = self._sessions.get(session_id)
        if raw is None:
            return None
        approval = self._deserialize(raw)
        if approval.is_expired():
            return None

        # Re-scan stored context for injection on retrieve.
        # Catches memory poisoning: content planted in session N
        # that gets loaded into session N+1.
        if scan_on_load and approval.context_summary:
            try:
                from tessera.scanners.heuristic import injection_score
                from tessera.scanners.directive import directive_score

                h_score = injection_score(approval.context_summary)
                d_score = directive_score(approval.context_summary)
                # Either scanner triggering is sufficient. The directive
                # scanner catches output manipulation, the heuristic
                # catches override patterns. Both use their own thresholds
                # to control false positives.
                if h_score >= scan_threshold or d_score >= scan_threshold:
                    emit_event(
                        SecurityEvent.now(
                            kind=EventKind.CONTENT_INJECTION_DETECTED,
                            principal=approval.principal,
                            detail={
                                "scanner": "session_rescan",
                                "session_id": session_id,
                                "heuristic_score": h_score,
                                "directive_score": d_score,
                                "threshold": scan_threshold,
                            },
                        )
                    )
                    return None  # fail closed
            except ImportError:
                pass  # scanners not available, skip re-scan

        return approval

    def resolve(
        self,
        session_id: str,
        approved: bool,
        approver: str,
        reason: str = "",
    ) -> Decision:
        """Resolve a pending approval and return the final decision.

        Removes the session from the store. If the session is expired
        or not found, returns DENY (fail closed).
        """
        with self._lock:
            raw = self._sessions.pop(session_id, None)
        if raw is None:
            return _deny_decision("session not found")

        approval = self._deserialize(raw)
        if approval.is_expired():
            return _deny_decision("session expired")

        resolved_kind = DecisionKind.ALLOW if approved else DecisionKind.DENY
        resolved_reason = (
            f"approved by {approver}: {reason}" if approved
            else f"denied by {approver}: {reason}"
        )
        return Decision(
            kind=resolved_kind,
            reason=resolved_reason,
            tool=approval.tool,
            required_trust=approval.decision.required_trust,
            observed_trust=approval.decision.observed_trust,
        )

    def expire_stale(self) -> int:
        """Remove all expired sessions. Returns the count removed."""
        now = datetime.now(timezone.utc)
        expired_ids: list[str] = []
        with self._lock:
            for sid, raw in list(self._sessions.items()):
                approval = self._deserialize(raw)
                if now >= approval.expires_at:
                    expired_ids.append(sid)
            for sid in expired_ids:
                del self._sessions[sid]

        for sid in expired_ids:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.SESSION_EXPIRED,
                    principal="system",
                    detail={"session_id": sid},
                )
            )
        return len(expired_ids)

    def __len__(self) -> int:
        """Number of active sessions."""
        with self._lock:
            return len(self._sessions)


def make_session_id() -> str:
    """Generate a cryptographically random session identifier."""
    return secrets.token_urlsafe(32)


def _deny_decision(reason: str) -> Decision:
    from tessera.labels import TrustLevel

    return Decision(
        kind=DecisionKind.DENY,
        reason=reason,
        tool="unknown",
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.UNTRUSTED,
    )
