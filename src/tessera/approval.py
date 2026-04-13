"""Human-in-the-loop approval for tool calls.

When Policy.evaluate returns REQUIRE_APPROVAL, the caller can use an
ApprovalGate to suspend the decision and request human approval via
webhook. The gate calls the configured URL with the decision details
and waits for an allow/deny response.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.policy import Decision, DecisionKind


@dataclass(frozen=True)
class ApprovalRequest:
    """Payload sent to the approval webhook."""

    tool: str
    principal: str
    reason: str
    context_summary: str

    def to_dict(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "principal": self.principal,
            "reason": self.reason,
            "context_summary": self.context_summary,
        }


@dataclass(frozen=True)
class ApprovalResponse:
    """Response from the approval webhook."""

    approved: bool
    approver: str
    reason: str


def _emit_required(decision: Decision, principal: str, url: str) -> None:
    emit_event(
        SecurityEvent.now(
            kind=EventKind.HUMAN_APPROVAL_REQUIRED,
            principal=principal,
            detail={
                "tool": decision.tool,
                "reason": decision.reason,
                "webhook_url": url,
            },
        )
    )


def _fail_closed(
    decision: Decision, principal: str, exc: Exception,
) -> Decision:
    emit_event(
        SecurityEvent.now(
            kind=EventKind.HUMAN_APPROVAL_RESOLVED,
            principal=principal,
            detail={
                "tool": decision.tool,
                "approved": False,
                "approver": "system",
                "reason": f"approval webhook failed: {exc}",
            },
        )
    )
    return Decision(
        kind=DecisionKind.DENY,
        reason=f"approval webhook failed: {exc}",
        tool=decision.tool,
        required_trust=decision.required_trust,
        observed_trust=decision.observed_trust,
    )


def _resolve(
    decision: Decision, body: dict[str, Any], principal: str,
) -> Decision:
    approved = bool(body.get("approved", False))
    approver = str(body.get("approver", "unknown"))
    reason = str(body.get("reason", ""))

    resolved_kind = DecisionKind.ALLOW if approved else DecisionKind.DENY
    resolved_reason = (
        f"approved by {approver}: {reason}" if approved
        else f"denied by {approver}: {reason}"
    )

    emit_event(
        SecurityEvent.now(
            kind=EventKind.HUMAN_APPROVAL_RESOLVED,
            principal=principal,
            detail={
                "tool": decision.tool,
                "approved": approved,
                "approver": approver,
                "reason": reason,
            },
        )
    )

    return Decision(
        kind=resolved_kind,
        reason=resolved_reason,
        tool=decision.tool,
        required_trust=decision.required_trust,
        observed_trust=decision.observed_trust,
    )


class ApprovalGate:
    """Synchronous webhook-based approval gate.

    Sends an ApprovalRequest to the configured URL and interprets the
    JSON response as an ApprovalResponse. Returns a final ALLOW or DENY
    Decision based on the human's response.
    """

    def __init__(
        self,
        webhook_url: str,
        timeout: float = 300.0,
        transport: Any = None,
    ) -> None:
        self._url = webhook_url
        self._timeout = timeout
        self._transport = transport

    def request_approval(
        self, decision: Decision, principal: str, context_summary: str,
    ) -> Decision:
        """Send the approval request and return the resolved decision.

        Emits HUMAN_APPROVAL_REQUIRED before the webhook call and
        HUMAN_APPROVAL_RESOLVED after.
        """
        req = ApprovalRequest(
            tool=decision.tool,
            principal=principal,
            reason=decision.reason,
            context_summary=context_summary,
        )

        _emit_required(decision, principal, self._url)

        client_kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        try:
            with httpx.Client(**client_kwargs) as client:
                resp = client.post(self._url, json=req.to_dict())
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            return _fail_closed(decision, principal, exc)

        return _resolve(decision, body, principal)


class AsyncApprovalGate:
    """Async webhook-based approval gate for the async proxy path."""

    def __init__(
        self,
        webhook_url: str,
        timeout: float = 300.0,
        transport: Any = None,
    ) -> None:
        self._url = webhook_url
        self._timeout = timeout
        self._transport = transport

    async def request_approval(
        self, decision: Decision, principal: str, context_summary: str,
    ) -> Decision:
        """Async version of ApprovalGate.request_approval."""
        req = ApprovalRequest(
            tool=decision.tool,
            principal=principal,
            reason=decision.reason,
            context_summary=context_summary,
        )

        _emit_required(decision, principal, self._url)

        client_kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(self._url, json=req.to_dict())
                resp.raise_for_status()
                body = resp.json()
        except Exception as exc:
            return _fail_closed(decision, principal, exc)

        return _resolve(decision, body, principal)
