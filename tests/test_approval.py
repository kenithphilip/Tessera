"""Human-in-the-loop approval gate tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tessera.approval import ApprovalGate, AsyncApprovalGate
from tessera.context import Context, make_segment
from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)
from tessera.labels import Origin, TrustLevel
from tessera.policy import Decision, DecisionKind, Policy

KEY = b"test-hmac-key-do-not-use-in-prod"


@pytest.fixture(autouse=True)
def _reset_sinks():
    clear_sinks()
    yield
    clear_sinks()


def _ctx_with(*segments):
    ctx = Context()
    for s in segments:
        ctx.add(s)
    return ctx


def _mock_transport(response_json: dict[str, Any]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_json)
    return httpx.MockTransport(handler)


def _timeout_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("webhook timed out")
    return httpx.MockTransport(handler)


def _make_require_approval_decision(tool: str = "deploy") -> Decision:
    return Decision(
        kind=DecisionKind.REQUIRE_APPROVAL,
        reason="tool requires human approval",
        tool=tool,
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.USER,
    )


# -- DecisionKind --


def test_require_approval_decision_kind_exists():
    assert DecisionKind.REQUIRE_APPROVAL == "require_approval"


def test_decision_requires_approval_property():
    d = _make_require_approval_decision()
    assert d.requires_approval
    assert not d.allowed


# -- Policy --


def test_policy_returns_require_approval_for_marked_tool():
    ctx = _ctx_with(
        make_segment("do something", Origin.USER, "alice", KEY),
    )
    policy = Policy()
    policy.require("deploy", TrustLevel.USER)
    policy.requires_human_approval("deploy")
    decision = policy.evaluate(ctx, "deploy")
    assert decision.requires_approval
    assert decision.kind is DecisionKind.REQUIRE_APPROVAL
    assert not decision.allowed


def test_deny_takes_precedence_over_require_approval():
    """Tainted context should DENY even for approval-marked tools."""
    ctx = _ctx_with(
        make_segment("user instruction", Origin.USER, "alice", KEY),
        make_segment("injected content", Origin.WEB, "alice", KEY),
    )
    policy = Policy()
    policy.require("deploy", TrustLevel.USER)
    policy.requires_human_approval("deploy")
    decision = policy.evaluate(ctx, "deploy")
    assert not decision.allowed
    assert not decision.requires_approval
    assert decision.kind is DecisionKind.DENY


# -- ApprovalGate --


def test_approval_gate_sends_webhook_and_resolves_allow():
    transport = _mock_transport({
        "approved": True,
        "approver": "jane",
        "reason": "looks good",
    })
    gate = ApprovalGate(
        "https://approvals.example.com/hook", transport=transport,
    )
    decision = _make_require_approval_decision()
    resolved = gate.request_approval(decision, "alice", "1 segment, min_trust=100")
    assert resolved.allowed
    assert resolved.kind is DecisionKind.ALLOW
    assert "jane" in resolved.reason


def test_approval_gate_sends_webhook_and_resolves_deny():
    transport = _mock_transport({
        "approved": False,
        "approver": "bob",
        "reason": "too risky",
    })
    gate = ApprovalGate(
        "https://approvals.example.com/hook", transport=transport,
    )
    decision = _make_require_approval_decision()
    resolved = gate.request_approval(decision, "alice", "1 segment, min_trust=100")
    assert not resolved.allowed
    assert resolved.kind is DecisionKind.DENY
    assert "bob" in resolved.reason


def test_approval_gate_fails_closed_on_timeout():
    transport = _timeout_transport()
    gate = ApprovalGate(
        "https://approvals.example.com/hook", transport=transport,
    )
    decision = _make_require_approval_decision()
    resolved = gate.request_approval(decision, "alice", "1 segment, min_trust=100")
    assert not resolved.allowed
    assert resolved.kind is DecisionKind.DENY
    assert "failed" in resolved.reason.lower()


def test_approval_gate_emits_events():
    events: list[SecurityEvent] = []
    register_sink(events.append)

    transport = _mock_transport({
        "approved": True,
        "approver": "jane",
        "reason": "ok",
    })
    gate = ApprovalGate(
        "https://approvals.example.com/hook", transport=transport,
    )
    decision = _make_require_approval_decision()
    gate.request_approval(decision, "alice", "1 segment, min_trust=100")

    kinds = [e.kind for e in events]
    assert EventKind.HUMAN_APPROVAL_REQUIRED in kinds
    assert EventKind.HUMAN_APPROVAL_RESOLVED in kinds

    resolved_event = next(
        e for e in events if e.kind == EventKind.HUMAN_APPROVAL_RESOLVED
    )
    assert resolved_event.detail["approved"] is True
    assert resolved_event.detail["approver"] == "jane"


def test_approval_gate_emits_events_on_timeout():
    events: list[SecurityEvent] = []
    register_sink(events.append)

    transport = _timeout_transport()
    gate = ApprovalGate(
        "https://approvals.example.com/hook", transport=transport,
    )
    decision = _make_require_approval_decision()
    gate.request_approval(decision, "alice", "1 segment, min_trust=100")

    kinds = [e.kind for e in events]
    assert EventKind.HUMAN_APPROVAL_REQUIRED in kinds
    assert EventKind.HUMAN_APPROVAL_RESOLVED in kinds

    resolved_event = next(
        e for e in events if e.kind == EventKind.HUMAN_APPROVAL_RESOLVED
    )
    assert resolved_event.detail["approved"] is False


def test_policy_emits_human_approval_required_event():
    events: list[SecurityEvent] = []
    register_sink(events.append)

    ctx = _ctx_with(
        make_segment("do something", Origin.USER, "alice", KEY),
    )
    policy = Policy()
    policy.require("deploy", TrustLevel.USER)
    policy.requires_human_approval("deploy")
    policy.evaluate(ctx, "deploy")

    kinds = [e.kind for e in events]
    assert EventKind.HUMAN_APPROVAL_REQUIRED in kinds


# -- Proxy integration --


def test_proxy_with_approval_gate_resolves_pending():
    from fastapi.testclient import TestClient
    from tessera.proxy import create_app

    policy = Policy()
    policy.require("deploy", TrustLevel.USER)
    policy.requires_human_approval("deploy")

    class _MockAsyncGate(AsyncApprovalGate):
        async def request_approval(
            self, decision: Decision, principal: str, context_summary: str,
        ) -> Decision:
            return Decision(
                kind=DecisionKind.ALLOW,
                reason="approved by test-approver: auto-approved",
                tool=decision.tool,
                required_trust=decision.required_trust,
                observed_trust=decision.observed_trust,
            )

    gate = _MockAsyncGate("https://approvals.example.com/hook")

    async def _upstream(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": "stub",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {"function": {"name": "deploy", "arguments": "{}"}},
                        ],
                    }
                }
            ],
        }

    seg = make_segment("deploy to prod", Origin.USER, "alice", KEY)
    app = create_app(
        key=KEY, upstream=_upstream, policy=policy, approval_gate=gate,
    )
    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "test",
            "messages": [
                {
                    "role": "user",
                    "content": seg.content,
                    "label": {
                        "origin": str(seg.label.origin),
                        "principal": seg.label.principal,
                        "trust_level": int(seg.label.trust_level),
                        "nonce": seg.label.nonce,
                        "signature": seg.label.signature,
                    },
                }
            ],
            "tools": [{"name": "deploy", "required_trust": int(TrustLevel.USER)}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    tessera = body["tessera"]
    assert len(tessera["allowed"]) == 1
    assert len(tessera["pending_approval"]) == 1
    assert tessera["pending_approval"][0]["tool"] == "deploy"


def test_proxy_without_approval_gate_fails_closed():
    from fastapi.testclient import TestClient
    from tessera.proxy import create_app

    policy = Policy()
    policy.require("deploy", TrustLevel.USER)
    policy.requires_human_approval("deploy")

    async def _upstream(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": "stub",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {"function": {"name": "deploy", "arguments": "{}"}},
                        ],
                    }
                }
            ],
        }

    seg = make_segment("deploy to prod", Origin.USER, "alice", KEY)
    app = create_app(key=KEY, upstream=_upstream, policy=policy)
    client = TestClient(app)
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "test",
            "messages": [
                {
                    "role": "user",
                    "content": seg.content,
                    "label": {
                        "origin": str(seg.label.origin),
                        "principal": seg.label.principal,
                        "trust_level": int(seg.label.trust_level),
                        "nonce": seg.label.nonce,
                        "signature": seg.label.signature,
                    },
                }
            ],
            "tools": [{"name": "deploy", "required_trust": int(TrustLevel.USER)}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    tessera = body["tessera"]
    assert len(tessera["allowed"]) == 0
    assert len(tessera["denied"]) == 1
    assert "no approval gate" in tessera["denied"][0]["reason"]
