"""Tests for extension hook dispatcher and remote hook client."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from tessera.hooks.client import RemoteHookClient
from tessera.hooks.dispatcher import HookDispatcher
from tessera.labels import TrustLevel
from tessera.policy import Decision, DecisionKind


def _allow_decision(tool: str = "send_email") -> Decision:
    return Decision(
        kind=DecisionKind.ALLOW,
        reason="trust met",
        tool=tool,
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.USER,
    )


def _deny_decision(tool: str = "send_email") -> Decision:
    return Decision(
        kind=DecisionKind.DENY,
        reason="trust too low",
        tool=tool,
        required_trust=TrustLevel.USER,
        observed_trust=TrustLevel.UNTRUSTED,
    )


# -- HookDispatcher: policy hooks --------------------------------------------


def test_dispatcher_runs_policy_hooks() -> None:
    dispatcher = HookDispatcher()
    called: list[str] = []

    def hook(tool: str, principal: str, decision: Decision) -> Decision | None:
        called.append(tool)
        return None

    dispatcher.register_policy_hook(hook)
    result = dispatcher.dispatch_policy("send_email", "user@test", _allow_decision())
    assert result.kind == DecisionKind.ALLOW
    assert called == ["send_email"]


def test_policy_hook_deny_overrides_allow() -> None:
    dispatcher = HookDispatcher()

    def deny_hook(tool: str, principal: str, decision: Decision) -> Decision | None:
        return Decision(
            kind=DecisionKind.DENY,
            reason="blocked by hook",
            tool=tool,
            required_trust=decision.required_trust,
            observed_trust=decision.observed_trust,
        )

    dispatcher.register_policy_hook(deny_hook)
    result = dispatcher.dispatch_policy("send_email", "user@test", _allow_decision())
    assert result.kind == DecisionKind.DENY
    assert result.reason == "blocked by hook"


def test_policy_hook_cannot_override_deny_to_allow() -> None:
    dispatcher = HookDispatcher()

    def upgrade_hook(tool: str, principal: str, decision: Decision) -> Decision | None:
        return Decision(
            kind=DecisionKind.ALLOW,
            reason="hook tried to allow",
            tool=tool,
            required_trust=decision.required_trust,
            observed_trust=decision.observed_trust,
        )

    dispatcher.register_policy_hook(upgrade_hook)
    result = dispatcher.dispatch_policy("send_email", "user@test", _deny_decision())
    # The original DENY must survive because hooks are deny-only.
    assert result.kind == DecisionKind.DENY
    assert result.reason == "trust too low"


def test_policy_hook_error_fails_closed() -> None:
    dispatcher = HookDispatcher()

    def broken_hook(tool: str, principal: str, decision: Decision) -> Decision | None:
        raise RuntimeError("boom")

    dispatcher.register_policy_hook(broken_hook)
    result = dispatcher.dispatch_policy("send_email", "user@test", _allow_decision())
    assert result.kind == DecisionKind.DENY
    assert "failing closed" in result.reason


# -- HookDispatcher: tool call hooks -----------------------------------------


def test_tool_call_hook_allows_on_true() -> None:
    dispatcher = HookDispatcher()

    def allow_hook(tool: str, args: dict[str, Any], principal: str) -> bool:
        return True

    dispatcher.register_tool_call_hook(allow_hook)
    assert dispatcher.dispatch_tool_call("calc", {"x": 1}, "user@test") is True


def test_tool_call_hook_blocks_on_false() -> None:
    dispatcher = HookDispatcher()

    def block_hook(tool: str, args: dict[str, Any], principal: str) -> bool:
        return False

    dispatcher.register_tool_call_hook(block_hook)
    assert dispatcher.dispatch_tool_call("calc", {"x": 1}, "user@test") is False


def test_tool_call_hook_error_fails_closed() -> None:
    dispatcher = HookDispatcher()

    def broken_hook(tool: str, args: dict[str, Any], principal: str) -> bool:
        raise RuntimeError("boom")

    dispatcher.register_tool_call_hook(broken_hook)
    assert dispatcher.dispatch_tool_call("calc", {}, "user@test") is False


# -- RemoteHookClient --------------------------------------------------------


def test_remote_hook_client_posts_to_url() -> None:
    decision = _allow_decision()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"decision_kind": None}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=mock_response) as mock_post:
        client = RemoteHookClient("http://hooks.test/evaluate")
        result = client.post_policy_evaluate("send_email", "user@test", decision)

    assert result is None
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert call_kwargs[1]["json"]["tool"] == "send_email"
    assert call_kwargs[1]["json"]["principal"] == "user@test"
    assert call_kwargs[1]["json"]["decision_kind"] == "allow"


def test_remote_hook_client_deny_override() -> None:
    decision = _allow_decision()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "decision_kind": "deny",
        "reason": "remote says no",
    }
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=mock_response):
        client = RemoteHookClient("http://hooks.test/evaluate")
        result = client.post_policy_evaluate("send_email", "user@test", decision)

    assert result is not None
    assert result.kind == DecisionKind.DENY
    assert result.reason == "remote says no"


def test_remote_hook_client_fails_closed_on_timeout() -> None:
    decision = _allow_decision()

    with patch("httpx.post", side_effect=httpx.TimeoutException("timed out")):
        client = RemoteHookClient("http://hooks.test/evaluate", timeout=1.0)
        result = client.post_policy_evaluate("send_email", "user@test", decision)

    assert result is not None
    assert result.kind == DecisionKind.DENY
    assert "failing closed" in result.reason


def test_remote_hook_client_fails_closed_on_network_error() -> None:
    decision = _allow_decision()

    with patch("httpx.post", side_effect=httpx.ConnectError("connection refused")):
        client = RemoteHookClient("http://hooks.test/evaluate", timeout=1.0)
        result = client.post_policy_evaluate("send_email", "user@test", decision)

    assert result is not None
    assert result.kind == DecisionKind.DENY
    assert "failing closed" in result.reason


def test_remote_hook_client_callable_protocol() -> None:
    """RemoteHookClient is directly registerable as a policy hook."""
    decision = _allow_decision()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"decision_kind": None}
    mock_response.raise_for_status = MagicMock()

    with patch("httpx.post", return_value=mock_response):
        client = RemoteHookClient("http://hooks.test/evaluate")
        dispatcher = HookDispatcher()
        dispatcher.register_policy_hook(client)
        result = dispatcher.dispatch_policy("send_email", "user@test", decision)

    assert result.kind == DecisionKind.ALLOW
