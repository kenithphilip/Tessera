"""Extension hook dispatcher for post-processing policy decisions.

Hooks are deny-only: they can downgrade ALLOW to DENY but cannot
upgrade DENY to ALLOW. This preserves the taint floor invariant.
A hook returning None leaves the decision unchanged.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol

from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.policy import Decision, DecisionKind


class PostPolicyEvaluateHook(Protocol):
    """Hook called after policy evaluation.

    Return a modified Decision to override (deny-only), or None
    to accept the original.
    """

    def __call__(
        self, tool: str, principal: str, decision: Decision
    ) -> Decision | None: ...


class PostToolCallGateHook(Protocol):
    """Hook called before a tool invocation is dispatched.

    Return False to block the call, True to allow it.
    """

    def __call__(
        self, tool: str, args: dict[str, Any], principal: str
    ) -> bool: ...


class HookDispatcher:
    """Dispatch post-processing hooks at key extension points.

    All hooks are deny-only. A policy hook can change ALLOW to DENY
    but cannot change DENY to ALLOW. Tool call hooks block on any
    False return. Errors in hooks fail closed (deny).
    """

    def __init__(self) -> None:
        self._policy_hooks: list[PostPolicyEvaluateHook] = []
        self._tool_call_hooks: list[PostToolCallGateHook] = []

    def register_policy_hook(self, hook: PostPolicyEvaluateHook) -> None:
        """Register a post-policy-evaluation hook."""
        self._policy_hooks.append(hook)

    def register_tool_call_hook(self, hook: PostToolCallGateHook) -> None:
        """Register a pre-tool-call gate hook."""
        self._tool_call_hooks.append(hook)

    def dispatch_policy(
        self, tool: str, principal: str, decision: Decision
    ) -> Decision:
        """Run all policy hooks. A hook returning DENY overrides ALLOW.

        Hooks cannot upgrade DENY to ALLOW. If a hook raises, the
        dispatcher fails closed and returns DENY.
        """
        current = decision
        for hook in self._policy_hooks:
            try:
                result = hook(tool, principal, current)
            except Exception:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.POLICY_DENY,
                        principal=principal,
                        detail={
                            "tool": tool,
                            "reason": "hook raised, failing closed",
                        },
                    )
                )
                return Decision(
                    kind=DecisionKind.DENY,
                    reason="extension hook error, failing closed",
                    tool=tool,
                    required_trust=current.required_trust,
                    observed_trust=current.observed_trust,
                )
            if result is None:
                continue
            # Deny-only: hooks can downgrade ALLOW to DENY but not
            # upgrade DENY to ALLOW.
            if current.kind != DecisionKind.DENY and result.kind == DecisionKind.DENY:
                current = result
        return current

    def dispatch_tool_call(
        self, tool: str, args: dict[str, Any], principal: str
    ) -> bool:
        """Run all tool call hooks. Any returning False blocks the call.

        If a hook raises, the dispatcher fails closed and returns False.
        """
        for hook in self._tool_call_hooks:
            try:
                allowed = hook(tool, args, principal)
            except Exception:
                emit_event(
                    SecurityEvent.now(
                        kind=EventKind.POLICY_DENY,
                        principal=principal,
                        detail={
                            "tool": tool,
                            "reason": "tool call hook raised, failing closed",
                        },
                    )
                )
                return False
            if not allowed:
                return False
        return True
