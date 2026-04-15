"""Runtime assertion that Policy.evaluate() is called on every path.

The TLA+ specs in specs/ prove the invariant holds in the formal model.
This module enforces the same invariant at runtime: every code path
between agent output and tool execution (or response emission) MUST
pass through Policy.evaluate(). If any path bypasses it, a
PolicyBypassError is raised immediately.

Thread-safe. Uses threading.local() for per-thread session tracking
so concurrent sessions don't interfere.

Usage::

    checker = PolicyInvariantChecker()

    # When agent output arrives:
    checker.on_output_received("session_1")

    # When Policy.evaluate() runs:
    checker.on_policy_evaluated("session_1")

    # Before executing a tool:
    checker.assert_before_tool("session_1", "send_email")
    # raises PolicyBypassError if evaluate() wasn't called

    # Before returning a response:
    checker.assert_before_response("session_1")
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


class PolicyBypassError(RuntimeError):
    """Raised when a code path bypasses Policy.evaluate()."""


@dataclass
class _SessionState:
    output_received_at: float
    policy_evaluated: bool = False
    policy_evaluated_at: float | None = None


class PolicyInvariantChecker:
    """Runtime enforcement of the control-flow invariant.

    Instruments the pipeline to verify that Policy.evaluate() is called
    between every agent output and every tool execution or response
    emission. If a code path bypasses the policy check, the checker
    raises PolicyBypassError before the tool executes or the response
    is sent.

    Thread-safe via threading.local(). Each thread maintains its own
    session tracking state.
    """

    _local = threading.local()

    def on_output_received(self, session_id: str) -> None:
        """Record that new agent output arrived for a session.

        Resets the policy-evaluated flag. Any subsequent tool execution
        or response emission must pass through Policy.evaluate() first.
        """
        sessions = self._get_sessions()
        sessions[session_id] = _SessionState(
            output_received_at=time.monotonic(),
        )

    def on_policy_evaluated(self, session_id: str) -> None:
        """Record that Policy.evaluate() completed for a session."""
        sessions = self._get_sessions()
        state = sessions.get(session_id)
        if state is not None:
            state.policy_evaluated = True
            state.policy_evaluated_at = time.monotonic()

    def assert_before_tool(self, session_id: str, tool_name: str) -> None:
        """Assert that policy was evaluated before tool execution.

        Call this immediately before every tool execution. Raises
        PolicyBypassError if Policy.evaluate() was not called since
        the last agent output.

        Args:
            session_id: The session executing the tool.
            tool_name: The tool about to be executed.

        Raises:
            PolicyBypassError: If the policy check was bypassed.
        """
        sessions = self._get_sessions()
        state = sessions.get(session_id)

        if state is None:
            raise PolicyBypassError(
                f"tool {tool_name!r} execution attempted without "
                f"registered agent output for session {session_id!r}"
            )
        if not state.policy_evaluated:
            raise PolicyBypassError(
                f"tool {tool_name!r} execution attempted without "
                f"Policy.evaluate() for session {session_id!r} "
                f"(output received at {state.output_received_at:.3f})"
            )

    def assert_before_response(self, session_id: str) -> None:
        """Assert that policy was evaluated before response emission.

        Call this before sending a response to the user. If no agent
        output was received (direct response without tool calls), this
        is a no-op.

        Args:
            session_id: The session emitting the response.

        Raises:
            PolicyBypassError: If the policy check was bypassed.
        """
        sessions = self._get_sessions()
        state = sessions.get(session_id)
        if state is None:
            return  # No agent output = direct response, allowed
        if not state.policy_evaluated:
            raise PolicyBypassError(
                f"response emission attempted without "
                f"Policy.evaluate() for session {session_id!r}"
            )

    def reset(self, session_id: str | None = None) -> None:
        """Clear tracking state.

        Args:
            session_id: If provided, clear only that session.
                If None, clear all sessions for this thread.
        """
        sessions = self._get_sessions()
        if session_id is None:
            sessions.clear()
        else:
            sessions.pop(session_id, None)

    def _get_sessions(self) -> dict[str, _SessionState]:
        if not hasattr(self._local, "sessions"):
            self._local.sessions = {}
        return self._local.sessions
