"""Tests for runtime policy invariant enforcement."""

from __future__ import annotations

import pytest

from tessera.policy_invariant import PolicyBypassError, PolicyInvariantChecker


class TestPolicyInvariantChecker:
    def setup_method(self) -> None:
        """Reset thread-local state before each test."""
        checker = PolicyInvariantChecker()
        checker.reset()

    def test_normal_flow_passes(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        checker.on_policy_evaluated("s1")
        checker.assert_before_tool("s1", "send_email")  # should not raise

    def test_tool_without_policy_raises(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        # Skip policy evaluation
        with pytest.raises(PolicyBypassError, match="send_email"):
            checker.assert_before_tool("s1", "send_email")

    def test_tool_without_output_raises(self) -> None:
        checker = PolicyInvariantChecker()
        with pytest.raises(PolicyBypassError, match="without registered"):
            checker.assert_before_tool("s1", "read_file")

    def test_response_without_policy_raises(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        with pytest.raises(PolicyBypassError, match="response emission"):
            checker.assert_before_response("s1")

    def test_response_without_output_is_ok(self) -> None:
        checker = PolicyInvariantChecker()
        # No output received = direct response, allowed
        checker.assert_before_response("s1")  # should not raise

    def test_new_output_resets_policy_flag(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        checker.on_policy_evaluated("s1")
        checker.assert_before_tool("s1", "tool_a")  # passes

        # New output resets the flag
        checker.on_output_received("s1")
        with pytest.raises(PolicyBypassError):
            checker.assert_before_tool("s1", "tool_b")

    def test_independent_sessions(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        checker.on_policy_evaluated("s1")
        checker.on_output_received("s2")
        # s2 has output but no policy evaluation
        checker.assert_before_tool("s1", "tool")  # s1 is fine
        with pytest.raises(PolicyBypassError):
            checker.assert_before_tool("s2", "tool")  # s2 is not

    def test_reset_clears_session(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        checker.reset("s1")
        # After reset, tool without output raises "without registered"
        with pytest.raises(PolicyBypassError, match="without registered"):
            checker.assert_before_tool("s1", "tool")

    def test_reset_all(self) -> None:
        checker = PolicyInvariantChecker()
        checker.on_output_received("s1")
        checker.on_output_received("s2")
        checker.reset()
        # Both sessions cleared
        checker.assert_before_response("s1")  # no output = ok
        checker.assert_before_response("s2")  # no output = ok
