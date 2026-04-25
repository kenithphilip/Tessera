"""LangGraph node guard that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[langgraph]   # adds langgraph

Design:
- check_tool_call: evaluates the Tessera policy for a given tool call
  and returns the state dict with a "blocked" flag if denied. Designed
  to be used as a conditional node in a LangGraph graph.
- label_tool_output: labels tool output as TOOL trust (trust_level=50),
  runs the injection scorer, and returns updated state. Designed to run
  as a node after tool execution.

Targets LangGraph >=0.2 state-based graph interface (duck-typed).
State is passed as a plain dict; the guard adds "tessera_blocked"
and "tessera_reason" keys on deny.
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraLangGraphGuard", "LangGraphNotAvailable"]


class LangGraphNotAvailable(RuntimeError):
    """Raised when langgraph is not installed."""


class TesseraLangGraphGuard:
    """LangGraph node function pair that gates tool calls via Tessera policy.

    Duck-types the LangGraph node interface. Requires langgraph at
    runtime; raises LangGraphNotAvailable if the package is absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.langgraph import TesseraLangGraphGuard

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        guard = TesseraLangGraphGuard(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Use as node functions in a LangGraph graph:
        # graph.add_node("check_tool", guard.check_tool_call)
        # graph.add_node("label_output", guard.label_tool_output)
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import langgraph  # noqa: F401
        except ImportError as exc:
            raise LangGraphNotAvailable(
                "langgraph is required for TesseraLangGraphGuard. "
                "Install it with: pip install tessera[langgraph]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # LangGraph node interface (duck-typed)
    # ------------------------------------------------------------------

    def check_tool_call(
        self,
        state: dict[str, Any],
        tool_name: str,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate the tool call against the Tessera policy.

        Returns the state dict with "tessera_blocked" and "tessera_reason"
        keys added. If the call is allowed, "tessera_blocked" is False.

        Args:
            state: LangGraph state dict.
            tool_name: Name of the tool being invoked.
            args: Arguments passed to the tool.

        Returns:
            Updated state dict with policy decision fields.
        """
        decision = self._policy.evaluate(self._ctx, tool_name)
        return {
            **state,
            "tessera_blocked": not decision.allowed,
            "tessera_reason": decision.reason if not decision.allowed else None,
        }

    def label_tool_output(
        self,
        state: dict[str, Any],
        tool_name: str,
        output: Any,
    ) -> dict[str, Any]:
        """Label tool output as TOOL trust and scan for injection.

        Args:
            state: LangGraph state dict.
            tool_name: Name of the tool that produced the output.
            output: The tool output to label and scan.

        Returns:
            Updated state dict (unchanged keys, context updated internally).
        """
        text = str(output)
        seg = make_segment(
            text,
            origin=Origin.TOOL,
            principal=self._principal,
            key=self._key,
        )
        self._ctx.add(seg)

        score = injection_score(text)
        if score >= self._injection_threshold:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=self._principal,
                    detail={
                        "tool": tool_name,
                        "injection_score": round(score, 2),
                        "threshold": self._injection_threshold,
                    },
                )
            )

        return state

    @property
    def context(self) -> Context:
        """Expose the current session context for inspection."""
        return self._ctx


# Wave 2H spec name (back-compat alias).
MeshLangGraphGuard = TesseraLangGraphGuard

__all__ = ["TesseraLangGraphGuard", "MeshLangGraphGuard"]
