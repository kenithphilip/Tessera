"""Haystack pipeline guard component that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[haystack]   # adds haystack-ai

Design:
- run(): evaluates the Tessera policy for a given tool call and returns
  an allow/block verdict. Insert this component into a Haystack pipeline
  before the tool execution node.

Targets Haystack >=2.0 component interface (duck-typed). Implements
the run() method that Haystack calls when the pipeline executes.
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraHaystackGuard", "HaystackNotAvailable"]


class HaystackNotAvailable(RuntimeError):
    """Raised when haystack-ai is not installed."""


class TesseraHaystackGuard:
    """Haystack pipeline component that gates tool calls via Tessera policy.

    Duck-types the Haystack >=2.0 component interface. Requires
    haystack-ai at runtime; raises HaystackNotAvailable if the
    package is absent.

    Insert this component into a Haystack pipeline before tool execution.
    The run() method returns {"allowed": True} or {"blocked": True, "reason": ...}.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.haystack import TesseraHaystackGuard

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        guard = TesseraHaystackGuard(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Insert into a Haystack pipeline:
        # pipeline.add_component("tessera_guard", guard)
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import haystack  # noqa: F401
        except ImportError as exc:
            raise HaystackNotAvailable(
                "haystack-ai is required for TesseraHaystackGuard. "
                "Install it with: pip install tessera[haystack]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # Haystack component interface (duck-typed)
    # ------------------------------------------------------------------

    def run(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Evaluate the tool call against the Tessera policy.

        Args:
            tool_name: Name of the tool being invoked.
            tool_input: Arguments passed to the tool.

        Returns:
            {"allowed": True} if the call is permitted, or
            {"blocked": True, "reason": str} if denied.
        """
        decision = self._policy.evaluate(self._ctx, tool_name)
        if not decision.allowed:
            return {"blocked": True, "reason": decision.reason}
        return {"allowed": True}

    def label_output(self, tool_name: str, output: Any) -> None:
        """Label tool output as TOOL trust and scan for injection.

        Call this after tool execution to update the session context
        with the tool's output segment.

        Args:
            tool_name: Name of the tool that produced the output.
            output: The tool output to label and scan.
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

    @property
    def context(self) -> Context:
        """Expose the current session context for inspection."""
        return self._ctx
