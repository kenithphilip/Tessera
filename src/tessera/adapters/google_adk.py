"""Google Agent Development Kit callback adapter that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[google-adk]   # adds google-adk

Design:
- before_tool_callback: run Policy.evaluate() against the session context;
  return {"blocked": True, "reason": ...} on deny, None on allow.
- after_tool_callback: label the tool output as TOOL trust (trust_level=50)
  and run the injection scorer; high scores emit SecurityEvents.

Targets Google ADK >=0.3 callback interface. The callback_context
parameter is duck-typed: it exposes .tool_name, .tool_input, and
.tool_output attributes.
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraADKCallbacks", "GoogleADKNotAvailable"]


class GoogleADKNotAvailable(RuntimeError):
    """Raised when google-adk is not installed."""


class TesseraADKCallbacks:
    """Google ADK callback pair that gates tool calls via Tessera policy.

    Duck-types the ADK before_tool_callback / after_tool_callback
    interface. Requires google-adk at runtime; raises
    GoogleADKNotAvailable if the package is absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.google_adk import TesseraADKCallbacks

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        guard = TesseraADKCallbacks(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Register with an ADK agent:
        # agent = Agent(
        #     before_tool_callback=guard.before_tool_callback,
        #     after_tool_callback=guard.after_tool_callback,
        # )
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import google.adk as _adk_mod  # noqa: F401
        except ImportError as exc:
            raise GoogleADKNotAvailable(
                "google-adk is required for TesseraADKCallbacks. "
                "Install it with: pip install tessera[google-adk]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # ADK callback interface (duck-typed)
    # ------------------------------------------------------------------

    def before_tool_callback(self, callback_context: Any) -> dict[str, Any] | None:
        """Gate the tool call against the Tessera policy.

        Args:
            callback_context: ADK callback context with .tool_name and
                .tool_input attributes.

        Returns:
            None if the call is allowed, or a dict with "blocked" and
            "reason" keys if denied.
        """
        tool_name = getattr(callback_context, "tool_name", "unknown_tool")
        decision = self._policy.evaluate(self._ctx, tool_name)
        if not decision.allowed:
            return {"blocked": True, "reason": decision.reason}
        return None

    def after_tool_callback(self, callback_context: Any) -> None:
        """Label tool output as TOOL trust and scan for injection.

        Args:
            callback_context: ADK callback context with .tool_name and
                .tool_output attributes.
        """
        tool_name = getattr(callback_context, "tool_name", "unknown_tool")
        output = getattr(callback_context, "tool_output", "")
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
