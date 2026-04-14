"""LlamaIndex callback handler that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[llamaindex]   # adds llama-index-core

Design:
- on_event_start: if the event is a FUNCTION_CALL, run Policy.evaluate()
  against the session context; raise RuntimeError on deny.
- on_event_end: if the event is a FUNCTION_CALL, label the tool output
  as TOOL trust (trust_level=50) and run the injection scorer.

Targets LlamaIndex >=0.10 CallbackManager event interface (duck-typed).
The CBEventType.FUNCTION_CALL constant is matched as a string to avoid
importing the enum at module level.
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraLlamaIndexHandler", "LlamaIndexNotAvailable"]

# Duck-typed event type constant. Matches CBEventType.FUNCTION_CALL
# without requiring llama-index-core at import time.
_FUNCTION_CALL = "function_call"


class LlamaIndexNotAvailable(RuntimeError):
    """Raised when llama-index-core is not installed."""


class TesseraLlamaIndexHandler:
    """LlamaIndex callback handler that gates tool calls via Tessera policy.

    Duck-types the LlamaIndex CallbackManager handler interface.
    Requires llama-index-core at runtime; raises LlamaIndexNotAvailable
    if the package is absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.llamaindex import TesseraLlamaIndexHandler

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        handler = TesseraLlamaIndexHandler(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Register with a LlamaIndex CallbackManager:
        # callback_manager = CallbackManager([handler])
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import llama_index.core  # noqa: F401
        except ImportError as exc:
            raise LlamaIndexNotAvailable(
                "llama-index-core is required for TesseraLlamaIndexHandler. "
                "Install it with: pip install tessera[llamaindex]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # LlamaIndex CallbackManager interface (duck-typed)
    # ------------------------------------------------------------------

    def on_event_start(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Gate tool calls against the Tessera policy.

        Only acts on FUNCTION_CALL events. Other event types pass through.

        Args:
            event_type: The LlamaIndex CBEventType value (compared as string).
            payload: Event payload dict. Expected to contain "tool" with
                a .name attribute for function call events.
        """
        if str(event_type).lower() != _FUNCTION_CALL:
            return

        tool_name = "unknown_tool"
        if payload:
            tool = payload.get("tool")
            if tool is not None:
                tool_name = getattr(tool, "name", str(tool))

        decision = self._policy.evaluate(self._ctx, tool_name)
        if not decision.allowed:
            raise RuntimeError(
                f"Tessera policy denied tool '{tool_name}': {decision.reason}"
            )

    def on_event_end(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Label tool output as TOOL trust and scan for injection.

        Only acts on FUNCTION_CALL events. Other event types pass through.

        Args:
            event_type: The LlamaIndex CBEventType value (compared as string).
            payload: Event payload dict. Expected to contain "response"
                with the tool output for function call events.
        """
        if str(event_type).lower() != _FUNCTION_CALL:
            return

        output = ""
        tool_name = "unknown_tool"
        if payload:
            output = str(payload.get("response", ""))
            tool = payload.get("tool")
            if tool is not None:
                tool_name = getattr(tool, "name", str(tool))

        seg = make_segment(
            output,
            origin=Origin.TOOL,
            principal=self._principal,
            key=self._key,
        )
        self._ctx.add(seg)

        score = injection_score(output)
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
