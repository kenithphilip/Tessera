"""CrewAI step callback adapter that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[crewai]   # adds crewai

Design:
- on_tool_start: run Policy.evaluate() against the session context;
  raise RuntimeError on deny (CrewAI convention for step failures).
- on_tool_end: label the tool output as TOOL trust (trust_level=50)
  and run the injection scorer; high scores emit SecurityEvents.

Targets CrewAI >=0.50 step callback interface (duck-typed).
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraCrewCallback", "CrewAINotAvailable"]


class CrewAINotAvailable(RuntimeError):
    """Raised when crewai is not installed."""


class TesseraCrewCallback:
    """CrewAI step callback that gates tool calls via Tessera policy.

    Duck-types the CrewAI step callback interface. Requires the
    crewai package at runtime; raises CrewAINotAvailable if absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.crewai import TesseraCrewCallback

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        callback = TesseraCrewCallback(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Pass as step_callback to CrewAI Crew or Task.
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import crewai as _crewai_mod  # noqa: F401
        except ImportError as exc:
            raise CrewAINotAvailable(
                "crewai is required for TesseraCrewCallback. "
                "Install it with: pip install tessera[crewai]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # CrewAI step callback interface (duck-typed)
    # ------------------------------------------------------------------

    def on_tool_start(self, tool_name: str, tool_input: dict[str, Any]) -> None:
        """Gate the tool call against the Tessera policy.

        Raises RuntimeError on deny (CrewAI convention).
        """
        decision = self._policy.evaluate(self._ctx, tool_name)
        if not decision.allowed:
            raise RuntimeError(
                f"Tessera policy denied tool '{tool_name}': {decision.reason}"
            )

    def on_tool_end(self, tool_name: str, output: Any) -> None:
        """Label tool output as TOOL trust and scan for injection."""
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


# Wave 2H spec name (back-compat alias).
MeshCrewCallback = TesseraCrewCallback

__all__ = ["TesseraCrewCallback", "MeshCrewCallback"]
