"""PydanticAI guard adapter that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[pydantic-ai]   # adds pydantic-ai

Design:
- tool_prepare: evaluates the Tessera policy before a tool runs. Raises
  an error on deny so PydanticAI skips the tool call.
- result_validator: labels the tool result as TOOL trust (trust_level=50),
  runs the injection scorer, and raises on suspicious content.

Targets PydanticAI >=0.0.5 tool hook / result validator interface
(duck-typed). The RunContext is accessed via duck-typing on its
attributes, not by importing the actual class.
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin
from tessera.policy import Policy
from tessera.scanners.heuristic import injection_score

__all__ = ["TesseraPydanticAIGuard", "PydanticAINotAvailable"]


class PydanticAINotAvailable(RuntimeError):
    """Raised when pydantic-ai is not installed."""


class TesseraPydanticAIGuard:
    """PydanticAI guard that gates tool calls via Tessera policy.

    Duck-types the PydanticAI tool hook and result validator interfaces.
    Requires pydantic-ai at runtime; raises PydanticAINotAvailable if
    the package is absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.pydantic_ai import TesseraPydanticAIGuard

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        guard = TesseraPydanticAIGuard(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Use with PydanticAI:
        # @agent.tool(prepare=guard.tool_prepare)
        # async def web_search(ctx, query: str) -> str: ...
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import pydantic_ai  # noqa: F401
        except ImportError as exc:
            raise PydanticAINotAvailable(
                "pydantic-ai is required for TesseraPydanticAIGuard. "
                "Install it with: pip install tessera[pydantic-ai]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        self._ctx = Context()

    # ------------------------------------------------------------------
    # PydanticAI hook interface (duck-typed)
    # ------------------------------------------------------------------

    def tool_prepare(self, ctx: Any, tool_def: Any) -> Any:
        """Evaluate the tool call against the Tessera policy.

        Designed to be passed as the ``prepare`` argument to a PydanticAI
        tool decorator. Returns the tool_def unchanged on allow, or
        raises RuntimeError on deny.

        Args:
            ctx: PydanticAI RunContext (duck-typed).
            tool_def: The tool definition object.

        Returns:
            The unmodified tool_def if the call is allowed.

        Raises:
            RuntimeError: If the policy denies the tool call.
        """
        tool_name = getattr(tool_def, "name", str(tool_def))
        decision = self._policy.evaluate(self._ctx, tool_name)
        if not decision.allowed:
            raise RuntimeError(
                f"Tessera policy denied tool '{tool_name}': {decision.reason}"
            )
        return tool_def

    def result_validator(self, ctx: Any, result: Any) -> Any:
        """Label the result as TOOL trust and scan for injection.

        Designed to be passed as a result_validator to a PydanticAI agent.
        Returns the result unchanged if clean, or raises ValueError if
        the injection score exceeds the threshold.

        Args:
            ctx: PydanticAI RunContext (duck-typed).
            result: The tool or agent result to validate.

        Returns:
            The unmodified result if the injection score is below threshold.

        Raises:
            ValueError: If the injection score exceeds the threshold.
        """
        text = str(result)
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
                        "tool": "(result_validator)",
                        "injection_score": round(score, 2),
                        "threshold": self._injection_threshold,
                    },
                )
            )
            raise ValueError(
                f"Tessera: injection score {score:.2f} exceeds threshold "
                f"{self._injection_threshold}"
            )
        return result

    @property
    def context(self) -> Context:
        """Expose the current session context for inspection."""
        return self._ctx


# Wave 2H spec name (back-compat alias).
MeshPydanticAIGuard = TesseraPydanticAIGuard

__all__ = ["TesseraPydanticAIGuard", "MeshPydanticAIGuard"]
