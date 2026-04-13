"""LangChain callback handler adapter for Tessera policy enforcement.

Instruments LangChain agent runs with context labeling and tool-call
policy evaluation. Does NOT import langchain at module level; the
callback handler protocol is implemented as a plain class with the
expected method signatures.

Usage:
    from agentmesh import init
    from agentmesh.adapters.langchain import TesseraCallbackHandler

    mesh = init({"hmac_key": "auto"})
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")
    agent.run("do something", callbacks=[handler])
"""

from __future__ import annotations

import logging
from typing import Any

from tessera.context import Context
from tessera.labels import Origin, TrustLevel
from tessera.policy import PolicyViolation

from agentmesh import AgentMeshContext

logger = logging.getLogger(__name__)

_VALID_ON_DENY = ("raise", "log")


class TesseraCallbackHandler:
    """LangChain callback handler that enforces Tessera policy on tool calls.

    Implements ``on_llm_start``, ``on_tool_start``, and ``on_tool_end``
    without inheriting from any LangChain base class. LangChain dispatches
    callbacks by method name, so this works as long as the methods exist.

    The handler builds a fresh context on each ``on_llm_start`` call and
    holds it until the next ``on_llm_start`` replaces it. Tool calls
    between those boundaries are evaluated against that context.
    """

    def __init__(
        self,
        mesh: AgentMeshContext,
        principal: str,
        on_deny: str = "raise",
    ) -> None:
        if on_deny not in _VALID_ON_DENY:
            raise ValueError(
                f"on_deny must be one of {_VALID_ON_DENY!r}, got {on_deny!r}"
            )
        self.mesh = mesh
        self.principal = principal
        self.on_deny = on_deny
        self._current_context: Context | None = None

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Label each prompt string and build a new context."""
        ctx = Context()
        for prompt in prompts:
            seg = self.mesh.label(prompt, Origin.USER, self.principal)
            ctx.add(seg)
        self._current_context = ctx

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Evaluate the tool call against the current context.

        If no context has been built yet (no prior on_llm_start), the
        handler builds a minimal context from the tool input itself,
        labeled as Origin.TOOL.
        """
        tool_name = serialized.get("name", "unknown")

        if self._current_context is None:
            ctx = Context()
            seg = self.mesh.label(
                input_str, Origin.TOOL, self.principal,
                trust_level=TrustLevel.TOOL,
            )
            ctx.add(seg)
            self._current_context = ctx

        decision = self.mesh.evaluate(self._current_context, tool_name)
        if not decision.allowed:
            if self.on_deny == "raise":
                raise PolicyViolation(decision.reason)
            logger.warning(
                "tool call %r denied by policy: %s",
                tool_name,
                decision.reason,
            )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Label the tool output and add it to the current context."""
        if self._current_context is None:
            self._current_context = Context()

        seg = self.mesh.label(
            output, Origin.TOOL, self.principal,
            trust_level=TrustLevel.TOOL,
        )
        self._current_context.add(seg)
