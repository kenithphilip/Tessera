"""OpenAI Agents SDK hook adapter that gates tool calls via Tessera policy.

Install requirements:
    pip install tessera[openai-agents]   # adds openai-agents

Design:
- on_agent_start: initialise a fresh Context for the agent run.
- on_tool_start: run Policy.evaluate() against the agent's context;
  raise an exception on deny (the SDK surfaces this as a tool error).
- on_tool_end: label the tool output as TOOL trust (trust_level=50)
  and run the injection scorer; high scores emit SecurityEvents.
- on_agent_end: emit a session risk summary event and clean up state.

Source attribution: RunHooksBase interface from the OpenAI Agents SDK
(hooks.py in openai-agents).
"""

from __future__ import annotations

import uuid
from typing import Any

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy
from tessera.risk.forecaster import SessionRisk, SessionRiskForecaster
from tessera.scanners.heuristic import injection_score


class OpenAIAgentsNotAvailable(RuntimeError):
    """Raised when openai-agents is not installed."""


class TesseraAgentHooks:
    """OpenAI Agents SDK hook implementation that gates tool calls via Tessera.

    Implements the duck-typed RunHooksBase interface. Requires the
    openai-agents package at runtime; raises OpenAIAgentsNotAvailable
    if the package is absent.

    Args:
        policy: The Policy instance to evaluate tool calls against.
        signing_key: HMAC key used to sign context segment labels.
        principal: Principal name for context segments.
        injection_threshold: Injection score threshold for tool outputs.
            Events are emitted above this value. Default 0.5.

    Usage::

        from tessera import Policy, TrustLevel
        from tessera.adapters.openai_agents import TesseraAgentHooks

        policy = Policy()
        policy.require("web_search", TrustLevel.USER)

        hooks = TesseraAgentHooks(
            policy=policy,
            signing_key=b"replace-me",
            principal="alice",
        )
        # Pass to the Runner:
        # result = await Runner.run(agent, input, hooks=hooks)
    """

    def __init__(
        self,
        policy: Policy,
        signing_key: bytes,
        principal: str = "user",
        injection_threshold: float = 0.5,
    ) -> None:
        try:
            import agents as _agents_mod  # noqa: F401
        except ImportError as exc:
            raise OpenAIAgentsNotAvailable(
                "openai-agents is required for TesseraAgentHooks. "
                "Install it with: pip install tessera[openai-agents]"
            ) from exc

        self._policy = policy
        self._key = signing_key
        self._principal = principal
        self._injection_threshold = injection_threshold
        # agent_id -> (Context, SessionRiskForecaster, last_risk)
        self._sessions: dict[str, tuple[Context, SessionRiskForecaster, SessionRisk | None]] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _session(self, agent_id: str) -> tuple[Context, SessionRiskForecaster, SessionRisk | None]:
        if agent_id not in self._sessions:
            self._sessions[agent_id] = (Context(), SessionRiskForecaster(), None)
        return self._sessions[agent_id]

    def _agent_id(self, agent: Any) -> str:
        return str(getattr(agent, "id", None) or getattr(agent, "name", None) or id(agent))

    # ------------------------------------------------------------------
    # RunHooksBase interface (duck-typed)
    # ------------------------------------------------------------------

    async def on_agent_start(self, context: Any, agent: Any) -> None:
        """Initialise a fresh Tessera context and risk forecaster for this agent."""
        agent_id = self._agent_id(agent)
        ctx = Context()
        self._sessions[agent_id] = (ctx, SessionRiskForecaster(), None)

        # Label the initial input as a USER segment if accessible.
        input_text = getattr(context, "input", None)
        if isinstance(input_text, str) and input_text:
            seg = make_segment(
                input_text,
                origin=Origin.USER,
                principal=self._principal,
                key=self._key,
            )
            ctx.add(seg)

    async def on_tool_start(
        self,
        context: Any,
        agent: Any,
        tool: Any,
    ) -> None:
        """Gate the tool call against the Tessera policy.

        Raises RuntimeError on deny; the SDK surfaces this as a tool error.
        """
        agent_id = self._agent_id(agent)
        ctx, forecaster, _last_risk = self._session(agent_id)
        tool_name = getattr(tool, "name", str(tool))

        decision = self._policy.evaluate(ctx, tool_name)
        if not decision.allowed:
            raise RuntimeError(
                f"Tessera policy denied tool '{tool_name}': {decision.reason}"
            )

    async def on_tool_end(
        self,
        context: Any,
        agent: Any,
        tool: Any,
        result: str,
    ) -> None:
        """Label tool output as TOOL trust and scan for injection."""
        agent_id = self._agent_id(agent)
        ctx, forecaster, _ = self._session(agent_id)
        tool_name = getattr(tool, "name", str(tool))

        seg = make_segment(
            str(result),
            origin=Origin.TOOL,
            principal=self._principal,
            key=self._key,
        )
        ctx.add(seg)
        last_risk = forecaster.record(tool_name)
        self._sessions[agent_id] = (ctx, forecaster, last_risk)

        score = injection_score(str(result))
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

    async def on_agent_end(
        self,
        context: Any,
        agent: Any,
        output: Any,
    ) -> None:
        """Emit session risk summary and clean up state."""
        agent_id = self._agent_id(agent)
        if agent_id not in self._sessions:
            return
        ctx, forecaster, last_risk = self._sessions.pop(agent_id)
        if last_risk is not None and last_risk.should_pause:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=self._principal,
                    detail={
                        "source": "session_risk_forecaster",
                        "drift_score": last_risk.drift_score,
                        "salami_index": last_risk.salami_index,
                        "commitment_creep": last_risk.commitment_creep,
                        "overall_risk": last_risk.overall_risk,
                    },
                )
            )
