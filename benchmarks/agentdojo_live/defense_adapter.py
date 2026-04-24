"""Tessera defense adapter for AgentDojo (reference copy).

This module holds the Tessera defense adapter in the shape the
upstream AgentDojo project will host at
``agentdojo/agent_pipeline/defenses/tessera.py`` once the Phase 2
upstream PR lands. We maintain it in-tree as a reference so the
``submit.py`` driver can run against a local clone without
requiring the upstream fork.

Two integration points:

- :class:`MeshDefensePipeline` decorates an AgentDojo ``AgentPipeline``
  by inserting label tagging at :class:`InitQuery` time and a
  policy gate (via :mod:`tessera.policy` and the Action Critic) at
  each ``ToolsExecutor`` invocation.
- :func:`defense_pipeline_factory` is the entry point registered
  in AgentDojo's defense registry (see the ``agentdojo --defenses``
  CLI flag).

The adapter is intentionally thin: it imports Tessera primitives
and delegates decision logic to them. The upstream project does
not need to vendor Tessera; it imports it as an optional dependency.

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 4.2.
- AgentDojo defense plugin docs: ``agentdojo/agent_pipeline/defenses/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol


class _PipelineStage(Protocol):
    """Minimal structural shape of an AgentDojo pipeline stage.

    Mirrors ``agentdojo.agent_pipeline.BasePipelineElement`` without
    importing it here; the adapter is importable on its own for
    testing and docs.
    """

    def query(
        self,
        prompt: str,
        runtime: Any,
        env: Any,
        messages: list[dict[str, Any]] | None = None,
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[Any, ...]: ...


@dataclass
class MeshDefensePipeline:
    """Wrap an AgentDojo pipeline with Tessera label + policy gates.

    Instantiation does not import Tessera eagerly; the
    :meth:`_activate` call at first use does so lazily to keep the
    adapter importable in environments where Tessera is optional.
    """

    inner: _PipelineStage
    trust_key: bytes
    critic_mode: str = "stub"

    def _activate(self) -> Any:
        from tessera.context import Context, make_segment
        from tessera.labels import Origin, TrustLevel
        from tessera.policy import Policy

        return Context, make_segment, Origin, TrustLevel, Policy

    def query(
        self,
        prompt: str,
        runtime: Any,
        env: Any,
        messages: list[dict[str, Any]] | None = None,
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[Any, ...]:
        """Delegate to the inner pipeline after tagging the prompt.

        In Phase 2 wave 2A this call:

        1. Builds a :class:`tessera.context.Context` seeded with the
           user prompt as a USER-trust segment and each tool result
           as an UNTRUSTED segment labeled with the source URI.
        2. Wraps each tool call in a :func:`Policy.evaluate` +
           :func:`tessera.action_critic.review` pair. Denied calls
           become ``{"role": "tool", "content": "denied"}`` messages
           that AgentDojo's utility function interprets as tool
           failure.
        3. Passes the decorated message stream back to the inner
           pipeline.

        For v0.12 the adapter is documented-but-not-wired; the
        driver in ``submit.py`` uses the existing ``run_haiku.py``
        path which embeds Tessera manually.
        """
        return self.inner.query(prompt, runtime, env, messages, extra_args)


def defense_pipeline_factory(
    inner: _PipelineStage,
    *,
    trust_key: bytes | None = None,
    critic_mode: str = "stub",
) -> MeshDefensePipeline:
    """Entry point the AgentDojo defense registry will call."""
    if trust_key is None:
        import os

        raw = os.environ.get("TESSERA_DEFENSE_TRUST_KEY", "")
        trust_key = raw.encode("utf-8") if raw else b"\x00" * 32
    return MeshDefensePipeline(
        inner=inner, trust_key=trust_key, critic_mode=critic_mode
    )


__all__ = ["MeshDefensePipeline", "defense_pipeline_factory"]
