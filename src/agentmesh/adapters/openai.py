"""OpenAI SDK monkey-patching adapter.

Wraps ``client.chat.completions.create`` so every call automatically
labels messages, builds a Tessera Context, and evaluates tool calls
against the mesh policy. Denied tool calls raise ``PolicyViolation``.

This is a skeleton demonstrating the integration pattern. Production
adapters will handle streaming, async, and richer role mapping.
"""

from __future__ import annotations

import functools
from typing import Any

from tessera.context import Context
from tessera.labels import Origin
from tessera.policy import PolicyViolation

from agentmesh import AgentMeshContext

# OpenAI message role -> Tessera origin mapping
_ROLE_ORIGIN: dict[str, Origin] = {
    "user": Origin.USER,
    "system": Origin.SYSTEM,
    "tool": Origin.TOOL,
    "assistant": Origin.SYSTEM,
}


def patch_openai_client(
    client: Any,
    mesh: AgentMeshContext,
    principal: str,
) -> Any:
    """Wrap ``client.chat.completions.create`` with Tessera policy checks.

    Args:
        client: An ``openai.OpenAI`` client instance.
        mesh: The AgentMeshContext from ``agentmesh.init()``.
        principal: Identity string attributed to user messages.

    Returns:
        The same client instance, with ``chat.completions.create`` wrapped.

    Raises:
        PolicyViolation: if a tool call in the response is denied by policy.
    """
    original_create = client.chat.completions.create

    @functools.wraps(original_create)
    def wrapped_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages") or (args[0] if args else [])
        ctx = _build_context(messages, mesh, principal)
        response = original_create(*args, **kwargs)
        _check_tool_calls(response, mesh, ctx)
        return response

    client.chat.completions.create = wrapped_create
    return client


def _build_context(
    messages: list[dict[str, Any]],
    mesh: AgentMeshContext,
    principal: str,
) -> Context:
    """Label each message and assemble a Context."""
    ctx = Context()
    for msg in messages:
        role = msg.get("role", "user")
        origin = _ROLE_ORIGIN.get(role, Origin.USER)
        content = msg.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        seg = mesh.label(content, origin, principal)
        ctx.add(seg)
    return ctx


def _check_tool_calls(
    response: Any,
    mesh: AgentMeshContext,
    ctx: Context,
) -> None:
    """Evaluate each tool call in the response against the policy."""
    choices = getattr(response, "choices", None)
    if not choices:
        return
    for choice in choices:
        message = getattr(choice, "message", None)
        if message is None:
            continue
        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            continue
        for tc in tool_calls:
            fn = getattr(tc, "function", None)
            tool_name = getattr(fn, "name", None) if fn else None
            if not tool_name:
                continue
            decision = mesh.evaluate(ctx, tool_name)
            if not decision.allowed:
                raise PolicyViolation(decision.reason)
