"""OpenAI SDK monkey-patching adapter.

Wraps ``client.chat.completions.create`` so every call automatically
labels messages, builds a Tessera Context, and evaluates tool calls
against the mesh policy. Denied tool calls raise ``PolicyViolation``
by default, but callers can select "log" or "strip" behavior instead.

Supports both sync (``OpenAI``) and async (``AsyncOpenAI``) clients.
Does NOT import openai at module level.
"""

from __future__ import annotations

import functools
import logging
import re
from typing import Any

from tessera.context import Context
from tessera.labels import Origin, TrustLevel
from tessera.policy import PolicyViolation

from agentmesh import AgentMeshContext

logger = logging.getLogger(__name__)

# OpenAI message role -> Tessera origin mapping
_ROLE_ORIGIN: dict[str, Origin] = {
    "user": Origin.USER,
    "system": Origin.SYSTEM,
    "tool": Origin.TOOL,
    "assistant": Origin.SYSTEM,
}

_VALID_ON_DENY = ("raise", "log", "strip")


def patch_openai_client(
    client: Any,
    mesh: AgentMeshContext,
    principal: str,
    on_deny: str = "raise",
    untrusted_roles: dict[str, Any] | None = None,
) -> Any:
    """Wrap ``client.chat.completions.create`` with Tessera policy checks.

    Args:
        client: An ``openai.OpenAI`` or ``openai.AsyncOpenAI`` instance.
        mesh: The AgentMeshContext from ``agentmesh.init()``.
        principal: Identity string attributed to user messages.
        on_deny: Behavior when a tool call is denied by policy.
            "raise" (default): raise PolicyViolation.
            "log": log the denial but return the response unchanged.
            "strip": remove denied tool calls from the response.
        untrusted_roles: Optional mapping to mark specific messages as
            untrusted. Keys can be:
            - int: message index in the list (zero-based)
            - str: regex pattern matched against message content
            Matched messages are labeled as Origin.WEB / TrustLevel.UNTRUSTED
            regardless of their role.

    Returns:
        The same client instance, with ``chat.completions.create`` wrapped.

    Raises:
        PolicyViolation: if on_deny is "raise" and a tool call is denied.
        ValueError: if on_deny is not one of "raise", "log", "strip".
    """
    if on_deny not in _VALID_ON_DENY:
        raise ValueError(
            f"on_deny must be one of {_VALID_ON_DENY!r}, got {on_deny!r}"
        )

    original_create = client.chat.completions.create

    # Detect async client: if the original create is a coroutine function,
    # wrap with an async wrapper.
    if _is_coroutine_function(original_create):
        @functools.wraps(original_create)
        async def async_wrapped_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages") or (args[0] if args else [])
            ctx = _build_context(messages, mesh, principal, untrusted_roles)
            response = await original_create(*args, **kwargs)
            response = _handle_tool_calls(response, mesh, ctx, on_deny)
            return response

        client.chat.completions.create = async_wrapped_create
    else:
        @functools.wraps(original_create)
        def wrapped_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages") or (args[0] if args else [])
            ctx = _build_context(messages, mesh, principal, untrusted_roles)
            response = original_create(*args, **kwargs)
            response = _handle_tool_calls(response, mesh, ctx, on_deny)
            return response

        client.chat.completions.create = wrapped_create

    return client


def _is_coroutine_function(fn: Any) -> bool:
    """Check if fn is an async function without importing asyncio at top level."""
    import asyncio
    return asyncio.iscoroutinefunction(fn)


def _build_context(
    messages: list[dict[str, Any]],
    mesh: AgentMeshContext,
    principal: str,
    untrusted_roles: dict[str, Any] | None = None,
) -> Context:
    """Label each message and assemble a Context."""
    untrusted_indices: set[int] = set()
    untrusted_patterns: list[re.Pattern[str]] = []

    if untrusted_roles:
        for key, _value in untrusted_roles.items():
            if isinstance(key, int):
                untrusted_indices.add(key)
            elif isinstance(key, str):
                untrusted_patterns.append(re.compile(key))

    ctx = Context()
    for idx, msg in enumerate(messages):
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if not isinstance(content, str):
            content = str(content)

        # Check if this message should be treated as untrusted
        if idx in untrusted_indices or _matches_any(content, untrusted_patterns):
            origin = Origin.WEB
            trust = TrustLevel.UNTRUSTED
            seg = mesh.label(content, origin, principal, trust_level=trust)
        elif role == "tool":
            origin = Origin.TOOL
            seg = mesh.label(content, origin, principal, trust_level=TrustLevel.TOOL)
        else:
            origin = _ROLE_ORIGIN.get(role, Origin.USER)
            seg = mesh.label(content, origin, principal)

        ctx.add(seg)
    return ctx


def _matches_any(content: str, patterns: list[re.Pattern[str]]) -> bool:
    """Return True if content matches any compiled regex pattern."""
    return any(p.search(content) for p in patterns)


def _handle_tool_calls(
    response: Any,
    mesh: AgentMeshContext,
    ctx: Context,
    on_deny: str,
) -> Any:
    """Evaluate tool calls and apply the on_deny strategy."""
    choices = getattr(response, "choices", None)
    if not choices:
        return response

    for choice in choices:
        message = getattr(choice, "message", None)
        if message is None:
            continue
        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            continue

        denied_indices: list[int] = []
        for i, tc in enumerate(tool_calls):
            fn = getattr(tc, "function", None)
            tool_name = getattr(fn, "name", None) if fn else None
            if not tool_name:
                continue
            decision = mesh.evaluate(ctx, tool_name)
            if not decision.allowed:
                if on_deny == "raise":
                    raise PolicyViolation(decision.reason)
                elif on_deny == "log":
                    logger.warning(
                        "tool call %r denied by policy: %s",
                        tool_name,
                        decision.reason,
                    )
                elif on_deny == "strip":
                    denied_indices.append(i)

        if on_deny == "strip" and denied_indices:
            remaining = [
                tc for i, tc in enumerate(tool_calls)
                if i not in set(denied_indices)
            ]
            message.tool_calls = remaining if remaining else None

    return response
