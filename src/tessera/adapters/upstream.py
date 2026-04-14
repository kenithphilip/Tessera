"""Upstream LLM callables for the Tessera proxy.

Provides ready-to-use UpstreamFn implementations for OpenAI-compatible
providers and Anthropic. Pass the returned callable as the `upstream`
argument to `tessera.proxy.create_app()`.

OpenAI-compatible (same wire format, just a different base URL):
    - OpenAI
    - Mistral
    - Deepseek
    - xAI (Grok)
    - Qwen (DashScope compatible-mode endpoint)
    - Groq (serves Llama, Mixtral, etc.)
    - Together AI
    - Ollama (local)
    - vLLM (local or hosted)

Anthropic requires request/response translation because the Messages API
uses a different schema from OpenAI. This module handles the translation
transparently, so the rest of Tessera sees one canonical format.

Usage::

    from tessera.adapters.upstream import openai_upstream, anthropic_upstream, PROVIDERS

    # Any OpenAI-compatible provider
    upstream = openai_upstream(api_key="sk-...", base_url=PROVIDERS["mistral"])

    # Anthropic (schema translation handled internally)
    upstream = anthropic_upstream(api_key="sk-ant-...")

    app = create_app(..., upstream=upstream, ...)
"""

from __future__ import annotations

import json
from typing import Any

import httpx

# Known OpenAI-compatible base URLs. All use /chat/completions.
PROVIDERS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "xai": "https://api.x.ai/v1",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "ollama": "http://localhost:11434/v1",
}

# Anthropic API endpoint and version header.
_ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"

# Default max_tokens for Anthropic requests (required field with no OpenAI equivalent).
_DEFAULT_MAX_TOKENS = 4096


# ---------------------------------------------------------------------------
# OpenAI-compatible upstream
# ---------------------------------------------------------------------------

def openai_upstream(
    *,
    api_key: str,
    base_url: str = PROVIDERS["openai"],
    timeout: float = 120.0,
) -> Any:
    """Return an UpstreamFn that calls any OpenAI-compatible chat completions endpoint.

    Args:
        api_key: Bearer token for the provider.
        base_url: Provider base URL (no trailing slash). Defaults to OpenAI.
            Use PROVIDERS["mistral"], PROVIDERS["deepseek"], etc. for others.
        timeout: HTTP timeout in seconds. Default 120.

    Returns:
        An async callable ``payload -> response dict`` suitable for
        ``tessera.proxy.create_app(upstream=...)``.
    """
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    async def _call(payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp = await resp
            resp.raise_for_status()
            return resp.json()

    return _call


# ---------------------------------------------------------------------------
# Anthropic upstream (with schema translation)
# ---------------------------------------------------------------------------

def anthropic_upstream(
    *,
    api_key: str,
    default_max_tokens: int = _DEFAULT_MAX_TOKENS,
    timeout: float = 120.0,
) -> Any:
    """Return an UpstreamFn that calls the Anthropic Messages API.

    Translates the OpenAI chat completions format to the Anthropic Messages
    API format on the way in, and maps the Anthropic response back to the
    OpenAI format on the way out. The rest of Tessera sees one canonical
    representation.

    Args:
        api_key: Anthropic API key (``sk-ant-...``).
        default_max_tokens: Fallback max_tokens for Anthropic requests.
            Anthropic requires this field; OpenAI does not. Default 4096.
        timeout: HTTP timeout in seconds. Default 120.

    Returns:
        An async callable ``payload -> response dict`` suitable for
        ``tessera.proxy.create_app(upstream=...)``.
    """
    headers = {
        "x-api-key": api_key,
        "anthropic-version": _ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }

    async def _call(payload: dict[str, Any]) -> dict[str, Any]:
        anthropic_payload = _openai_to_anthropic(payload, default_max_tokens)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = client.post(_ANTHROPIC_API, headers=headers, json=anthropic_payload)
            resp = await resp
            resp.raise_for_status()
            return _anthropic_to_openai(resp.json())

    return _call


# ---------------------------------------------------------------------------
# Translation: OpenAI -> Anthropic Messages API
# ---------------------------------------------------------------------------

def _openai_to_anthropic(
    payload: dict[str, Any],
    default_max_tokens: int,
) -> dict[str, Any]:
    """Convert an OpenAI chat completions payload to Anthropic Messages API format.

    Translation rules:
    - role=system messages are extracted and joined as the top-level `system` string.
    - role=tool messages (tool results) are converted to user content blocks and
      merged with the preceding user message to satisfy Anthropic's alternating
      turn requirement.
    - Assistant messages with `tool_calls` become assistant content blocks of
      type `tool_use`.
    - Tool definitions convert `function.parameters` to `input_schema` and
      drop the outer `function` wrapper.
    """
    messages: list[dict[str, Any]] = payload.get("messages", [])
    tools: list[dict[str, Any]] = payload.get("tools", [])
    tool_choice = payload.get("tool_choice")

    # Extract system messages.
    system_parts: list[str] = []
    non_system: list[dict[str, Any]] = []
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content", "")
            if isinstance(content, str):
                system_parts.append(content)
            elif isinstance(content, list):
                system_parts.extend(
                    block.get("text", "") for block in content if block.get("type") == "text"
                )
        else:
            non_system.append(msg)

    # Convert remaining messages, merging tool results into user turns.
    anthropic_messages = _convert_messages(non_system)

    result: dict[str, Any] = {
        "model": payload.get("model", "claude-opus-4-6"),
        "messages": anthropic_messages,
        "max_tokens": payload.get("max_tokens", default_max_tokens),
    }

    if system_parts:
        result["system"] = "\n\n".join(system_parts)

    if tools:
        result["tools"] = [_convert_tool(t) for t in tools]

    if tool_choice is not None:
        result["tool_choice"] = _convert_tool_choice(tool_choice)

    # Forward optional fields.
    for key in ("temperature", "top_p", "stop", "stream"):
        if key in payload:
            result[key] = payload[key]

    return result


def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert non-system OpenAI messages to Anthropic turn format.

    Merges consecutive tool results into a single user message, because
    Anthropic requires strict user/assistant alternation with tool results
    as user-role content blocks.
    """
    out: list[dict[str, Any]] = []

    for msg in messages:
        role = msg.get("role")

        if role == "assistant":
            content = msg.get("content")
            tool_calls = msg.get("tool_calls", [])

            blocks: list[dict[str, Any]] = []
            if content:
                blocks.append({"type": "text", "text": content})
            for tc in tool_calls:
                fn = tc.get("function", {})
                args_raw = fn.get("arguments", "{}")
                try:
                    args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                except json.JSONDecodeError:
                    args = {"_raw": args_raw}
                blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", ""),
                    "name": fn.get("name", ""),
                    "input": args,
                })

            out.append({"role": "assistant", "content": blocks or content or ""})

        elif role == "tool":
            # Tool results become user-role content blocks.
            result_block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": msg.get("tool_call_id", ""),
                "content": msg.get("content", ""),
            }
            # Merge into last user turn if it already holds tool_results.
            if (
                out
                and out[-1]["role"] == "user"
                and isinstance(out[-1]["content"], list)
                and out[-1]["content"]
                and out[-1]["content"][0].get("type") == "tool_result"
            ):
                out[-1]["content"].append(result_block)
            else:
                out.append({"role": "user", "content": [result_block]})

        else:
            # user messages
            content = msg.get("content", "")
            out.append({"role": "user", "content": content})

    return out


def _convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Convert an OpenAI tool definition to Anthropic format."""
    fn = tool.get("function", tool)
    return {
        "name": fn.get("name", ""),
        "description": fn.get("description", ""),
        "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
    }


def _convert_tool_choice(tool_choice: Any) -> dict[str, Any]:
    """Convert OpenAI tool_choice to Anthropic tool_choice format."""
    if tool_choice == "auto":
        return {"type": "auto"}
    if tool_choice == "none":
        return {"type": "none"}
    if tool_choice == "required":
        return {"type": "any"}
    if isinstance(tool_choice, dict):
        fn_name = tool_choice.get("function", {}).get("name")
        if fn_name:
            return {"type": "tool", "name": fn_name}
    return {"type": "auto"}


# ---------------------------------------------------------------------------
# Translation: Anthropic Messages API -> OpenAI
# ---------------------------------------------------------------------------

def _anthropic_to_openai(response: dict[str, Any]) -> dict[str, Any]:
    """Convert an Anthropic Messages API response to OpenAI chat completions format."""
    content_blocks: list[dict[str, Any]] = response.get("content", [])

    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    for block in content_blocks:
        btype = block.get("type")
        if btype == "text":
            text_parts.append(block.get("text", ""))
        elif btype == "tool_use":
            tool_calls.append({
                "id": block.get("id", ""),
                "type": "function",
                "function": {
                    "name": block.get("name", ""),
                    "arguments": json.dumps(block.get("input", {})),
                },
            })

    message: dict[str, Any] = {"role": "assistant"}
    if text_parts:
        message["content"] = "\n".join(text_parts)
    else:
        message["content"] = None
    if tool_calls:
        message["tool_calls"] = tool_calls

    stop_reason = response.get("stop_reason", "end_turn")
    finish_reason = _map_stop_reason(stop_reason)

    usage = response.get("usage", {})
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)

    return {
        "id": response.get("id", ""),
        "object": "chat.completion",
        "model": response.get("model", ""),
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    }


def _map_stop_reason(stop_reason: str) -> str:
    """Map Anthropic stop_reason to OpenAI finish_reason."""
    return {
        "end_turn": "stop",
        "max_tokens": "length",
        "tool_use": "tool_calls",
        "stop_sequence": "stop",
    }.get(stop_reason, "stop")
