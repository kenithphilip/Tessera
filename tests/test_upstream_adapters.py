"""Tests for tessera.adapters.upstream.

Covers:
- OpenAI->Anthropic request translation
- Anthropic->OpenAI response translation
- Edge cases: system messages, tool calls, tool results, tool_choice
- HTTP layer via httpx mock transport
- PROVIDERS registry contains expected keys
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tessera.adapters.upstream import (
    PROVIDERS,
    _anthropic_to_openai,
    _convert_messages,
    _convert_tool,
    _convert_tool_choice,
    _map_stop_reason,
    _openai_to_anthropic,
    anthropic_upstream,
    openai_upstream,
)


# ---------------------------------------------------------------------------
# PROVIDERS registry
# ---------------------------------------------------------------------------

def test_providers_contains_expected_keys():
    for key in ("openai", "mistral", "deepseek", "xai", "qwen", "groq", "together", "ollama"):
        assert key in PROVIDERS, f"Missing provider: {key}"


def test_providers_values_are_urls():
    for name, url in PROVIDERS.items():
        assert url.startswith("http"), f"{name} URL should start with http: {url}"


# ---------------------------------------------------------------------------
# OpenAI -> Anthropic: system message extraction
# ---------------------------------------------------------------------------

def test_system_message_extracted():
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
        ],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert result["system"] == "You are helpful."
    assert all(m["role"] != "system" for m in result["messages"])


def test_multiple_system_messages_joined():
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Part one."},
            {"role": "system", "content": "Part two."},
            {"role": "user", "content": "Hello"},
        ],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert result["system"] == "Part one.\n\nPart two."


def test_no_system_message_omits_system_field():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert "system" not in result


def test_system_message_as_content_blocks():
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": [{"type": "text", "text": "Be concise."}],
            },
            {"role": "user", "content": "Hello"},
        ],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert result["system"] == "Be concise."


# ---------------------------------------------------------------------------
# OpenAI -> Anthropic: message conversion
# ---------------------------------------------------------------------------

def test_user_message_preserved():
    msgs = [{"role": "user", "content": "Hello world"}]
    result = _convert_messages(msgs)
    assert result == [{"role": "user", "content": "Hello world"}]


def test_assistant_text_message():
    msgs = [{"role": "assistant", "content": "Hi there"}]
    result = _convert_messages(msgs)
    assert result[0]["role"] == "assistant"
    assert result[0]["content"] == [{"type": "text", "text": "Hi there"}]


def test_assistant_with_tool_calls():
    msgs = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_abc",
                    "type": "function",
                    "function": {
                        "name": "search",
                        "arguments": '{"query": "python"}',
                    },
                }
            ],
        }
    ]
    result = _convert_messages(msgs)
    assert result[0]["role"] == "assistant"
    blocks = result[0]["content"]
    assert len(blocks) == 1
    assert blocks[0]["type"] == "tool_use"
    assert blocks[0]["id"] == "call_abc"
    assert blocks[0]["name"] == "search"
    assert blocks[0]["input"] == {"query": "python"}


def test_assistant_with_text_and_tool_calls():
    msgs = [
        {
            "role": "assistant",
            "content": "Searching now.",
            "tool_calls": [
                {
                    "id": "call_xyz",
                    "type": "function",
                    "function": {"name": "search", "arguments": '{"q": "test"}'},
                }
            ],
        }
    ]
    result = _convert_messages(msgs)
    blocks = result[0]["content"]
    types = [b["type"] for b in blocks]
    assert "text" in types
    assert "tool_use" in types


def test_tool_result_becomes_user_content_block():
    msgs = [
        {
            "role": "tool",
            "tool_call_id": "call_abc",
            "content": "result text",
        }
    ]
    result = _convert_messages(msgs)
    assert result[0]["role"] == "user"
    assert result[0]["content"][0]["type"] == "tool_result"
    assert result[0]["content"][0]["tool_use_id"] == "call_abc"
    assert result[0]["content"][0]["content"] == "result text"


def test_consecutive_tool_results_merged_into_one_user_turn():
    msgs = [
        {"role": "tool", "tool_call_id": "call_1", "content": "result 1"},
        {"role": "tool", "tool_call_id": "call_2", "content": "result 2"},
    ]
    result = _convert_messages(msgs)
    # Must be merged into a single user turn
    assert len(result) == 1
    assert result[0]["role"] == "user"
    assert len(result[0]["content"]) == 2
    ids = [b["tool_use_id"] for b in result[0]["content"]]
    assert ids == ["call_1", "call_2"]


def test_tool_result_after_non_tool_result_starts_new_turn():
    msgs = [
        {"role": "user", "content": "Query"},
        {"role": "tool", "tool_call_id": "call_1", "content": "result"},
    ]
    result = _convert_messages(msgs)
    # User message first, then tool result as its own user turn
    assert len(result) == 2
    assert result[0]["role"] == "user"
    assert result[0]["content"] == "Query"
    assert result[1]["role"] == "user"
    assert result[1]["content"][0]["type"] == "tool_result"


# ---------------------------------------------------------------------------
# Tool definition conversion
# ---------------------------------------------------------------------------

def test_convert_tool_extracts_parameters_as_input_schema():
    tool = {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search the web",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
            },
        },
    }
    result = _convert_tool(tool)
    assert result["name"] == "search"
    assert result["description"] == "Search the web"
    assert result["input_schema"] == {
        "type": "object",
        "properties": {"query": {"type": "string"}},
    }
    assert "function" not in result
    assert "parameters" not in result


def test_convert_tool_in_openai_to_anthropic_pipeline():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Search for X"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "search",
                    "description": "Web search",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert len(result["tools"]) == 1
    assert result["tools"][0]["name"] == "search"
    assert "input_schema" in result["tools"][0]


# ---------------------------------------------------------------------------
# Tool choice conversion
# ---------------------------------------------------------------------------

def test_tool_choice_auto():
    assert _convert_tool_choice("auto") == {"type": "auto"}


def test_tool_choice_none():
    assert _convert_tool_choice("none") == {"type": "none"}


def test_tool_choice_required():
    assert _convert_tool_choice("required") == {"type": "any"}


def test_tool_choice_specific_function():
    choice = {"type": "function", "function": {"name": "search"}}
    result = _convert_tool_choice(choice)
    assert result == {"type": "tool", "name": "search"}


def test_tool_choice_absent_not_in_output():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    result = _openai_to_anthropic(payload, 4096)
    assert "tool_choice" not in result


# ---------------------------------------------------------------------------
# Optional fields forwarded
# ---------------------------------------------------------------------------

def test_temperature_forwarded():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.7,
    }
    result = _openai_to_anthropic(payload, 4096)
    assert result["temperature"] == 0.7


def test_max_tokens_forwarded_from_payload():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 256,
    }
    result = _openai_to_anthropic(payload, 4096)
    assert result["max_tokens"] == 256


def test_max_tokens_defaults_when_absent():
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
    }
    result = _openai_to_anthropic(payload, 512)
    assert result["max_tokens"] == 512


# ---------------------------------------------------------------------------
# Anthropic -> OpenAI response translation
# ---------------------------------------------------------------------------

def _anthropic_text_response(text: str, model: str = "claude-opus-4-6") -> dict:
    return {
        "id": "msg_abc",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": model,
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def _anthropic_tool_response(
    name: str, tool_id: str = "toolu_123", input_data: dict | None = None
) -> dict:
    return {
        "id": "msg_xyz",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "tool_use",
                "id": tool_id,
                "name": name,
                "input": input_data or {"query": "test"},
            }
        ],
        "model": "claude-opus-4-6",
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 20, "output_tokens": 15},
    }


def test_anthropic_text_response_to_openai():
    result = _anthropic_to_openai(_anthropic_text_response("Hello there"))
    assert result["object"] == "chat.completion"
    assert result["choices"][0]["message"]["role"] == "assistant"
    assert result["choices"][0]["message"]["content"] == "Hello there"
    assert result["choices"][0]["finish_reason"] == "stop"
    assert result["usage"]["prompt_tokens"] == 10
    assert result["usage"]["completion_tokens"] == 5
    assert result["usage"]["total_tokens"] == 15


def test_anthropic_tool_response_to_openai():
    result = _anthropic_to_openai(_anthropic_tool_response("search", "toolu_1", {"q": "python"}))
    msg = result["choices"][0]["message"]
    assert msg["content"] is None
    assert len(msg["tool_calls"]) == 1
    tc = msg["tool_calls"][0]
    assert tc["id"] == "toolu_1"
    assert tc["type"] == "function"
    assert tc["function"]["name"] == "search"
    assert json.loads(tc["function"]["arguments"]) == {"q": "python"}
    assert result["choices"][0]["finish_reason"] == "tool_calls"


def test_anthropic_mixed_text_and_tool_response():
    anthropic_resp = {
        "id": "msg_mix",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "Searching now."},
            {"type": "tool_use", "id": "toolu_2", "name": "search", "input": {"q": "x"}},
        ],
        "model": "claude-opus-4-6",
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 5, "output_tokens": 3},
    }
    result = _anthropic_to_openai(anthropic_resp)
    msg = result["choices"][0]["message"]
    assert msg["content"] == "Searching now."
    assert len(msg["tool_calls"]) == 1


def test_anthropic_response_preserves_model():
    result = _anthropic_to_openai(_anthropic_text_response("Hi", model="claude-haiku-4-5"))
    assert result["model"] == "claude-haiku-4-5"


# ---------------------------------------------------------------------------
# Stop reason mapping
# ---------------------------------------------------------------------------

def test_stop_reason_mapping():
    assert _map_stop_reason("end_turn") == "stop"
    assert _map_stop_reason("max_tokens") == "length"
    assert _map_stop_reason("tool_use") == "tool_calls"
    assert _map_stop_reason("stop_sequence") == "stop"
    assert _map_stop_reason("unknown_future_value") == "stop"


# ---------------------------------------------------------------------------
# HTTP layer: openai_upstream factory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_openai_upstream_posts_to_correct_url(respx_mock=None):
    """Verify openai_upstream builds the correct URL and passes the payload."""
    import httpx
    from unittest.mock import patch, AsyncMock

    mock_response = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }

    async def mock_post(url, **kwargs):
        assert url == "https://api.openai.com/v1/chat/completions"
        assert kwargs["json"]["model"] == "gpt-4o"
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value=mock_response)
        return resp

    upstream = openai_upstream(api_key="sk-test")
    with patch("tessera.adapters.upstream.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client_cls.return_value = mock_client

        result = await upstream({"model": "gpt-4o", "messages": []})

    assert result["model"] == "gpt-4o"


@pytest.mark.asyncio
async def test_openai_upstream_custom_base_url():
    """Custom base_url is used correctly (e.g. Mistral)."""
    async def mock_post(url, **kwargs):
        assert url == "https://api.mistral.ai/v1/chat/completions"
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"choices": [], "model": "mistral-large", "usage": {}})
        return resp

    upstream = openai_upstream(api_key="key", base_url=PROVIDERS["mistral"])
    with patch("tessera.adapters.upstream.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client_cls.return_value = mock_client

        await upstream({"model": "mistral-large", "messages": []})


# ---------------------------------------------------------------------------
# HTTP layer: anthropic_upstream factory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anthropic_upstream_translates_and_returns_openai_format():
    """Verify anthropic_upstream sends to Anthropic endpoint and returns OpenAI format."""
    anthropic_response = {
        "id": "msg_123",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Hello from Claude"}],
        "model": "claude-opus-4-6",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 4},
    }

    async def mock_post(url, **kwargs):
        assert "anthropic.com" in url
        # Verify translation happened
        body = kwargs["json"]
        assert "system" in body or "messages" in body
        assert "max_tokens" in body
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value=anthropic_response)
        return resp

    upstream = anthropic_upstream(api_key="sk-ant-test")
    payload = {
        "model": "claude-opus-4-6",
        "messages": [
            {"role": "system", "content": "Be helpful."},
            {"role": "user", "content": "Hello"},
        ],
    }

    with patch("tessera.adapters.upstream.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client_cls.return_value = mock_client

        result = await upstream(payload)

    assert result["object"] == "chat.completion"
    assert result["choices"][0]["message"]["content"] == "Hello from Claude"
    assert result["choices"][0]["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_anthropic_upstream_tool_call_round_trip():
    """Tool call flow: OpenAI tools in, Anthropic response out, OpenAI format returned."""
    anthropic_response = {
        "id": "msg_tool",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "tool_use", "id": "toolu_abc", "name": "search", "input": {"q": "test"}},
        ],
        "model": "claude-opus-4-6",
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 20, "output_tokens": 10},
    }

    captured_body: list[dict] = []

    async def mock_post(url, **kwargs):
        captured_body.append(kwargs["json"])
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value=anthropic_response)
        return resp

    upstream = anthropic_upstream(api_key="sk-ant-test")
    payload = {
        "model": "claude-opus-4-6",
        "messages": [{"role": "user", "content": "Search for test"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "search",
                    "description": "Web search",
                    "parameters": {"type": "object", "properties": {"q": {"type": "string"}}},
                },
            }
        ],
    }

    with patch("tessera.adapters.upstream.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=mock_post)
        mock_client_cls.return_value = mock_client

        result = await upstream(payload)

    # Verify the Anthropic request used input_schema not parameters
    sent = captured_body[0]
    assert sent["tools"][0]["name"] == "search"
    assert "input_schema" in sent["tools"][0]
    assert "parameters" not in sent["tools"][0]

    # Verify the response is in OpenAI format with tool_calls
    tc = result["choices"][0]["message"]["tool_calls"][0]
    assert tc["function"]["name"] == "search"
    assert result["choices"][0]["finish_reason"] == "tool_calls"
