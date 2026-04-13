"""Tests for the LangChain adapter in agentmesh.adapters.langchain."""

from __future__ import annotations

import logging

import pytest

from tessera.events import clear_sinks
from tessera.labels import Origin, TrustLevel
from tessera.policy import PolicyViolation

from agentmesh import init
from agentmesh.adapters.langchain import TesseraCallbackHandler


@pytest.fixture(autouse=True)
def _clean_sinks():
    clear_sinks()
    yield
    clear_sinks()


def _mesh_with_email_policy():
    return init({
        "hmac_key": "test-secret-key-long-enough",
        "tool_policies": [
            {"name": "send_email", "required_trust": "user"},
            {"name": "web_search", "required_trust": "tool"},
        ],
    })


def test_on_llm_start_builds_context():
    """Verify on_llm_start creates a context from the prompt list."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")

    handler.on_llm_start(
        serialized={},
        prompts=["You are a helpful assistant.", "Find me flight deals."],
    )
    assert handler._current_context is not None
    assert len(handler._current_context.segments) == 2
    # Both prompts are labeled as USER origin
    for seg in handler._current_context.segments:
        assert seg.label.origin == Origin.USER


def test_on_tool_start_denies_untrusted_tool():
    """Verify PolicyViolation when context is tainted and tool requires USER trust."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")

    # Build a context that includes an untrusted segment
    handler.on_llm_start(serialized={}, prompts=["user prompt"])
    # Taint the context by adding a web-origin segment
    tainted = mesh.label(
        "injected content", Origin.WEB, "attacker",
        trust_level=TrustLevel.UNTRUSTED,
    )
    handler._current_context.add(tainted)

    with pytest.raises(PolicyViolation):
        handler.on_tool_start(
            serialized={"name": "send_email"},
            input_str="send mail to bob",
        )


def test_on_tool_start_allows_trusted_tool():
    """Verify no error when context is clean and tool trust is met."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")

    handler.on_llm_start(serialized={}, prompts=["search for flights"])
    # web_search requires TOOL trust; USER context (100) >= TOOL (50)
    handler.on_tool_start(
        serialized={"name": "web_search"},
        input_str="flights to NYC",
    )
    # No exception means success


def test_on_deny_log_mode(caplog):
    """Verify on_deny='log' logs the denial but does not raise."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(
        mesh=mesh, principal="alice", on_deny="log",
    )

    handler.on_llm_start(serialized={}, prompts=["user prompt"])
    tainted = mesh.label(
        "injected", Origin.WEB, "attacker",
        trust_level=TrustLevel.UNTRUSTED,
    )
    handler._current_context.add(tainted)

    with caplog.at_level(logging.WARNING):
        handler.on_tool_start(
            serialized={"name": "send_email"},
            input_str="send secrets",
        )
    assert any("denied by policy" in r.message for r in caplog.records)


def test_on_tool_end_labels_output():
    """Verify on_tool_end adds a TOOL-origin segment to the context."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")

    handler.on_llm_start(serialized={}, prompts=["search"])
    handler.on_tool_end(output="search results: 3 flights found")

    # Should have 1 prompt segment + 1 tool output segment
    assert len(handler._current_context.segments) == 2
    tool_seg = handler._current_context.segments[1]
    assert tool_seg.label.origin == Origin.TOOL
    assert tool_seg.label.trust_level == TrustLevel.TOOL


def test_on_tool_start_without_prior_llm_start():
    """If on_tool_start is called before on_llm_start, a minimal context is built."""
    mesh = _mesh_with_email_policy()
    handler = TesseraCallbackHandler(mesh=mesh, principal="alice")

    # web_search requires TOOL; a TOOL-origin context should satisfy it
    handler.on_tool_start(
        serialized={"name": "web_search"},
        input_str="query",
    )
    assert handler._current_context is not None


def test_invalid_on_deny_raises():
    """Verify invalid on_deny values are rejected at construction time."""
    mesh = _mesh_with_email_policy()
    with pytest.raises(ValueError, match="on_deny"):
        TesseraCallbackHandler(mesh=mesh, principal="alice", on_deny="strip")
