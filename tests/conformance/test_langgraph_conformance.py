"""Conformance tests for ``tessera.adapters.langgraph``."""

from __future__ import annotations

import sys
import types

import pytest

from tessera.policy import Policy

from .conftest import (
    KEY,
    PRINCIPAL,
    assert_method_signature,
    captured_events,
    import_adapter,
    make_policy,
)


def _stub_langgraph() -> None:
    if "langgraph" in sys.modules and getattr(
        sys.modules["langgraph"], "_tessera_stub", False
    ):
        return
    mod = types.ModuleType("langgraph")
    mod._tessera_stub = True
    sys.modules["langgraph"] = mod


def _build_guard(deny_tool: str | None = None):
    _stub_langgraph()
    cls = import_adapter("tessera.adapters.langgraph", "TesseraLangGraphGuard")
    return cls(policy=make_policy(deny_tool), signing_key=KEY, principal=PRINCIPAL)


def test_class_is_importable_with_stubbed_framework():
    _stub_langgraph()
    cls = import_adapter("tessera.adapters.langgraph", "TesseraLangGraphGuard")
    assert cls.__name__ == "TesseraLangGraphGuard"


def test_public_method_signatures():
    _stub_langgraph()
    cls = import_adapter("tessera.adapters.langgraph", "TesseraLangGraphGuard")
    assert_method_signature(cls, "check_tool_call", "self", "state", "tool_name", "args")
    assert_method_signature(cls, "label_tool_output", "self", "state", "tool_name", "output")


def test_check_tool_call_returns_state_with_block_keys():
    guard = _build_guard()
    state = {"messages": [], "step": 1}
    out = guard.check_tool_call(state, "search_inbox", {})
    assert out["tessera_blocked"] is False
    assert out["tessera_reason"] is None
    assert out["messages"] == []
    assert out["step"] == 1


def test_check_tool_call_blocks_denied_tool():
    guard = _build_guard(deny_tool="dangerous_tool")
    # Seed the context with a TOOL-trust segment so min_trust drops
    # below SYSTEM and the SYSTEM requirement actually denies. Empty
    # contexts default to SYSTEM-trust per Context.min_trust.
    guard.label_tool_output({"messages": []}, "seed_tool", "previous tool output")
    out = guard.check_tool_call({"messages": []}, "dangerous_tool", {})
    assert out["tessera_blocked"] is True
    assert out["tessera_reason"]


def test_label_tool_output_adds_segment_to_context():
    guard = _build_guard()
    state = {"messages": []}
    before = len(guard._ctx.segments)
    guard.label_tool_output(state, "search_inbox", "result text")
    assert len(guard._ctx.segments) == before + 1


# ---------------------------------------------------------------------------
# Live integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_live_langgraph_node_round_trip():
    # Defeat any stub a sibling test may have left in sys.modules.
    for key in list(sys.modules):
        if key == "langgraph" or key.startswith("langgraph."):
            mod = sys.modules[key]
            if getattr(mod, "_tessera_stub", False):
                sys.modules.pop(key, None)
    pytest.importorskip("langgraph.graph")

    sys.modules.pop("tessera.adapters.langgraph", None)
    from tessera.adapters.langgraph import TesseraLangGraphGuard

    guard = TesseraLangGraphGuard(
        policy=make_policy(deny_tool="exfil"), signing_key=KEY, principal=PRINCIPAL
    )
    # Compose into a tiny graph: this only needs the StateGraph
    # constructor to exist; we avoid building edges to keep the
    # test snappy.
    from langgraph.graph import StateGraph

    graph = StateGraph(dict)
    graph.add_node("guard", lambda s: guard.check_tool_call(s, "exfil", {}))
    graph.add_node("label", lambda s: guard.label_tool_output(s, "exfil", "ok"))
    # Don't compile / run; presence of the node functions is the
    # contract we care about for this test.
    assert callable(guard.check_tool_call)
    assert callable(guard.label_tool_output)

    # Seed the context so min_trust drops below SYSTEM and the
    # SYSTEM requirement actually denies.
    guard.label_tool_output({"messages": []}, "seed_tool", "previous output")
    out = guard.check_tool_call({"messages": []}, "exfil", {})
    assert out["tessera_blocked"] is True
