"""Conformance tests for ``tessera.adapters.llamaindex``."""

from __future__ import annotations

import sys
import types

import pytest

from tessera.events import EventKind

from .conftest import (
    KEY,
    PRINCIPAL,
    assert_method_signature,
    captured_events,
    import_adapter,
    make_policy,
)


def _stub_llama_index() -> None:
    if "llama_index" in sys.modules and getattr(
        sys.modules["llama_index"], "_tessera_stub", False
    ):
        return
    li = types.ModuleType("llama_index")
    li._tessera_stub = True
    li_core = types.ModuleType("llama_index.core")
    li_core._tessera_stub = True
    li.core = li_core
    sys.modules["llama_index"] = li
    sys.modules["llama_index.core"] = li_core


def _build_handler(deny_tool: str | None = None):
    _stub_llama_index()
    cls = import_adapter("tessera.adapters.llamaindex", "TesseraLlamaIndexHandler")
    return cls(policy=make_policy(deny_tool), signing_key=KEY, principal=PRINCIPAL)


def test_class_is_importable_with_stubbed_framework():
    _stub_llama_index()
    cls = import_adapter("tessera.adapters.llamaindex", "TesseraLlamaIndexHandler")
    assert cls.__name__ == "TesseraLlamaIndexHandler"


def test_public_method_signatures():
    _stub_llama_index()
    cls = import_adapter("tessera.adapters.llamaindex", "TesseraLlamaIndexHandler")
    assert_method_signature(cls, "on_event_start", "self", "event_type", "payload")
    assert_method_signature(cls, "on_event_end", "self", "event_type", "payload")


def test_function_call_event_is_gated():
    handler = _build_handler(deny_tool="dangerous_tool")
    # Seed via a fake function_call end so the context has a non-SYSTEM
    # segment and the SYSTEM requirement actually denies. Empty
    # contexts default to SYSTEM-trust per Context.min_trust.
    handler.on_event_end("function_call", payload={"output": "previous output"})

    class _Tool:
        name = "dangerous_tool"

    with pytest.raises(RuntimeError, match="Tessera policy denied"):
        handler.on_event_start("function_call", payload={"tool": _Tool()})


def test_non_function_call_event_is_passthrough():
    handler = _build_handler(deny_tool="dangerous_tool")

    # Any other event_type should be a no-op even when a deny is configured.
    handler.on_event_start("retrieve", payload={"tool": object()})
    handler.on_event_start("synthesize", payload={})


def test_function_call_event_with_no_payload_uses_unknown_tool():
    handler = _build_handler()
    # Should not raise even when tool_name resolves to "unknown_tool".
    handler.on_event_start("function_call", payload={})


# ---------------------------------------------------------------------------
# Live integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_live_llamaindex_handler_round_trip():
    # Defeat any stub a sibling test may have left in sys.modules.
    for key in list(sys.modules):
        if key == "llama_index" or key.startswith("llama_index."):
            mod = sys.modules[key]
            if getattr(mod, "_tessera_stub", False):
                sys.modules.pop(key, None)
    pytest.importorskip("llama_index.core")

    sys.modules.pop("tessera.adapters.llamaindex", None)
    from tessera.adapters.llamaindex import TesseraLlamaIndexHandler

    handler = TesseraLlamaIndexHandler(
        policy=make_policy(deny_tool="exfil"), signing_key=KEY, principal=PRINCIPAL
    )
    assert callable(handler.on_event_start)
    assert callable(handler.on_event_end)
    # Seed the context so min_trust drops below SYSTEM and the
    # SYSTEM requirement actually denies.
    handler.on_event_end("function_call", payload={"output": "previous output"})

    class _Tool:
        name = "exfil"

    with pytest.raises(RuntimeError, match="Tessera policy denied"):
        handler.on_event_start("function_call", payload={"tool": _Tool()})
