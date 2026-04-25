"""Phase 1A audit gap 1: ProvenanceJSONEncoder class behaviors."""

from __future__ import annotations

import json

import pytest

from tessera.taint.json_encoder import (
    SIDECAR_KEY,
    ProvenanceJSONEncoder,
    decode,
    encode,
)
from tessera.taint.label import (
    IntegrityLevel,
    LabeledValue,
    ProvenanceLabel,
)


def _untrusted() -> ProvenanceLabel:
    return ProvenanceLabel.untrusted_tool_output(
        segment_id="seg-x", origin_uri="web://x"
    )


# --- Encoder class behavior --------------------------------------------------


def test_encoder_subclasses_json_jsonencoder() -> None:
    assert issubclass(ProvenanceJSONEncoder, json.JSONEncoder)


def test_encoder_emits_sidecar_for_labeled_values() -> None:
    label = _untrusted()
    payload = {"to": LabeledValue(raw="alice@x", label=label)}
    wire = json.dumps(payload, cls=ProvenanceJSONEncoder)
    parsed = json.loads(wire)
    assert SIDECAR_KEY in parsed
    assert "to" in parsed[SIDECAR_KEY]


def test_encoder_round_trip_via_decode() -> None:
    label = _untrusted()
    payload = {"to": LabeledValue(raw="alice@x", label=label)}
    wire = json.dumps(payload, cls=ProvenanceJSONEncoder)
    revived = decode(json.loads(wire))
    assert isinstance(revived["to"], LabeledValue)
    assert revived["to"].label.integrity == IntegrityLevel.UNTRUSTED


def test_encoder_with_indent_keeps_sidecar() -> None:
    label = _untrusted()
    payload = {"to": LabeledValue(raw="alice@x", label=label)}
    wire = json.dumps(payload, cls=ProvenanceJSONEncoder, indent=2)
    assert SIDECAR_KEY in wire


def test_encoder_no_sidecar_when_no_labels() -> None:
    payload = {"to": "alice@x", "from": "bob@y"}
    wire = json.dumps(payload, cls=ProvenanceJSONEncoder)
    parsed = json.loads(wire)
    assert SIDECAR_KEY not in parsed


def test_module_level_encode_function_still_works() -> None:
    """The class is additive; the existing functional API stays."""
    label = _untrusted()
    out = encode({"to": LabeledValue(raw="alice@x", label=label)})
    assert SIDECAR_KEY in out
