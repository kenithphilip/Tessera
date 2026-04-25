"""Provenance-preserving JSON encoder.

When a labeled value is serialized to JSON, the label MUST travel
alongside or downstream consumers lose attribution. The pattern
follows FIDES Section 4.1 ("add a metadata field to every node in
a tool result tree to store that node's label") and is wire-
compatible with the SEP-1913 ``attribution`` annotation surface
on MCP tool outputs.

Encoding rules
--------------

The encoder walks any mapping or sequence value. For every leaf or
container that carries a :class:`~tessera.taint.label.ProvenanceLabel`
(via :class:`~tessera.taint.label.LabeledValue` wrapper or the
``_label`` attribute pattern used by :class:`tessera.taint.tstr.TaintedStr`
in Phase 1 wave 1B-i), the encoder records a parallel ``__tessera_labels__``
sidecar at the same nesting depth. The sidecar is a JSON object
keyed by the same field names with compact label payloads:

.. code-block:: json

    {
      "recipient": "alice@example.com",
      "amount": 100,
      "__tessera_labels__": {
        "recipient": {"src": ["mcp://gmail/msg/123"], "i": 2, "s": 1, "cap": 4},
        "amount":    {"src": ["user://session/42"],   "i": 0, "s": 0, "cap": 3}
      }
    }

Compact field shorthand:

- ``src``: list of source URIs (``SegmentRef.origin_uri``).
- ``i``:   integrity level integer.
- ``s``:   secrecy level integer.
- ``cap``: capacity level integer.
- ``rd``:  reader list, omitted when readers is Public.
- ``mfd``: manifest digest, omitted when null.

Use :func:`canonical_json` for a stable serialization (sorted keys,
no whitespace) suitable for hashing or signing.
"""

from __future__ import annotations

import json
from typing import Any

from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
    LabeledValue,
    ProvenanceLabel,
    Public,
    SecrecyLevel,
)

#: Sidecar key used at every nesting depth where labels exist.
#: Reserved; user payloads must not use this key.
SIDECAR_KEY = "__tessera_labels__"


def _label_to_compact(label: ProvenanceLabel) -> dict[str, Any]:
    """Compact encoding of one label per the wire format above."""
    payload: dict[str, Any] = {
        "src": sorted(s.origin_uri for s in label.sources),
        "i": int(label.integrity),
        "s": int(label.secrecy),
        "cap": int(label.capacity),
    }
    # Manifest digests, when present on every source, ride along
    # under "mfd" so SEP-1913 manifestDigest interop works.
    digests = sorted(
        s.manifest_digest for s in label.sources if s.manifest_digest is not None
    )
    if digests:
        payload["mfd"] = digests
    # Readers omitted when Public.
    if label.readers is not Public.PUBLIC:
        payload["rd"] = sorted(label.readers)
    return payload


def _compact_to_label(payload: dict[str, Any]) -> ProvenanceLabel:
    """Inverse of :func:`_label_to_compact`."""
    from tessera.taint.label import SegmentRef

    sources = frozenset(
        SegmentRef(
            segment_id=uri,
            origin_uri=uri,
            manifest_digest=(payload.get("mfd") or [None])[idx]
            if idx < len(payload.get("mfd") or [])
            else None,
        )
        for idx, uri in enumerate(payload.get("src", []))
    )
    rd = payload.get("rd")
    readers = Public.PUBLIC if rd is None else frozenset(rd)
    return ProvenanceLabel(
        sources=sources,
        readers=readers,
        integrity=IntegrityLevel(payload.get("i", IntegrityLevel.UNTRUSTED)),
        secrecy=SecrecyLevel(payload.get("s", SecrecyLevel.PUBLIC)),
        capacity=InformationCapacity(
            payload.get("cap", InformationCapacity.STRING)
        ),
    )


def _strip_label(value: Any) -> Any:
    """Return the underlying raw value for any wrapper we recognize."""
    if isinstance(value, LabeledValue):
        return value.raw
    return value


def _label_or_none(value: Any) -> ProvenanceLabel | None:
    """Return the label carried on ``value``, or ``None``."""
    if isinstance(value, LabeledValue):
        return value.label
    label = getattr(value, "_label", None)
    if isinstance(label, ProvenanceLabel):
        return label
    return None


def encode(value: Any) -> Any:
    """Recursively encode ``value`` to a JSON-serializable shape
    with per-field ``__tessera_labels__`` sidecars.

    Mapping values get one sidecar at their level; sequences get a
    flat sidecar list under the parent key; bare leaves with labels
    are wrapped into a 2-key envelope ``{"_value": ..., "_label": ...}``
    when they cannot otherwise carry a sidecar (rare; happens only
    when a labeled leaf appears as the root of the encoded tree).

    Callers normally feed :func:`encode` into :func:`json.dumps`
    or :func:`canonical_json`; the encoder does not produce strings
    directly because downstream callers commonly want to inject
    additional fields before serializing.
    """
    return _encode(value)


def _encode(value: Any) -> Any:
    if isinstance(value, dict):
        return _encode_mapping(value)
    if isinstance(value, list | tuple):
        return _encode_sequence(value)
    label = _label_or_none(value)
    raw = _strip_label(value)
    if label is None:
        return raw
    return {
        "_value": _encode(raw) if isinstance(raw, dict | list | tuple) else raw,
        "_label": _label_to_compact(label),
    }


def _encode_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    sidecar: dict[str, Any] = {}
    for key, value in mapping.items():
        if key == SIDECAR_KEY:
            # Caller already provided a sidecar; pass through as-is
            # so round-trip decoding does not lose information.
            out[key] = value
            continue
        label = _label_or_none(value)
        out[key] = _encode(_strip_label(value)) if isinstance(_strip_label(value), dict | list | tuple) else _strip_label(value)
        if label is not None:
            sidecar[key] = _label_to_compact(label)
    if sidecar:
        out[SIDECAR_KEY] = sidecar
    return out


def _encode_sequence(seq: list | tuple) -> list:
    out: list = []
    for item in seq:
        out.append(_encode(item))
    return out


def canonical_json(value: Any) -> str:
    """Serialize ``value`` with stable key ordering and no
    whitespace. Suitable for hashing, signing, or audit-log
    chaining. Mirrors the existing
    :func:`tessera.audit_log.canonical_json` contract
    (``sort_keys=True, separators=(",", ":")``)."""
    return json.dumps(_encode(value), sort_keys=True, separators=(",", ":"))


def decode(payload: dict[str, Any]) -> dict[str, Any]:
    """Inverse of :func:`encode` for a mapping payload.

    Returns a new mapping with labels lifted onto each field's value
    as a :class:`LabeledValue` wrapper. The sidecar field is removed
    from the result. Sequences and nested mappings are decoded
    recursively. Leaves that lack a sidecar entry are returned bare
    (the encoder did not record a label for them).
    """
    if not isinstance(payload, dict):
        raise TypeError(
            f"decode() expected a dict, got {type(payload).__name__}"
        )
    sidecar: dict[str, Any] = payload.get(SIDECAR_KEY, {})
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key == SIDECAR_KEY:
            continue
        decoded_value: Any = value
        if isinstance(value, dict):
            decoded_value = decode(value)
        elif isinstance(value, list):
            decoded_value = [
                decode(item) if isinstance(item, dict) else item for item in value
            ]
        if key in sidecar:
            label = _compact_to_label(sidecar[key])
            out[key] = LabeledValue(raw=decoded_value, label=label)
        else:
            out[key] = decoded_value
    return out


class ProvenanceJSONEncoder(json.JSONEncoder):
    """``json.JSONEncoder`` subclass that emits the ``__tessera_labels__`` sidecar.

    Drop-in replacement for the stdlib ``json.JSONEncoder``. Use it
    via the ``cls=`` argument of :func:`json.dumps` / :func:`json.dump`
    to serialize labeled trees with sidecars at every mapping level.

    Example::

        import json
        from tessera.taint.json_encoder import ProvenanceJSONEncoder

        wire = json.dumps(report, cls=ProvenanceJSONEncoder)

    Round-trip via :func:`decode`::

        from tessera.taint.json_encoder import decode

        revived = decode(json.loads(wire))

    The sidecar shape is wire-compatible with the SEP-1913
    ``attribution`` field. Frozen 2026-04 under Phase 1 wave 1A.
    """

    def encode(self, o: Any) -> str:  # type: ignore[override]
        return json.dumps(
            _encode(o),
            sort_keys=self.sort_keys,
            indent=self.indent,
            separators=(self.item_separator, self.key_separator),
            ensure_ascii=self.ensure_ascii,
        )

    def iterencode(self, o: Any, _one_shot: bool = False):  # type: ignore[override]
        # iterencode is the chunked variant. Delegate to encode() so
        # the sidecar handling stays in one place; for any payload
        # Tessera produces, the size makes a single dump fine.
        yield self.encode(o)


__all__ = [
    "ProvenanceJSONEncoder",
    "SIDECAR_KEY",
    "encode",
    "decode",
    "canonical_json",
]
