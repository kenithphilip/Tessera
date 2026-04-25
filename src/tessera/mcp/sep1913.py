"""SEP-1913 (MCP attribution) compliance + Tessera compat shim.

Wave 4C of the v0.12 to v1.0 plan: ship SEP-1913 compliance with a
compat shim for environments where the upstream SEP-1913 PR has
not yet merged into the MCP spec. Tessera ships the compat shim
permanently because:

- Tessera adopted the SEP-1913 attribution shape early (v0.12),
  superset-style: Tessera annotations always include the
  SEP-1913 keys plus three Tessera-specific extensions
  (``dataClass``, ``actionImpact``, ``tesseraTrustTier``).
- Even after the upstream PR merges, downstream MCP servers may
  emit older annotation shapes for years; the shim translates
  them on the fly.

Reference
---------

- SEP-1913 PR (open as of v1.0 ship; track at
  https://github.com/modelcontextprotocol/specification/pull/1913)
- :mod:`tessera.mcp.manifest_schema` (the Tessera-superset shape)
- ``docs/standards-engagement/sep-1913-comments.md`` (Tessera's
  WG review comments)
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.1
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


# ---------------------------------------------------------------------------
# SEP-1913 canonical key set (the upstream PR shape)
# ---------------------------------------------------------------------------


#: SEP-1913 canonical annotation keys per the open PR. Tessera's
#: schema is a superset; these are the names the upstream draft
#: settles on.
SEP1913_CANONICAL_KEYS: frozenset[str] = frozenset(
    {
        "actionImpact",
        "sensitiveHint",
        "privateHint",
        "openWorldHint",
        "manifestDigest",
    }
)


#: Tessera-only extensions documented in
#: ``docs/standards-engagement/sep-1913-comments.md``: comment 3
#: proposes ``dataClass`` to upstream; comments 4 and 5 keep
#: ``tesseraTrustTier`` as a Tessera-internal additive field.
TESSERA_EXTENSIONS: frozenset[str] = frozenset(
    {
        "dataClass",
        "tesseraTrustTier",
    }
)


class CompatibilityMode(StrEnum):
    """Operator-facing knob for the SEP-1913 compat shim."""

    #: Accept either canonical SEP-1913 OR Tessera-superset shape.
    LENIENT = "lenient"
    #: Require canonical SEP-1913 keys; reject anything else.
    STRICT_SEP1913 = "strict_sep1913"
    #: Require Tessera-superset shape (the v0.12-v0.14 default).
    STRICT_TESSERA = "strict_tessera"


# ---------------------------------------------------------------------------
# Compat shim: normalize annotations to the canonical shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Outcome of normalizing one tool annotation block."""

    annotations: dict[str, Any]
    extensions_seen: tuple[str, ...]
    unknown_keys: tuple[str, ...]
    mode: CompatibilityMode


def normalize_annotations(
    raw: dict[str, Any] | None,
    *,
    mode: CompatibilityMode = CompatibilityMode.LENIENT,
) -> NormalizationResult:
    """Normalize a SEP-1913 (or Tessera-superset) annotation block.

    Args:
        raw: The raw annotation block from a tool entry. ``None``
            is treated as an empty annotation block.
        mode: Compatibility mode. ``LENIENT`` (default) accepts
            both canonical and superset shapes; ``STRICT_SEP1913``
            rejects extension keys; ``STRICT_TESSERA`` requires
            extension keys.

    Returns:
        :class:`NormalizationResult` with the canonical
        annotation dict (extensions split out for inspection),
        the list of Tessera extensions present, and any unknown
        keys the shim could not classify.

    Raises:
        ValueError: When ``mode`` is ``STRICT_SEP1913`` and a
            Tessera extension is present, or when ``mode`` is
            ``STRICT_TESSERA`` and an extension is absent, or
            when an unknown key is present in any strict mode.
    """
    annotations = dict(raw or {})
    extensions: list[str] = []
    unknown: list[str] = []
    canonical_out: dict[str, Any] = {}

    for key, value in annotations.items():
        if key in SEP1913_CANONICAL_KEYS:
            canonical_out[key] = value
        elif key in TESSERA_EXTENSIONS:
            extensions.append(key)
            canonical_out[key] = value
        else:
            unknown.append(key)
            canonical_out[key] = value

    if mode == CompatibilityMode.STRICT_SEP1913 and extensions:
        raise ValueError(
            f"strict SEP-1913 mode rejects Tessera extensions: {extensions!r}"
        )
    if mode == CompatibilityMode.STRICT_TESSERA and not extensions:
        raise ValueError(
            "strict Tessera mode requires at least one extension key "
            f"(one of {sorted(TESSERA_EXTENSIONS)!r})"
        )
    if mode != CompatibilityMode.LENIENT and unknown:
        raise ValueError(
            f"strict mode {mode.value!r} rejects unknown annotation keys: {unknown!r}"
        )

    return NormalizationResult(
        annotations=canonical_out,
        extensions_seen=tuple(sorted(extensions)),
        unknown_keys=tuple(sorted(unknown)),
        mode=mode,
    )


def to_canonical_sep1913(
    annotations: dict[str, Any] | None,
) -> dict[str, Any]:
    """Strip Tessera extensions and return ONLY the SEP-1913 canonical keys.

    Use this before forwarding a manifest to a non-Tessera consumer
    that may not understand the Tessera-superset shape. The
    Tessera-internal extensions (``dataClass``, ``tesseraTrustTier``)
    are not exposed.
    """
    if not annotations:
        return {}
    return {k: v for k, v in annotations.items() if k in SEP1913_CANONICAL_KEYS}


def to_tessera_superset(
    annotations: dict[str, Any] | None,
    *,
    default_data_class: str | None = None,
    default_trust_tier: str | None = None,
) -> dict[str, Any]:
    """Promote a canonical SEP-1913 annotation block to the Tessera superset.

    Useful when consuming a manifest from an upstream that has only
    the canonical keys; default values let the operator backfill
    the Tessera-only extensions per server.
    """
    if not annotations:
        annotations = {}
    out = dict(annotations)
    if default_data_class is not None and "dataClass" not in out:
        out["dataClass"] = default_data_class
    if default_trust_tier is not None and "tesseraTrustTier" not in out:
        out["tesseraTrustTier"] = default_trust_tier
    return out


__all__ = [
    "CompatibilityMode",
    "NormalizationResult",
    "SEP1913_CANONICAL_KEYS",
    "TESSERA_EXTENSIONS",
    "normalize_annotations",
    "to_canonical_sep1913",
    "to_tessera_superset",
]
