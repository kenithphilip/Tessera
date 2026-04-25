"""Wave 4C tests: SEP-1913 compliance + compat shim."""

from __future__ import annotations

import pytest

from tessera.mcp.sep1913 import (
    CompatibilityMode,
    SEP1913_CANONICAL_KEYS,
    TESSERA_EXTENSIONS,
    normalize_annotations,
    to_canonical_sep1913,
    to_tessera_superset,
)


# --- Canonical key set ------------------------------------------------------


def test_sep1913_canonical_keys_match_spec() -> None:
    expected = {
        "actionImpact",
        "sensitiveHint",
        "privateHint",
        "openWorldHint",
        "manifestDigest",
    }
    assert SEP1913_CANONICAL_KEYS == frozenset(expected)


def test_tessera_extensions_disjoint_from_canonical() -> None:
    assert SEP1913_CANONICAL_KEYS.isdisjoint(TESSERA_EXTENSIONS)


# --- Lenient normalization --------------------------------------------------


def test_lenient_accepts_canonical_only() -> None:
    raw = {
        "actionImpact": "destructive",
        "sensitiveHint": "high",
        "privateHint": True,
    }
    result = normalize_annotations(raw)
    assert result.extensions_seen == ()
    assert result.unknown_keys == ()
    assert result.annotations == raw


def test_lenient_accepts_tessera_superset() -> None:
    raw = {
        "actionImpact": "side-effect",
        "openWorldHint": False,
        "dataClass": "internal",
        "tesseraTrustTier": "verified",
    }
    result = normalize_annotations(raw)
    assert "dataClass" in result.extensions_seen
    assert "tesseraTrustTier" in result.extensions_seen
    assert result.unknown_keys == ()


def test_lenient_passes_unknown_keys() -> None:
    raw = {"actionImpact": "benign", "unknownExperimental": "x"}
    result = normalize_annotations(raw)
    assert result.unknown_keys == ("unknownExperimental",)
    assert result.annotations["unknownExperimental"] == "x"


def test_normalize_handles_none() -> None:
    result = normalize_annotations(None)
    assert result.annotations == {}
    assert result.extensions_seen == ()


# --- Strict SEP-1913 mode ---------------------------------------------------


def test_strict_sep1913_rejects_extensions() -> None:
    with pytest.raises(ValueError, match="extensions"):
        normalize_annotations(
            {"actionImpact": "benign", "dataClass": "internal"},
            mode=CompatibilityMode.STRICT_SEP1913,
        )


def test_strict_sep1913_rejects_unknown_keys() -> None:
    with pytest.raises(ValueError, match="unknown"):
        normalize_annotations(
            {"actionImpact": "benign", "experimental": "x"},
            mode=CompatibilityMode.STRICT_SEP1913,
        )


def test_strict_sep1913_accepts_canonical_only() -> None:
    raw = {
        "actionImpact": "benign",
        "sensitiveHint": "low",
    }
    result = normalize_annotations(raw, mode=CompatibilityMode.STRICT_SEP1913)
    assert result.annotations == raw


# --- Strict Tessera mode ----------------------------------------------------


def test_strict_tessera_requires_extensions() -> None:
    with pytest.raises(ValueError, match="requires at least one extension"):
        normalize_annotations(
            {"actionImpact": "benign"},
            mode=CompatibilityMode.STRICT_TESSERA,
        )


def test_strict_tessera_accepts_with_extensions() -> None:
    raw = {
        "actionImpact": "benign",
        "tesseraTrustTier": "attested",
    }
    result = normalize_annotations(raw, mode=CompatibilityMode.STRICT_TESSERA)
    assert "tesseraTrustTier" in result.extensions_seen


# --- Conversion helpers -----------------------------------------------------


def test_to_canonical_drops_extensions() -> None:
    raw = {
        "actionImpact": "destructive",
        "dataClass": "confidential",
        "tesseraTrustTier": "attested",
    }
    canonical = to_canonical_sep1913(raw)
    assert "dataClass" not in canonical
    assert "tesseraTrustTier" not in canonical
    assert canonical["actionImpact"] == "destructive"


def test_to_canonical_handles_none() -> None:
    assert to_canonical_sep1913(None) == {}


def test_to_tessera_backfills_defaults() -> None:
    raw = {"actionImpact": "benign"}
    upgraded = to_tessera_superset(
        raw,
        default_data_class="internal",
        default_trust_tier="verified",
    )
    assert upgraded["dataClass"] == "internal"
    assert upgraded["tesseraTrustTier"] == "verified"


def test_to_tessera_preserves_existing_extensions() -> None:
    raw = {"actionImpact": "benign", "dataClass": "confidential"}
    upgraded = to_tessera_superset(
        raw, default_data_class="internal"
    )
    # Existing dataClass NOT overwritten by the default.
    assert upgraded["dataClass"] == "confidential"
