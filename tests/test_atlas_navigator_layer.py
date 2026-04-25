"""Tests for the MITRE ATLAS Navigator layer (Wave 2M)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tessera.compliance import MITRE_ATLAS

LAYER_PATH = (
    Path(__file__).parent.parent / "docs" / "security" / "atlas_navigator_layer.json"
)


@pytest.fixture(scope="module")
def layer() -> dict:  # type: ignore[type-arg]
    return json.loads(LAYER_PATH.read_text())


def test_layer_file_parses(layer: dict) -> None:  # type: ignore[type-arg]
    assert isinstance(layer, dict)


def test_layer_references_tessera(layer: dict) -> None:  # type: ignore[type-arg]
    text = json.dumps(layer)
    assert "Tessera" in text


def test_layer_schema_version(layer: dict) -> None:  # type: ignore[type-arg]
    versions = layer.get("versions", {})
    assert versions.get("layer") == "4.5", "Navigator layer version must be 4.5"
    assert versions.get("navigator") == "4.9"


def test_all_atlas_techniques_present(layer: dict) -> None:  # type: ignore[type-arg]
    """Every AML.T* code in MITRE_ATLAS must appear in the layer."""
    required: set[str] = set()
    for techniques in MITRE_ATLAS.values():
        required.update(techniques)

    layer_ids = {t["techniqueID"] for t in layer.get("techniques", [])}

    missing = required - layer_ids
    assert not missing, f"Missing from layer: {sorted(missing)}"


def test_every_layer_technique_has_score_100(layer: dict) -> None:  # type: ignore[type-arg]
    for t in layer.get("techniques", []):
        assert t.get("score") == 100, f"{t['techniqueID']} score != 100"


def test_every_layer_technique_has_comment(layer: dict) -> None:  # type: ignore[type-arg]
    for t in layer.get("techniques", []):
        assert t.get("comment"), f"{t['techniqueID']} has no comment"


def test_domain_is_atlas(layer: dict) -> None:  # type: ignore[type-arg]
    assert layer.get("domain") == "ATLAS"
