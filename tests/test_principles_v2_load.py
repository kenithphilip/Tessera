"""Tests for principles v2 YAML loading and version-switch behavior.

Validates:
- v2.yaml parses without error
- Exactly 20 principles are present
- Each principle carries all required fields
- P01-P06 ids and ASI codes are preserved from v1
- TESSERA_PRINCIPLES_VERSION=2 loads v2 instead of v1
"""

from __future__ import annotations

import os

import pytest

from tessera.action_critic.principles import PrincipleSpec, load_principles

# Expected fields for completeness check.
_REQUIRED_FIELDS = ("id", "description", "asi_codes", "atlas_codes", "rationale")

# P01-P06 ids and their ASI codes as declared in v1.yaml (must be unchanged in v2).
_V1_PRESERVED: dict[str, tuple[str, ...]] = {
    "data_minimization": ("ASI-02", "ASI-07"),
    "origin_consistency": ("ASI-01", "ASI-04"),
    "irreversibility": ("ASI-03", "ASI-04"),
    "least_privilege": ("ASI-04", "ASI-10"),
    "no_exfiltration": ("ASI-02", "ASI-07"),
    "untrusted_arg_reasonable": ("ASI-01", "ASI-09"),
}


@pytest.fixture(scope="module")
def v2() -> list[PrincipleSpec]:
    return load_principles(version=2)


def test_v2_loads(v2: list[PrincipleSpec]) -> None:
    assert v2, "v2.yaml returned an empty list"


def test_v2_has_twenty_principles(v2: list[PrincipleSpec]) -> None:
    assert len(v2) == 20, f"Expected 20 principles; got {len(v2)}"


def test_v2_all_fields_present(v2: list[PrincipleSpec]) -> None:
    for spec in v2:
        assert spec.id, f"Principle missing id: {spec}"
        assert spec.description, f"Principle '{spec.id}' missing description"
        assert spec.asi_codes, f"Principle '{spec.id}' missing asi_codes"
        assert spec.atlas_codes, f"Principle '{spec.id}' missing atlas_codes"
        assert spec.rationale, f"Principle '{spec.id}' missing rationale"


def test_v2_preserves_v1_ids(v2: list[PrincipleSpec]) -> None:
    ids = {s.id for s in v2}
    for expected_id in _V1_PRESERVED:
        assert expected_id in ids, f"v1 principle '{expected_id}' missing from v2"


def test_v2_preserves_v1_asi_codes(v2: list[PrincipleSpec]) -> None:
    by_id = {s.id: s for s in v2}
    for pid, expected_codes in _V1_PRESERVED.items():
        spec = by_id[pid]
        for code in expected_codes:
            assert code in spec.asi_codes, (
                f"Principle '{pid}': expected ASI code '{code}' "
                f"not found in {spec.asi_codes}"
            )


def test_env_version_2_loads_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TESSERA_PRINCIPLES_VERSION", "2")
    specs = load_principles()
    assert len(specs) == 20


def test_env_version_1_loads_v1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TESSERA_PRINCIPLES_VERSION", "1")
    specs = load_principles()
    assert len(specs) == 6


def test_env_version_default_is_v1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TESSERA_PRINCIPLES_VERSION", raising=False)
    specs = load_principles()
    assert len(specs) == 6


def test_v2_ids_are_unique(v2: list[PrincipleSpec]) -> None:
    ids = [s.id for s in v2]
    assert len(ids) == len(set(ids)), "Duplicate principle ids in v2.yaml"
