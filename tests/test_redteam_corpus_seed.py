"""Validates the tessera-redteam-corpus seed files.

Checks:
- All expected probe JSONL files exist under corpus/probes/.
- Every line in each file parses as JSON.
- Every entry validates against the probe_v1 schema.
- Total seed count is >= 200.
- No duplicate probe_id across all files.
- Each category appears at least 5 times.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent
_PROBES_DIR = _REPO_ROOT / "corpus" / "probes"
_SCHEMA_PATH = _REPO_ROOT / "corpus" / "schema" / "probe_v1.json"

_REQUIRED_FILES = [
    "lakera_gandalf.jsonl",
    "tensor_trust.jsonl",
    "agentdojo_seed.jsonl",
]

_VALID_CATEGORIES = {
    "prompt_injection",
    "exfil",
    "jailbreak",
    "tool_description_injection",
    "url_manipulation",
}

_VALID_OUTCOMES = {"refuse", "block", "sanitize"}

# UUID v4 with optional EXAMPLE_ prefix.
_PROBE_ID_RE = re.compile(
    r"^(EXAMPLE_)?[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# v1.0 Phase 4 wave 4F target: >= 1000 raw payloads (the v2026.Q4
# release). The dedup tool collapses near-duplicates; the raw
# count is what the spec measures.
_MIN_TOTAL = 1000
_MIN_PER_CATEGORY = 5


def _load_all_probes() -> list[dict]:
    """Load every probe from all JSONL files under corpus/probes/."""
    probes: list[dict] = []
    for path in sorted(_PROBES_DIR.glob("*.jsonl")):
        for raw in path.read_text().splitlines():
            raw = raw.strip()
            if raw:
                probes.append(json.loads(raw))
    return probes


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", _REQUIRED_FILES)
def test_probe_file_exists(filename: str) -> None:
    """Each required probe JSONL file must exist."""
    assert (_PROBES_DIR / filename).is_file(), f"Missing: corpus/probes/{filename}"


def test_schema_file_exists() -> None:
    """The probe_v1 JSON Schema must exist."""
    assert _SCHEMA_PATH.is_file(), "Missing: corpus/schema/probe_v1.json"


# ---------------------------------------------------------------------------
# Parse validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("filename", _REQUIRED_FILES)
def test_all_lines_parse_as_json(filename: str) -> None:
    """Every non-empty line in a probe file must be valid JSON."""
    path = _PROBES_DIR / filename
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            json.loads(raw)
        except json.JSONDecodeError as exc:
            pytest.fail(f"{filename}:{lineno}: invalid JSON: {exc}")


# ---------------------------------------------------------------------------
# Schema field validation
# ---------------------------------------------------------------------------


def _validate_probe(probe: dict, location: str) -> None:
    required = {"probe_id", "category", "payload", "expected_outcome", "source", "license", "submitted_at"}
    missing = required - probe.keys()
    assert not missing, f"{location}: missing fields {missing}"

    assert _PROBE_ID_RE.match(probe["probe_id"]), (
        f"{location}: invalid probe_id {probe['probe_id']!r}"
    )
    assert probe["category"] in _VALID_CATEGORIES, (
        f"{location}: unknown category {probe['category']!r}"
    )
    assert isinstance(probe["payload"], str) and probe["payload"], (
        f"{location}: payload must be a non-empty string"
    )
    assert probe["expected_outcome"] in _VALID_OUTCOMES, (
        f"{location}: unknown expected_outcome {probe['expected_outcome']!r}"
    )
    assert isinstance(probe["source"], str) and probe["source"], (
        f"{location}: source must be a non-empty string"
    )
    assert isinstance(probe["license"], str) and probe["license"], (
        f"{location}: license must be a non-empty string"
    )
    assert _DATE_RE.match(probe["submitted_at"]), (
        f"{location}: submitted_at must be YYYY-MM-DD, got {probe['submitted_at']!r}"
    )


@pytest.mark.parametrize("filename", _REQUIRED_FILES)
def test_all_entries_match_schema(filename: str) -> None:
    """Every probe entry must satisfy the probe_v1 field contract."""
    path = _PROBES_DIR / filename
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        probe = json.loads(raw)
        _validate_probe(probe, location=f"{filename}:{lineno}")


# ---------------------------------------------------------------------------
# Aggregate checks
# ---------------------------------------------------------------------------


def test_total_seed_count_at_least_200() -> None:
    """The combined seed corpus must have at least 200 probes."""
    probes = _load_all_probes()
    assert len(probes) >= _MIN_TOTAL, (
        f"Expected >= {_MIN_TOTAL} probes, found {len(probes)}"
    )


def test_no_duplicate_probe_ids() -> None:
    """probe_id must be unique across all probe files."""
    seen: dict[str, str] = {}
    for path in sorted(_PROBES_DIR.glob("*.jsonl")):
        for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
            raw = raw.strip()
            if not raw:
                continue
            probe = json.loads(raw)
            pid = probe.get("probe_id", "")
            location = f"{path.name}:{lineno}"
            assert pid not in seen, (
                f"Duplicate probe_id {pid!r} at {location} (first seen at {seen[pid]})"
            )
            seen[pid] = location


def test_each_category_appears_at_least_5_times() -> None:
    """Every category must have at least 5 probes in the combined corpus."""
    probes = _load_all_probes()
    counts: dict[str, int] = {cat: 0 for cat in _VALID_CATEGORIES}
    for probe in probes:
        cat = probe.get("category", "")
        if cat in counts:
            counts[cat] += 1

    for cat, count in counts.items():
        assert count >= _MIN_PER_CATEGORY, (
            f"Category {cat!r} has only {count} probe(s), need >= {_MIN_PER_CATEGORY}"
        )
