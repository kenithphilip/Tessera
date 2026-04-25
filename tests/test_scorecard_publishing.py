"""Tests for Wave 3E: scorecard static site publishing artifacts.

Verifies that all static publishing prerequisites are structurally sound
without requiring Hugo, a network connection, or a GitHub Actions runner:

- Hugo config.toml parses as valid TOML with required fields.
- sample.intoto.jsonl validates against the in-toto Statement v1 schema.
- The badge partial exists and contains SVG markup.
- The publish workflow YAML parses and has required keys.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml  # PyYAML; available via the test dependencies

REPO = Path(__file__).resolve().parents[1]
SCORECARD = REPO / "docs" / "scorecard"
WORKFLOWS = REPO / ".github" / "workflows"
SAMPLE_ATTESTATION = SCORECARD / "static" / "sample.intoto.jsonl"


# ---------------------------------------------------------------------------
# Hugo config
# ---------------------------------------------------------------------------


def test_hugo_config_exists() -> None:
    assert (SCORECARD / "config.toml").exists()


def test_hugo_config_parses() -> None:
    # Use tomllib (stdlib 3.11+) so no extra dependency is needed.
    import tomllib

    data = tomllib.loads((SCORECARD / "config.toml").read_text(encoding="utf-8"))
    assert data.get("baseURL") == "https://tessera-ai.github.io/scorecard/"
    assert data.get("title") == "Tessera Scorecards"


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------


def test_index_content_exists() -> None:
    index = SCORECARD / "content" / "_index.md"
    assert index.exists()
    text = index.read_text(encoding="utf-8")
    assert "Tessera Scorecards" in text


# ---------------------------------------------------------------------------
# Badge partial
# ---------------------------------------------------------------------------


def test_badge_partial_exists() -> None:
    badge = SCORECARD / "layouts" / "partials" / "badge.html"
    assert badge.exists()


def test_badge_partial_contains_svg() -> None:
    badge = SCORECARD / "layouts" / "partials" / "badge.html"
    text = badge.read_text(encoding="utf-8")
    assert "<svg" in text
    assert "</svg>" in text


# ---------------------------------------------------------------------------
# single.html template
# ---------------------------------------------------------------------------


def test_single_template_exists() -> None:
    single = SCORECARD / "layouts" / "_default" / "single.html"
    assert single.exists()


def test_single_template_has_compliance_section() -> None:
    single = SCORECARD / "layouts" / "_default" / "single.html"
    text = single.read_text(encoding="utf-8")
    assert "compliance_taxonomies" in text
    assert "mcp_security_score" in text
    assert "benchmarks" in text


# ---------------------------------------------------------------------------
# sample.intoto.jsonl
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not SAMPLE_ATTESTATION.exists(),
    reason="sample.intoto.jsonl not yet generated; run 'tessera bench emit-scorecard'",
)
def test_sample_attestation_is_valid_jsonl() -> None:
    lines = [
        ln
        for ln in SAMPLE_ATTESTATION.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert lines, "sample.intoto.jsonl must contain at least one line"
    # Each non-empty line must be valid JSON.
    for ln in lines:
        data = json.loads(ln)
        assert isinstance(data, dict)


@pytest.mark.skipif(
    not SAMPLE_ATTESTATION.exists(),
    reason="sample.intoto.jsonl not yet generated; run 'tessera bench emit-scorecard'",
)
def test_sample_attestation_statement_type() -> None:
    first_line = next(
        ln
        for ln in SAMPLE_ATTESTATION.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    )
    data = json.loads(first_line)
    assert data.get("_type") == "https://in-toto.io/Statement/v1"
    assert data.get("predicateType") == "https://tessera.dev/security-attestation/v1"


@pytest.mark.skipif(
    not SAMPLE_ATTESTATION.exists(),
    reason="sample.intoto.jsonl not yet generated; run 'tessera bench emit-scorecard'",
)
def test_sample_attestation_predicate_fields() -> None:
    first_line = next(
        ln
        for ln in SAMPLE_ATTESTATION.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    )
    predicate = json.loads(first_line)["predicate"]
    assert "tessera_version" in predicate
    assert "generated_at" in predicate
    assert "compliance_taxonomies" in predicate
    assert "audit_summary" in predicate


# ---------------------------------------------------------------------------
# Publish workflow
# ---------------------------------------------------------------------------


def test_publish_workflow_exists() -> None:
    assert (WORKFLOWS / "publish-scorecard.yml").exists()


def test_publish_workflow_parses() -> None:
    data = yaml.safe_load(
        (WORKFLOWS / "publish-scorecard.yml").read_text(encoding="utf-8")
    )
    assert isinstance(data, dict)


def test_publish_workflow_triggers_on_tags() -> None:
    data = yaml.safe_load(
        (WORKFLOWS / "publish-scorecard.yml").read_text(encoding="utf-8")
    )
    on = data.get("on", data.get(True, {}))  # YAML parses 'on' as True
    assert "push" in on
    assert "tags" in on["push"]


def test_publish_workflow_has_required_steps() -> None:
    data = yaml.safe_load(
        (WORKFLOWS / "publish-scorecard.yml").read_text(encoding="utf-8")
    )
    jobs = data.get("jobs", {})
    assert "publish" in jobs
    steps = jobs["publish"].get("steps", [])
    step_names = [s.get("name", "") for s in steps]
    # Attestation emission and Hugo build are the critical steps.
    assert any("emit" in n.lower() or "scorecard" in n.lower() for n in step_names)
    assert any("hugo" in n.lower() for n in step_names)
