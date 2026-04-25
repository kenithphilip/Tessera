"""Tests for the Wave 2G Security Attestation emitter, signer, and CLI.

Covers:
- ScorecardEmitter.build() returns all required top-level fields.
- emit() writes valid JSON-lines that round-trip through json.loads.
- sign(method="hmac") produces a verifiable envelope.
- verify() returns False when the envelope is tampered.
- JSON-Schema validates a sample attestation via jsonschema.
- CLI emit-scorecard --out=... writes a file and exits 0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tessera.evaluate.scorecard.emitter import (
    PREDICATE_TYPE,
    STATEMENT_TYPE,
    ScorecardEmitter,
)
from tessera.evaluate.scorecard.sign import sign, verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_emitter(**kwargs) -> ScorecardEmitter:
    return ScorecardEmitter(version="0.12.0-test", **kwargs)


# ---------------------------------------------------------------------------
# Schema loading helper
# ---------------------------------------------------------------------------


def _load_schema() -> dict:
    schema_path = (
        Path(__file__).parent.parent
        / "src/tessera/evaluate/scorecard/schema/security_attestation_v1.yaml"
    )
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        pytest.skip("pyyaml not installed; skipping schema validation test")
    return yaml.safe_load(schema_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# emitter.build()
# ---------------------------------------------------------------------------


def test_build_returns_required_top_level_fields():
    attestation = _make_emitter().build()
    assert attestation["_type"] == STATEMENT_TYPE
    assert attestation["predicateType"] == PREDICATE_TYPE
    assert isinstance(attestation["subject"], list)
    assert len(attestation["subject"]) >= 1
    predicate = attestation["predicate"]
    assert predicate["tessera_version"] == "0.12.0-test"
    assert "attestation_id" in predicate
    assert "generated_at" in predicate
    assert isinstance(predicate["claims"], list)
    assert isinstance(predicate["benchmarks"], dict)
    assert isinstance(predicate["mcp_security_score"], dict)
    assert isinstance(predicate["audit_summary"], dict)
    assert isinstance(predicate["compliance_taxonomies"], dict)
    assert isinstance(predicate["principles_revision"], int)


def test_build_audit_summary_defaults_to_genesis():
    predicate = _make_emitter().build()["predicate"]
    summary = predicate["audit_summary"]
    assert summary["sequence_count"] == 0
    assert summary["hash_chain_root"] == "0" * 64
    assert summary["event_counts_by_kind"] == {}


def test_build_compliance_taxonomies_all_eight_covered():
    taxonomies = _make_emitter().build()["predicate"]["compliance_taxonomies"]
    expected = {
        "NIST_CSF",
        "CWE",
        "OWASP_ASI",
        "MITRE_ATLAS",
        "EU_AI_Act",
        "ISO_42001",
        "CSA_AICM",
        "NIST_AI_600_1",
    }
    assert set(taxonomies.keys()) == expected
    for name, entry in taxonomies.items():
        assert entry["covered"] is True, f"{name} should be covered=True"


def test_build_with_scanner_report(tmp_path):
    report = tmp_path / "scanner.json"
    report.write_text(
        json.dumps({"precision": 0.9, "recall": 0.85, "f1": 0.87, "roc_auc": 0.93}),
        encoding="utf-8",
    )
    emitter = _make_emitter(scanner_report_path=report)
    benchmarks = emitter.build()["predicate"]["benchmarks"]
    assert "scanner_eval" in benchmarks
    assert benchmarks["scanner_eval"]["precision"] == pytest.approx(0.9)


def test_build_with_benchmark_run(tmp_path):
    run = tmp_path / "agentdojo.json"
    run.write_text(
        json.dumps(
            {
                "suite": "agentdojo",
                "utility_accuracy": 0.82,
                "attack_success_rate": 0.04,
                "run_id": "test-run-001",
            }
        ),
        encoding="utf-8",
    )
    emitter = _make_emitter(benchmark_runs=[run])
    benchmarks = emitter.build()["predicate"]["benchmarks"]
    assert benchmarks["agentdojo"]["utility_accuracy"] == pytest.approx(0.82)
    assert benchmarks["agentdojo"]["attack_success_rate"] == pytest.approx(0.04)


def test_build_missing_benchmark_file_is_not_an_error(tmp_path):
    missing = tmp_path / "nonexistent.json"
    emitter = _make_emitter(benchmark_runs=[missing])
    attestation = emitter.build()
    assert attestation["predicate"]["benchmarks"] == {}


# ---------------------------------------------------------------------------
# emit()
# ---------------------------------------------------------------------------


def test_emit_writes_valid_jsonl(tmp_path):
    out = tmp_path / "attestation.intoto.jsonl"
    emitter = _make_emitter()
    result_path = emitter.emit(out)
    assert result_path.exists()
    lines = [l for l in result_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["_type"] == STATEMENT_TYPE


def test_emit_round_trips_through_json_loads(tmp_path):
    out = tmp_path / "round_trip.intoto.jsonl"
    emitter = _make_emitter()
    original = emitter.build()
    emitter.emit(out)
    line = out.read_text(encoding="utf-8").strip()
    recovered = json.loads(line)
    # attestation_id is fresh each build(), so compare structurally.
    assert recovered["predicateType"] == original["predicateType"]
    assert recovered["predicate"]["tessera_version"] == original["predicate"]["tessera_version"]
    assert recovered["predicate"]["compliance_taxonomies"] == original["predicate"]["compliance_taxonomies"]


def test_emit_creates_parent_directory(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "out.intoto.jsonl"
    _make_emitter().emit(deep)
    assert deep.exists()


# ---------------------------------------------------------------------------
# sign() / verify() with HMAC
# ---------------------------------------------------------------------------


def test_hmac_sign_produces_dsse_shaped_envelope(tmp_path):
    out = tmp_path / "attest.intoto.jsonl"
    _make_emitter().emit(out)
    envelope_path = sign(out, signing_method="hmac")
    assert envelope_path.exists()
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert "payload" in envelope
    assert "payloadType" in envelope
    assert "signatures" in envelope
    assert envelope["signing_method"] == "hmac"
    assert len(envelope["signatures"]) == 1


def test_hmac_verify_returns_true_for_valid_envelope(tmp_path):
    out = tmp_path / "attest.intoto.jsonl"
    _make_emitter().emit(out)
    envelope_path = sign(out, signing_method="hmac")
    assert verify(envelope_path) is True


def test_hmac_verify_returns_false_when_tampered(tmp_path):
    out = tmp_path / "attest.intoto.jsonl"
    _make_emitter().emit(out)
    envelope_path = sign(out, signing_method="hmac")

    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    # Corrupt the signature: flip the last character.
    orig_sig = envelope["signatures"][0]["sig"]
    tampered = orig_sig[:-1] + ("A" if orig_sig[-1] != "A" else "B")
    envelope["signatures"][0]["sig"] = tampered
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")

    assert verify(envelope_path) is False


def test_verify_returns_false_for_missing_file(tmp_path):
    assert verify(tmp_path / "nonexistent.dsse.json") is False


def test_verify_returns_false_for_malformed_envelope(tmp_path):
    bad = tmp_path / "bad.dsse.json"
    bad.write_text("{not json at all ...", encoding="utf-8")
    assert verify(bad) is False


# ---------------------------------------------------------------------------
# JSON-Schema validation
# ---------------------------------------------------------------------------


def test_schema_validates_sample_attestation():
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed; skipping schema validation")

    schema = _load_schema()
    attestation = _make_emitter().build()
    # Should not raise.
    jsonschema.validate(instance=attestation, schema=schema)


def test_schema_rejects_missing_predicate_type():
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed; skipping schema validation")

    schema = _load_schema()
    attestation = _make_emitter().build()
    del attestation["predicateType"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=attestation, schema=schema)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_emit_scorecard_writes_file_and_exits_zero(tmp_path):
    out = tmp_path / "cli_out.intoto.jsonl"
    from tessera.evaluate.cli import main

    rc = main(["emit-scorecard", "--out", str(out), "--sign", "none"])
    assert rc == 0
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8").strip())
    assert data["_type"] == STATEMENT_TYPE


def test_cli_emit_scorecard_with_hmac_sign_creates_envelope(tmp_path):
    out = tmp_path / "signed_out.intoto.jsonl"
    from tessera.evaluate.cli import main

    rc = main(["emit-scorecard", "--out", str(out), "--sign", "hmac"])
    assert rc == 0
    envelope = out.with_suffix(".dsse.json")
    assert envelope.exists()
    assert verify(envelope) is True


def test_cli_emit_scorecard_with_version_flag(tmp_path):
    out = tmp_path / "versioned.intoto.jsonl"
    from tessera.evaluate.cli import main

    rc = main(["emit-scorecard", "--out", str(out), "--version", "1.2.3"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8").strip())
    assert data["predicate"]["tessera_version"] == "1.2.3"


def test_attestation_embeds_atlas_navigator_reference() -> None:
    """Wave 2M audit: the ATLAS Navigator layer reference must
    appear in every attestation predicate."""
    from tessera.evaluate.scorecard.emitter import ScorecardEmitter

    attestation = ScorecardEmitter(version="0.13.1").build()
    layer = attestation["predicate"]["mitre_atlas_navigator_layer"]
    assert layer["schema_version"] == "tessera.atlas_navigator.v1"
    assert "atlas_navigator_layer.json" in layer["relative_path"]
    # technique_count is loaded from the static layer file when present.
    assert isinstance(layer["technique_count"], int)


# ---------------------------------------------------------------------------
# Wave 4E: paired-model scorecards
# ---------------------------------------------------------------------------


def test_paired_model_predicate_and_subject_suffix() -> None:
    from tessera.evaluate.scorecard.emitter import ScorecardEmitter

    attestation = ScorecardEmitter(
        version="1.0.0", paired_model="claude-sonnet-4.5"
    ).build()
    assert attestation["predicate"]["paired_model"] == "claude-sonnet-4.5"
    subject_name = attestation["subject"][0]["name"]
    assert "+claude-sonnet-4.5" in subject_name


def test_paired_model_omitted_when_not_set() -> None:
    from tessera.evaluate.scorecard.emitter import ScorecardEmitter

    attestation = ScorecardEmitter(version="1.0.0").build()
    assert "paired_model" not in attestation["predicate"]


def test_cli_paired_model_flag(tmp_path) -> None:
    from tessera.evaluate.cli import main

    out = tmp_path / "paired.intoto.jsonl"
    rc = main(["emit-scorecard", "--out", str(out), "--paired-model", "gpt-5"])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8").strip())
    assert data["predicate"]["paired_model"] == "gpt-5"
    assert "+gpt-5" in data["subject"][0]["name"]
