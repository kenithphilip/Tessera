"""Tests for the ``python -m tessera.redteam`` CLI surface."""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from tessera.redteam.cli import main


def _capture(*argv: str) -> tuple[int, str]:
    """Run main(argv) and return (exit_code, stdout)."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(list(argv))
    return rc, buf.getvalue()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_command_prints_corpora_and_counts(capsys):
    rc = main(["list"])
    out, _ = capsys.readouterr()
    assert rc == 0
    assert "tensor_trust" in out
    assert "lakera_gandalf" in out
    # Per-corpus probe count present.
    assert "probes" in out


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


def test_show_command_prints_head(capsys):
    rc = main(["show", "tensor_trust", "--head", "2"])
    out, _ = capsys.readouterr()
    assert rc == 0
    assert "tensor_trust" in out
    # Two probe lines (start with a 2-space indent + bracket).
    probe_lines = [l for l in out.splitlines() if l.startswith("  [")]
    assert len(probe_lines) == 2


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_writes_json_report_with_all_keys(tmp_path, capsys):
    out_file = tmp_path / "report.json"
    rc = main(
        [
            "run",
            "--corpus", "tensor_trust",
            "--scanner", "tessera.scanners.heuristic.injection_score",
            "--threshold", "0.5",
            "--output", str(out_file),
        ]
    )
    assert rc == 0
    assert out_file.exists()
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    for key in ("scanner", "threshold", "total", "precision", "recall", "f1",
                "per_category", "elapsed_seconds", "corpus"):
        assert key in payload
    assert payload["corpus"] == "tensor_trust"
    assert payload["total"] >= 1


def test_run_to_stdout_when_no_output(capsys):
    rc = main(
        [
            "run",
            "--corpus", "tensor_trust",
            "--scanner", "tessera.scanners.heuristic.injection_score",
            "--threshold", "0.5",
        ]
    )
    out, err = capsys.readouterr()
    assert rc == 0
    payload = json.loads(out)
    assert payload["scanner"].endswith("injection_score")


def test_run_with_invalid_scanner_returns_2(capsys):
    rc = main(
        [
            "run",
            "--corpus", "tensor_trust",
            "--scanner", "tessera.does_not_exist_12345.nope",
        ]
    )
    out, err = capsys.readouterr()
    assert rc == 2
    assert "error resolving scanner" in err


# ---------------------------------------------------------------------------
# reproduce
# ---------------------------------------------------------------------------


def test_reproduce_against_attestation_with_no_recorded_metrics(tmp_path, capsys):
    """A v1.0.0-style attestation with empty benchmarks{} block must
    still produce a reproduction report (with before=None, diff=None)."""
    attest = tmp_path / "stub.intoto.jsonl"
    attest.write_text(
        json.dumps(
            {
                "predicate": {
                    "attestation_id": "stub-id",
                    "tessera_version": "1.0.0",
                    "benchmarks": {},
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    rc = main(
        [
            "reproduce",
            "--attestation", str(attest),
            "--corpus", "tensor_trust",
            "--scanner", "tessera.scanners.heuristic.injection_score",
        ]
    )
    out, err = capsys.readouterr()
    assert rc == 0
    payload = json.loads(out)
    assert payload["attestation_id"] == "stub-id"
    assert payload["recorded"]["precision"] is None
    assert isinstance(payload["reproduced"]["precision"], float)
    assert payload["delta"]["precision"]["before"] is None
    assert payload["delta"]["precision"]["after"] is not None
    assert payload["delta"]["precision"]["diff"] is None


def test_reproduce_against_attestation_with_recorded_metrics(tmp_path, capsys):
    attest = tmp_path / "real.intoto.jsonl"
    attest.write_text(
        json.dumps(
            {
                "predicate": {
                    "attestation_id": "real-id",
                    "tessera_version": "1.1.0",
                    "benchmarks": {
                        "scanner_eval": {
                            "precision": 0.5,
                            "recall": 0.5,
                            "f1": 0.5,
                        }
                    },
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    rc = main(
        [
            "reproduce",
            "--attestation", str(attest),
            "--corpus", "tensor_trust",
            "--scanner", "tessera.scanners.heuristic.injection_score",
        ]
    )
    out, err = capsys.readouterr()
    assert rc == 0
    payload = json.loads(out)
    assert payload["recorded"]["precision"] == 0.5
    assert isinstance(payload["delta"]["precision"]["diff"], float)


def test_reproduce_with_missing_attestation_returns_2(capsys):
    rc = main(
        [
            "reproduce",
            "--attestation", "/no/such/file.jsonl",
            "--corpus", "tensor_trust",
            "--scanner", "tessera.scanners.heuristic.injection_score",
        ]
    )
    _, err = capsys.readouterr()
    assert rc == 2
    assert "error loading attestation" in err
