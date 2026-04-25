"""Security attestation emitter.

Builds and writes a Tessera Security Attestation (in-toto Statement v1) from
lazily-loaded local data sources: an audit log, scanner report, and benchmark
run files. Missing sources become empty sections; they are never errors.

The output is JSON-lines in-toto envelope format: one JSON object per line,
each line being an independent in-toto Statement payload. For the single-release
use case, the file contains exactly one line.

References
----------
- Schema: tessera/evaluate/scorecard/schema/security_attestation_v1.yaml
- in-toto Statement v1: https://in-toto.io/Statement/v1
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://tessera.dev/security-attestation/v1"

# Genesis hash matches the audit_log genesis constant.
_GENESIS_HASH = "0" * 64

# Compliance taxonomies Tessera enriches (frozen list, matches schema).
_TAXONOMIES = [
    "NIST_CSF",
    "CWE",
    "OWASP_ASI",
    "MITRE_ATLAS",
    "EU_AI_Act",
    "ISO_42001",
    "CSA_AICM",
    "NIST_AI_600_1",
]


def _sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA-256 of a file's contents."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


def _load_json(path: Path) -> dict[str, Any] | None:
    """Return parsed JSON from path, or None if the file is missing or invalid."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _audit_summary(audit_log_path: Path | None) -> dict[str, Any]:
    """Derive the audit_summary predicate section from the audit log.

    Reads the log lazily via tessera.audit_log.iter_records. When the path
    is None or the file is absent, returns a zero-count summary with the
    genesis hash.

    Args:
        audit_log_path: Path to a JSONL hash-chained audit log, or None.

    Returns:
        Dict matching the audit_summary schema section.
    """
    if audit_log_path is None or not audit_log_path.exists():
        return {
            "event_counts_by_kind": {},
            "hash_chain_root": _GENESIS_HASH,
            "sequence_count": 0,
        }

    from tessera.audit_log import iter_records  # lazy import

    counts: dict[str, int] = {}
    last_hash = _GENESIS_HASH
    count = 0
    for record in iter_records(audit_log_path):
        counts[record.kind] = counts.get(record.kind, 0) + 1
        last_hash = record.hash
        count += 1

    return {
        "event_counts_by_kind": counts,
        "hash_chain_root": last_hash,
        "sequence_count": count,
    }


def _scanner_metrics(report_path: Path | None) -> dict[str, Any]:
    """Extract scanner_eval metrics from a JSON report file.

    The report must be a dict with keys: precision, recall, f1, roc_auc.
    Unknown keys are ignored. Missing file returns empty dict.

    Args:
        report_path: Path to the scanner evaluation JSON report, or None.

    Returns:
        Dict matching the scannerEvalMetrics schema definition, possibly empty.
    """
    if report_path is None:
        return {}
    data = _load_json(report_path)
    if not data:
        return {}
    result: dict[str, Any] = {}
    for key in ("precision", "recall", "f1", "roc_auc", "run_id"):
        if key in data:
            result[key] = data[key]
    return result


def _benchmark_metrics(run_paths: list[Path]) -> dict[str, Any]:
    """Aggregate benchmark metrics from one or more benchmark run JSON files.

    Each file must contain a top-level "suite" key (value: "agentdojo",
    "cyberseceval", or "scanner_eval") and the relevant metric keys. Unknown
    suite values and missing files are silently skipped.

    Args:
        run_paths: List of paths to benchmark run JSON files.

    Returns:
        Dict matching the benchmarks schema section.
    """
    benchmarks: dict[str, Any] = {}
    for path in run_paths:
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        suite = str(data.get("suite", ""))
        if suite == "agentdojo":
            entry: dict[str, Any] = {"suite": suite}
            for key in ("utility_accuracy", "attack_success_rate", "run_id"):
                if key in data:
                    entry[key] = data[key]
            benchmarks["agentdojo"] = entry
        elif suite == "cyberseceval":
            entry = {"suite": suite}
            for key in ("attack_success_rate", "average_pass_rate", "run_id"):
                if key in data:
                    entry[key] = data[key]
            benchmarks["cyberseceval"] = entry
        elif suite == "scanner_eval":
            entry = {"suite": suite}
            for key in ("precision", "recall", "f1", "roc_auc", "run_id"):
                if key in data:
                    entry[key] = data[key]
            benchmarks["scanner_eval"] = entry
    return benchmarks


def _default_compliance() -> dict[str, Any]:
    """Return the default compliance_taxonomies section.

    All 8 taxonomies Tessera enriches are marked covered=True. Callers that
    want to override individual entries should update the returned dict before
    passing it to the emitter.

    Returns:
        Dict matching the compliance_taxonomies schema section.
    """
    return {name: {"covered": True} for name in _TAXONOMIES}


def _atlas_navigator_layer() -> dict[str, Any]:
    """Return a compact reference to the MITRE ATLAS Navigator layer.

    Wave 2M ships a static layer at
    ``docs/security/atlas_navigator_layer.json``. Embed a reference
    (URI + on-disk relative path + technique count) here so a
    consumer of the attestation can pivot directly to the layer
    without re-deriving it from the compliance tables.

    The full layer JSON is NOT inlined to keep the attestation
    payload bounded; the reference points at the addressable
    artifact, which is what a SOC team imports into the ATLAS
    Navigator UI.
    """
    layer_uri = (
        "https://github.com/kenithphilip/Tessera/blob/main/"
        "docs/security/atlas_navigator_layer.json"
    )
    relative_path = "docs/security/atlas_navigator_layer.json"
    technique_count = 0
    layer_path = (
        Path(__file__).resolve().parents[3] / relative_path
    )
    if layer_path.exists():
        try:
            data = json.loads(layer_path.read_text(encoding="utf-8"))
            technique_count = len(data.get("techniques", []))
        except (OSError, json.JSONDecodeError):
            pass
    return {
        "schema_version": "tessera.atlas_navigator.v1",
        "layer_uri": layer_uri,
        "relative_path": relative_path,
        "technique_count": technique_count,
    }


@dataclass
class ScorecardEmitter:
    """Builds a Tessera Security Attestation from local data sources.

    All source inputs are optional. Missing files produce empty sections, not
    errors. This lets CI emit a partial attestation early in a pipeline and
    fill it out as benchmark and scanner runs complete.

    Attributes:
        version: SemVer string for the Tessera release being attested.
        audit_log_path: Path to a JSONL hash-chained audit log.
        scanner_report_path: Path to a JSON scanner evaluation report.
        benchmark_runs: List of paths to benchmark run JSON files.
        subjects: List of artifact subject dicts (name + sha256 digest).
            If empty, a placeholder subject is included.
        claims: List of claim dicts to embed in the predicate.
        mcp_security_score: Map of server name to score in [0, 1].
        principles_revision: Integer revision of the principles document.

    Example::

        emitter = ScorecardEmitter(version="0.12.0")
        attestation = emitter.build()
        out = emitter.emit(Path("/tmp/attestation.intoto.jsonl"))
    """

    version: str
    audit_log_path: Path | None = None
    scanner_report_path: Path | None = None
    benchmark_runs: list[Path] = field(default_factory=list)
    subjects: list[dict[str, Any]] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    mcp_security_score: dict[str, float] = field(default_factory=dict)
    principles_revision: int = 1
    # Wave 4E: paired-model identifier (claude-sonnet-4.5, gpt-5,
    # gemini-2.5-pro). When set, the attestation predicate carries
    # a `paired_model` field and the rendered subject name gets a
    # `+<model>` suffix so paired scorecards are addressable.
    paired_model: str | None = None

    def build(self) -> dict[str, Any]:
        """Construct the attestation dict without writing it to disk.

        Returns:
            A Python dict matching the security_attestation_v1 JSON-Schema.
        """
        subject_suffix = (
            f"+{self.paired_model}" if self.paired_model else ""
        )
        subjects = list(self.subjects) or [
            {
                "name": (
                    f"tessera_mesh-{self.version}{subject_suffix}-py3-none-any.whl"
                ),
                "digest": {"sha256": _GENESIS_HASH},
            }
        ]

        predicate: dict[str, Any] = {
            "tessera_version": self.version,
            "attestation_id": str(uuid4()),
            "generated_at": datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "claims": list(self.claims),
            "benchmarks": _benchmark_metrics(self.benchmark_runs),
            "mcp_security_score": dict(self.mcp_security_score),
            "audit_summary": _audit_summary(self.audit_log_path),
            "compliance_taxonomies": _default_compliance(),
            "principles_revision": self.principles_revision,
            # Wave 2M: embed the MITRE ATLAS Navigator layer reference
            # so SOC teams can pivot from a scorecard back to ATLAS
            # technique coverage without a second hop.
            "mitre_atlas_navigator_layer": _atlas_navigator_layer(),
        }
        if self.paired_model:
            predicate["paired_model"] = self.paired_model

        if self.scanner_report_path:
            scanner = _scanner_metrics(self.scanner_report_path)
            if scanner:
                existing = predicate["benchmarks"].get("scanner_eval", {})
                predicate["benchmarks"]["scanner_eval"] = {**scanner, **existing}

        return {
            "_type": STATEMENT_TYPE,
            "subject": subjects,
            "predicateType": PREDICATE_TYPE,
            "predicate": predicate,
        }

    def emit(self, out_path: Path) -> Path:
        """Write the attestation as a JSON-lines file to ``out_path``.

        Each call writes a single line containing the full in-toto Statement.
        The file is created (or overwritten) atomically via a temp-file rename.

        Args:
            out_path: Destination path. Parent directory is created if absent.

        Returns:
            The resolved path of the written file.
        """
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        attestation = self.build()
        line = json.dumps(attestation, sort_keys=True, separators=(",", ":"))
        tmp = out_path.with_suffix(out_path.suffix + ".tmp")
        tmp.write_text(line + "\n", encoding="utf-8")
        tmp.replace(out_path)
        return out_path.resolve()


__all__ = ["ScorecardEmitter", "STATEMENT_TYPE", "PREDICATE_TYPE"]
