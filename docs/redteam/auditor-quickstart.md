# External auditor quickstart: Tessera red-team corpus

This guide is for external security auditors who want to
reproduce a Tessera scorecard's `scanner_eval` benchmark numbers
end-to-end without writing custom code.

## What you get

- A versioned, schema-validated red-team corpus shipped at
  `corpus/probes/` (1000+ probes across 8 datasets:
  `tensor_trust`, `lakera_gandalf`, `agentdojo_seed`,
  `jailbreak_personas`, `encoding_obfuscation`,
  `multi_turn_setup`, `tool_call_payloads`,
  `exfiltration_patterns`).
- A schema at `corpus/schema/probe_v1.json`. Each entry has
  `probe_id`, `category`, `payload`, `expected_outcome`,
  `source`, `license`, `submitted_at`.
- A reproducer CLI: `python -m tessera.redteam`.
- A Garak compatibility shim
  (`tessera.redteam.garak_adapter.garak_probe_classes`) so
  Garak users can drive Tessera probes through their existing
  pipeline.

## 60-second runbook

```bash
pip install 'tessera[redteam]'

# 1. Inspect the corpus.
python3 -m tessera.redteam list
python3 -m tessera.redteam show tensor_trust --head 3

# 2. Run any Tessera scorer over any corpus and emit a report.
python3 -m tessera.redteam run \
    --corpus tensor_trust \
    --scanner tessera.scanners.heuristic.injection_score \
    --threshold 0.5 \
    --output /tmp/report.json

# 3. Reproduce the scanner_eval block of an existing attestation,
#    print a delta against the recorded numbers.
python3 -m tessera.redteam reproduce \
    --attestation docs/scorecard/static/paired-claude-sonnet-4.5.intoto.jsonl \
    --corpus tensor_trust \
    --scanner tessera.scanners.heuristic.injection_score
```

## Output schema

`run` writes a JSON report keyed by:

- `scanner`: dotted import path of the scorer.
- `corpus`: corpus name (or `all`).
- `threshold`: detection threshold applied.
- `total`, `detected`, `errors`: per-probe counts.
- `precision`, `recall`, `f1`: rounded to 4 decimals.
- `latency_ms_p50`, `latency_ms_p99`: per-probe scorer latency.
- `elapsed_seconds`: wall-clock for the full run.
- `per_category`: per-category `{tp, fp, fn, tn, precision,
  recall, f1}`.

`reproduce` writes:

- `attestation_path`, `attestation_id`, `tessera_version`.
- `recorded`: `{precision, recall, f1}` from the attestation.
- `reproduced`: same metrics from the live re-run.
- `delta`: `{before, after, diff}` per metric.

## Garak integration

Optional dependency. Install with:

```bash
pip install 'tessera[redteam-garak]'
```

Then in a Python session:

```python
from tessera.redteam.garak_adapter import garak_probe_classes

probe_classes = garak_probe_classes()
# {'tensor_trust': <GarakProbe Tensor_trust>,
#  'lakera_gandalf': <GarakProbe Lakera_gandalf>, ...}
```

A downstream Garak fork or plugin can re-export these from a
`garak.probes.tessera` module to get them auto-discovered by
`garak --list-probes`.

## Schema contract

The corpus format is frozen at `probe_v1`. Adding new fields is
additive (forward-compatible); removing or renaming is a v2
migration that ships with a corresponding schema bump in
`corpus/schema/probe_v2.json`.

## Reporting issues

If a probe has a stale `expected_outcome`, an inaccurate
`category`, or a license mismatch, file an issue at
<https://github.com/kenithphilip/Tessera/issues> tagged
`redteam:corpus`. Patches that add new probes should sign off
under DCO and reference the source dataset's license.

## Pinning a corpus version for an audit

```bash
# Snapshot the corpus at a specific Tessera commit so the audit
# runs are reproducible.
git -C /path/to/Tessera checkout v1.0.2
python3 -m tessera.redteam run --corpus tensor_trust \
    --scanner tessera.scanners.heuristic.injection_score \
    --output audit-2026-04-26-tensor_trust.json
```

Tessera releases tag the corpus state along with the codebase, so
auditing a release tag pins both the defense and the probes.
