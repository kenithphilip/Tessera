---
title: "Tessera v1.0.0 paired with Gemini 2.5 Pro"
date: 2026-04-25
predicate:
  attestation_id: 57e0ae19-5015-4f7d-8f5f-a411e56d532a
  audit_summary:
    event_counts_by_kind: {}
    hash_chain_root: "0000000000000000000000000000000000000000000000000000000000000000"
    sequence_count: 0
  benchmarks: {}
  claims: []
  compliance_taxonomies:
    CSA_AICM: { covered: true }
    CWE: { covered: true }
    EU_AI_Act: { covered: true }
    ISO_42001: { covered: true }
    MITRE_ATLAS: { covered: true }
    NIST_AI_600_1: { covered: true }
    NIST_CSF: { covered: true }
    OWASP_ASI: { covered: true }
  generated_at: "2026-04-25T13:44:36Z"
  mcp_security_score: {}
  mitre_atlas_navigator_layer:
    layer_uri: "https://github.com/kenithphilip/Tessera/blob/main/docs/security/atlas_navigator_layer.json"
    relative_path: "docs/security/atlas_navigator_layer.json"
    schema_version: "tessera.atlas_navigator.v1"
    technique_count: 0
  paired_model: "gemini-2.5-pro"
  principles_revision: 1
  tessera_version: "1.0.0"
---

This attestation pins the Tessera 1.0.0 release primitives to
the Gemini 2.5 Pro paired model. Benchmark numbers are populated
from `benchmarks/agentdojo_live/run_gemini.py` runs and re-signed
by the publish pipeline.

The empty `benchmarks` block in the predicate is the placeholder
shipped with v1.0.0; real measured numbers land via the
`--from-runs` flag tracked in
[`docs/benchmarks/REAL_RUN_RUNBOOK.md`](https://github.com/kenithphilip/Tessera/blob/main/docs/benchmarks/REAL_RUN_RUNBOOK.md).
