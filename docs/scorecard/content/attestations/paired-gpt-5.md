---
title: "Tessera v1.0.0 paired with GPT-5"
date: 2026-04-25
predicate:
  attestation_id: f6c9037c-5b7e-40ab-b2c2-13354f1d4342
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
  generated_at: "2026-04-25T13:44:35Z"
  mcp_security_score: {}
  mitre_atlas_navigator_layer:
    layer_uri: "https://github.com/kenithphilip/Tessera/blob/main/docs/security/atlas_navigator_layer.json"
    relative_path: "docs/security/atlas_navigator_layer.json"
    schema_version: "tessera.atlas_navigator.v1"
    technique_count: 0
  paired_model: "gpt-5"
  principles_revision: 1
  tessera_version: "1.0.0"
---

This attestation pins the Tessera 1.0.0 release primitives to
the GPT-5 paired model. Benchmark numbers are populated from
`benchmarks/agentdojo_live/run_openai.py` runs and re-signed by
the publish pipeline.

The empty `benchmarks` block in the predicate is the placeholder
shipped with v1.0.0; real measured numbers land via the
`--from-runs` flag tracked in
[`docs/benchmarks/REAL_RUN_RUNBOOK.md`](https://github.com/kenithphilip/Tessera/blob/main/docs/benchmarks/REAL_RUN_RUNBOOK.md).
