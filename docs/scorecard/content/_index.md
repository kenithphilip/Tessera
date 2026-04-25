---
title: "Tessera Scorecards"
date: 2026-04-25
---

# Tessera Scorecards

This site publishes signed security attestations for every Tessera release.
Each attestation is an [in-toto Statement v1](https://in-toto.io/Statement/v1)
carrying benchmark results, MCP security scores, audit chain roots, and
compliance taxonomy coverage.

## What is an attestation?

A Tessera Security Attestation records:

- **Benchmark results**: AgentDojo utility accuracy and attack success rate;
  CyberSecEval pass rate; scanner precision, recall, and F1.
- **MCP security score**: per-server rating (0.0 to 1.0) from the Tessera
  MCP manifest scanner.
- **Audit summary**: hash-chain root, event counts by kind.
- **Compliance coverage**: which of the eight taxonomies (NIST CSF, CWE,
  OWASP ASVS, MITRE ATLAS, EU AI Act, ISO 42001, CSA AICM, NIST AI 600-1)
  are covered.
- **MITRE ATLAS Navigator layer**: reference URI and technique count.

Attestations are signed with HMAC-SHA256 (air-gapped / CI) or Sigstore
(OIDC-bound, Rekor-anchored) depending on the release environment.

## Embedding the badge

```markdown
![Tessera APR](https://tessera-ai.github.io/scorecard/badge.svg)
```

## Latest sample attestation

The sample attestation in JSON-lines format is available at
[static/sample.intoto.jsonl](/scorecard/sample.intoto.jsonl).
It was generated from the Tessera CLI and signed with HMAC using the
development fallback key. Do not use this attestation as a trust anchor
in production.
