# 3H-2: Hash-chained audit event sink plugin

## Status

GATED on the same plugin-mechanism discussion as 3H-1.

## Target

- Repo: https://github.com/agentgateway/agentgateway
- Branch base: `main`
- License (this contribution): Apache-2.0

## PR title

`feat: hash-chained audit event sink plugin from Tessera`

## PR body

```markdown
## Summary

Adds a Rust plugin that writes a hash-chained audit log of
agentgateway request/response events. Each entry's record includes
the SHA-256 of the previous entry's record, which lets downstream
SIEM pipelines detect deletion or reordering by re-walking the
chain.

Source attribution: this is the Rust port of Tessera's
`tessera.compliance.ChainedAuditLog` (Python) and
`tessera_audit::JsonlHashchainSink` (Rust), already in production
use in the AgentMesh proxy.

## What it does

- Writes one JSONL line per event to a configurable sink path.
- Each line carries `prev_hash`, `seq`, `timestamp`, `kind`,
  `principal`, and a `detail` blob.
- Optional `seal_key` HMACs the chain for truncation detection.
- Async-safe via a single writer task to avoid lock contention
  on the hot path.

## Why agentgateway needs this

Agent gateways are a chokepoint for tool calls; the audit trail
is the evidence operators need for incident response and for
compliance frameworks (NIST AI 600-1, EU AI Act Article 12, ISO
42001 Annex A.10.1). A built-in tamper-evident sink is more
defensible than per-deployment sidecars.

## Test plan

- [x] Unit tests cover hash chaining, seq monotonicity, and seal
      verification.
- [ ] Integration test with `agentgateway` proxy in CI.
- [ ] Worked example in `examples/`.

## Dependencies

- `sha2` 0.10 (Apache-2.0 / MIT)

## Source attribution

Originally from `tessera/rust/agentgateway-plugins/audit-event-sink/`.
181 LOC, Apache-2.0.
```

## Submission checklist

- [ ] File the discussion issue (or piggy-back on 3H-1 if the
      maintainer accepts plugin crates wholesale).
- [ ] Fork upstream.
- [ ] Branch: `feat/audit-event-sink-from-tessera`.
- [ ] Copy `rust/agentgateway-plugins/audit-event-sink/` into the
      target location.
- [ ] DCO sign-off every commit.
- [ ] Open PR with the body above.
