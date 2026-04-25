# 3H-3: MCP behavioral drift scanner plugin

## Status

GATED on the same plugin-mechanism discussion as 3H-1.

## Target

- Repo: https://github.com/agentgateway/agentgateway
- Branch base: `main`
- License (this contribution): Apache-2.0

## PR title

`feat: MCP behavioral drift scanner plugin from Tessera`

## PR body

```markdown
## Summary

Adds a Rust plugin that monitors per-MCP-server response shape and
latency p99 distribution across a 7-day rolling window and emits an
event when either drifts beyond an operator-configured threshold.
Source attribution: ported from
`tessera.mcp.drift.DriftMonitor` (Python) which has been the
`MCP_DRIFT_SHAPE` / `MCP_DRIFT_LATENCY` /
`MCP_DRIFT_DISTRIBUTION` event source in Tessera since v0.13.

## What it does

- Tracks response shape per server (top-level field set hash).
- Tracks latency p50 and p99 in a sliding 7-day window using
  T-Digest.
- Emits drift events when either shape or latency moves beyond
  configured thresholds.
- Stateless across restarts: state lives in the audit sink.

## Why agentgateway needs this

The Wave 3D / 3F integration model assumes drift telemetry is a
mesh-level signal, not a per-application one. Detecting that a
trusted MCP server suddenly returns a new field, or jumps from
50ms to 5s p99, is a cheap and useful canary for supply-chain
compromise or upstream regressions.

## Test plan

- [x] Unit tests cover shape stability, p99 computation, and
      threshold firing.
- [ ] Integration test against a deliberately-mutated MCP server
      stub.

## Dependencies

- None beyond what agentgateway already pulls in.

## Source attribution

Originally from `tessera/rust/agentgateway-plugins/mcp-drift-scanner/`.
172 LOC, Apache-2.0.
```

## Submission checklist

- [ ] File the discussion issue (or piggy-back on 3H-1).
- [ ] Fork upstream.
- [ ] Branch: `feat/mcp-drift-scanner-from-tessera`.
- [ ] Copy `rust/agentgateway-plugins/mcp-drift-scanner/`.
- [ ] DCO sign-off every commit.
- [ ] Open PR with the body above.
