# SOC 2 Type I evidence trail (Phase 3 + Phase 4)

## Status

Trail starts with Phase 3 ship (v0.14.0). Type II observation
window (6+ months) feeds into Phase 4 to v1.0 timeline; the
formal certification is **out of scope per ADR-0002** and lives
in the separate `agentmesh-cloud` repository / org.

## What this document is

Operators running Tessera or AgentMesh in regulated environments
need a paper trail showing the security controls Tessera advertises
are actually exercised in production. This document maps Tessera's
runtime artifacts to the Trust Services Criteria a SOC 2 Type I
auditor walks through. It is NOT a SOC 2 report; it is the input a
downstream cloud operator (or an internal compliance team) feeds
into their own auditor's package.

The trail starts when v0.14.0 ships because that is the release
where every load-bearing primitive (provenance labels, MCP
signing, audit hash chain, runtime isolation) is in place.

## Trust Services Criteria coverage map

The TSC categories are: Common Criteria (CC), Availability,
Processing Integrity, Confidentiality, Privacy. Per the SOC 2
2017 Trust Services Criteria (revised 2022).

### CC1 Control Environment

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Code-of-conduct | `CONTRIBUTING.md` DCO sign-off (per ADR-0001) | repo root |
| Code-review enforcement | GitHub branch protection on `main`; PR template | `.github/` |
| Maintainer attestation | Sigstore-signed git tags | `git tag -v <tag>` |

### CC2 Communication and Information

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Security disclosures policy | `SECURITY.md` | repo root |
| Threat model | `papers/two-primitives-for-agent-security-meshes.md` | `papers/` |
| Architecture docs | `docs/standards-engagement/nccoe-architecture.md` | `docs/standards-engagement/` |

### CC3 Risk Assessment

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Documented risk register | `~/.claude/plans/buzzing-baking-waterfall.md` Section "Risk register" | local plan file (operator's working copy of the engineering brief) |
| External threat-model review | Wave 2K vendor engagement scoping | `docs/security/external_review_2026.md` |

### CC4 Monitoring Activities

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Security event log | hash-chained audit | `tessera.compliance.ChainedAuditLog`; runtime-emitted to JSONL |
| MCP drift signals | `MCP_DRIFT_SHAPE / LATENCY / DISTRIBUTION` events | `tessera.mcp.drift.DriftMonitor` |
| Multi-turn anomaly detection | `multi_turn` scanner | `tessera.scanners.multi_turn` |
| Memory poisoning detection | `memory_poisoning` scanner | `tessera.scanners.memory_poisoning` |
| Lethal trifecta detection | `lethal_trifecta` scanner | `tessera.scanners.lethal_trifecta` |

### CC5 Control Activities

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Argument-level provenance | `TESSERA_ENFORCEMENT_MODE=both` (v0.13+) / `args` (v1.0+) | `tessera.policy.tool_critical_args` |
| MCP audience binding | RFC 8707 enforcement | `tessera.mcp.oauth` |
| MCP signing | Sigstore + DSSE | `tessera.mcp.manifest` |
| Trust tier floor | `TESSERA_MCP_MIN_TIER` | `tessera.mcp.tier` |
| Action Critic principles | 20 principles v2 | `tessera.action_critic.principles.v2.yaml` |
| Runtime isolation | Tier 1 (Solo), Tier 2 (Firecracker), Tier 3 (Tetragon + Cilium + WireGuard) | `tessera.runtime.{solo, firecracker, tetragon}` |

### CC6 Logical and Physical Access Controls

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Workload identity | SPIFFE / WIMSE | `tessera.identity`, `tessera.spire` |
| Delegation tokens | HMAC-signed; 30s clock skew | `tessera.delegation` |
| Token audience binding | RFC 8707; AgentMesh as Resource Server | `tessera.mcp.oauth` |

### CC7 System Operations

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Observability | OpenTelemetry GenAI semconv (Phase 0) | `tessera.telemetry` |
| Incident response | `SECURITY.md` disclosure flow | repo root |
| Recovery | Worker recovery boundary (over-taint fallback) | `tessera.worker.recovery` |

### CC8 Change Management

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Versioned releases | SemVer + signed tags | git history |
| Migration docs | `docs/MIGRATION.md` | repo root |
| ADRs | `docs/adr/` | repo root |
| Test gates | `pytest` + `cargo test --workspace` in CI | `.github/workflows/` |

### CC9 Risk Mitigation

| Control | Tessera evidence | Where to find it |
| --- | --- | --- |
| Threat-intel feed | reference impl | `tessera.threat_intel` |
| Community red-team corpus | 200+ payloads, quarterly OCI artifact | `corpus/` (repo) and `tessera-redteam-corpus` (planned separate repo) |
| Security Attestation | scorecard publishing | `tessera bench emit-scorecard` |

## How to ship the trail to an auditor

A downstream operator collects the following artifacts on a
periodic cadence (recommend monthly during the Type I observation
window):

1. **Audit log dump**: The hash-chained JSONL produced by
   `tessera.compliance.ChainedAuditLog` for the period. The chain
   integrity verify log is the auditor's tamper-evidence proof.
2. **Scorecard attestations**: Run
   `tessera bench emit-scorecard --out=YYYY-MM.intoto.jsonl
   --sign=sigstore` once per period; commit the signed attestation
   alongside the audit log.
3. **Drift alert summary**: Roll up `MCP_DRIFT_*` events by server
   and impact class.
4. **Test results**: `pytest -q` + `cargo test --workspace` from
   the released tag, captured to a CI artifact with the run URL
   recorded.
5. **Vulnerability disclosures**: Rolling list from
   `SECURITY.md` and any CVEs filed against Tessera (none open
   at v0.14.0).

The bundle goes into the operator's compliance repo (NOT
Tessera's). Tessera produces the artifacts; the operator is the
data controller for SOC 2 purposes.

## Out of scope

Per ADR-0002:

- Tessera does not seek SOC 2 Type II directly.
- The certification belongs to the cloud operator that runs
  Tessera in regulated environments.
- The `agentmesh-cloud` separate repo / org is the home for the
  hosted service that pursues SOC 2 Type II + HIPAA + FedRAMP.

## Timeline

| Date | Milestone |
| --- | --- |
| 2026-04-25 | v0.14.0 ships; Phase 3 trail starts |
| 2026-05-25 | First monthly evidence bundle compiled |
| 2026-10-25 | 6 months of trail accumulated; downstream operators can begin Type II observation |
| 2026-12-?? | v1.0 ships; full primitive surface frozen |
| 2027-04-?? | First downstream Type II report likely (operator-driven) |

## References

- ADR-0002: No Tessera-hosted commercial services
- AICPA TSP 100 (2017, revised 2022)
- `docs/strategy/2026-04-engineering-brief.md` Section 5
- `docs/standards-engagement/nccoe-architecture.md`
