# OWASP And NIST Control Matrix

This document maps the current Tessera implementation to:

- the OWASP GenAI Security Project guidance for agentic applications
- the NIST AI RMF core functions `Govern`, `Map`, `Measure`, and `Manage`

It is intentionally conservative. A row marked `Partial` means the repo
contains a meaningful control, but not enough to claim full coverage.

## OWASP Agentic Alignment

| Theme | Current Tessera Controls | Status | Notes |
|---|---|---|---|
| Indirect prompt injection and behavior hijacking | `labels.py`, `provenance.py`, `context.py`, `policy.py`, `quarantine.py`, `proxy.py` | Partial | Strong at tool boundary and dual-LLM isolation, but not model-native trust separation |
| Tool misuse and unauthorized actions | `policy.py`, `delegation.py`, `proxy.py`, `a2a.py` | Partial | Deterministic allow or deny exists, but no fleet-wide policy backend or approval workflow system |
| Identity and privilege abuse | `signing.py`, `delegation.py`, `proxy.py` | Partial | Good application-layer binding, missing mTLS, DPoP/WIMSE, SPIRE-backed live issuance, federation |
| Agent-to-agent trust | `a2a.py`, `proxy.py` A2A JSON-RPC mediation | Partial | Signed carriage and verified transport ingress exist, but not cross-provider mutual auth or full lifecycle mediation |
| Auditability and traceability | `events.py`, `telemetry.py` | Partial | Events and spans exist, but not evidence exports, provenance DAGs, or compliance packaging |
| Runtime isolation and rogue behavior containment | None in-tree | Missing | No sandbox orchestration, kill switch, kernel policy, or network containment |
| Supply-chain integrity | None in-tree | Missing | No prompt, tool, agent package, or MCP server attestation and verification |
| Human oversight | delegated `requires_human_for` checks in `policy.py` | Partial | Deny hook exists, but no operator approval UX, queue, or override trail |
| Denial-of-wallet and spend governance | delegated `max_cost_usd` checks in `policy.py` | Partial | Per-action cap exists, but no cumulative budget ledger by principal or session |
| Egress control | delegated domain allowlists in `policy.py` | Partial | Application-layer destination constraints exist, but no network-layer enforcement |

## NIST AI RMF Mapping

| NIST Function | Current Controls | Status | Gaps |
|---|---|---|---|
| Govern | `policy.py`, `events.py`, `docs/AGENT_SECURITY_MESH_GAP_AUDIT_2026-04-10.md` | Partial | No organizational governance workflow, approval operations, policy rollout engine, or evidence pipeline |
| Map | `provenance.py`, `context.py`, `proxy.py` discovery, `a2a.py` | Partial | No fleet registry, supply-chain map, provider inventory, or multi-tenant dependency map |
| Measure | `tests/`, `events.py`, `telemetry.py` | Partial | No benchmark harness, attack-eval program, risk scoring, or provenance analytics |
| Manage | `policy.py`, `delegation.py`, `proxy.py`, `quarantine.py` | Partial | No shadow mode, no cumulative budgeting, no runtime containment, no incident controls |

## Secure And Resilient Characteristic

NIST treats `Secure and Resilient` as a primary trustworthiness
characteristic. Tessera contributes meaningfully here, but only for a
subset of the full stack.

Implemented today:

- deterministic tool-boundary authorization
- signed content provenance and delegation artifacts
- fail-closed verification on delegated and provenance-bound requests
- structured security events and traces
- dual-LLM isolation for untrusted content processing

Still missing for a stronger claim:

- runtime isolation
- network and egress enforcement
- proof-of-possession identity
- fleet-wide control plane governance
- supply-chain integrity
- recovery and containment workflows

## Honest Claim

The honest claim today is:

Tessera implements several load-bearing technical controls that support
OWASP-style agentic security and NIST AI RMF secure-and-resilient goals.
It does not yet provide a complete OWASP coverage story or a full NIST
AI RMF implementation profile by itself.
