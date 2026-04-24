# NCCoE practice-guide proposal: AI agent identity and authorization

Drafted 2026-04-24 under the Tessera v0.12 to v1.0 plan, Phase 0
wave 0E. To be filed through NCCoE channels as a candidate
reference implementation contribution to the AI Agent Identity
and Authorization practice guide initiative announced by
CAISI / NCCoE in February 2026.

## Submitter

- Project: Tessera (open-source agent security primitives library)
  and AgentMesh (companion proxy / service)
- Maintainer: Kenith Philip
- License: Apache-2.0 (Tessera library) and AGPL-3.0-or-later
  (AgentMesh service); see
  `https://github.com/kenithphilip/Tessera/blob/main/NOTICE`
- Repository: https://github.com/kenithphilip/Tessera
- Specification: `papers/two-primitives-for-agent-security-meshes.md`

## Why this proposal fits the NCCoE practice-guide scope

The NCCoE concept paper on AI agent identity and authorization
(February 2026) centers on WIMSE / SPIFFE workload identity,
OAuth-based authorization, and policy-based access control for
AI agents. Tessera's architecture maps 1:1 onto the concept:

| NCCoE concept layer | Tessera primitive | Status |
|---------------------|-------------------|--------|
| Workload identity (SPIFFE/WIMSE) | `tessera.identity` + `tessera.spire` | Implemented v0.7+; WIMSE alignment in v0.13 wave 2I |
| OAuth authorization | `tessera.delegation.DelegationToken` | Implemented v0.7+; RFC 8707 audience binding in v0.13 wave 2C |
| Policy-based access control | `tessera.policy.Policy` (taint-tracking + CEL deny rules) | Implemented v0.7+; CEL JIT in v0.10 |
| Audit / forensic record | `tessera.audit_log.JSONLHashchainSink` | Implemented v0.7+; tamper-evident hash chain |
| Tool-call authorization | `tessera.policy.evaluate(tool, ctx)` | Implemented v0.7+; argument-level provenance in v0.12 |
| Cross-system data labeling | `ProvenanceLabel` (SEP-1913 wire compatible) | Land v0.12 |

Tessera + AgentMesh is, to the maintainer's knowledge, the only
open-source implementation that combines all six layers in a
deployable shape (FastAPI proxy + Rust gateway + 16 framework
adapters).

## What we are proposing

Tessera contributes:

1. **A reference implementation of the NCCoE concept paper's
   architecture**, runnable end to end via docker-compose +
   Helm + air-gapped install scripts (Phase 2 wave 2E).
2. **A signed, in-toto attested security scorecard** mapping
   Tessera's controls to NIST AI RMF subcategories,
   NIST AI 600-1 GenAI risks, OWASP Agentic Top 10 2026,
   MITRE ATLAS v5.4.0, EU AI Act Articles 9 / 12 / 14 / 15,
   ISO/IEC 42001 Annex A, and CSA AICM 1.0. Compliance enrichment
   shipped 2026-04-24 in v0.11.1 wave 0C.
3. **Conformance fixtures** for SEP-1913 annotations and signed
   MCP manifests (see
   `docs/standards-engagement/sep-1913-comments.md`).
4. **Maintainer time** to review NCCoE drafts of the practice
   guide, attend working-group calls, and update the reference
   implementation as the practice guide evolves.

The reference implementation lives in the NCCoE repository per
the standard NCCoE practice-guide pattern (project ownership
remains with the contributing organization; NCCoE hosts the
reference deployment and documentation). Tessera's role is
contributing engineer time and code maintenance, not owning the
guide's repository.

## What we are not proposing

- Tessera does not seek to be the "official" AI agent identity
  reference implementation. Multiple reference implementations
  serve different deployment contexts; Tessera offers one.
- Tessera does not seek funding from NIST or NCCoE. Engagement
  is contributor time at the maintainer's expense.
- Tessera does not seek any commercial endorsement.

## Why now

CAISI's January 2026 RFI on securing agentic AI systems and the
February 2026 launch of the AI Agent Standards Initiative align
with Tessera's v1.0 release timing (Phase 4, weeks 22 to 30 of
the plan). The window for a credible reference-implementation
contribution closes when other open-source projects (Microsoft
Agent Governance Toolkit, agentgateway from Solo.io) propose
themselves first. Tessera's differentiator: WIMSE-aligned
identity (Microsoft's toolkit does not yet claim WIMSE
alignment) and SPIFFE-based workload identity (agentgateway
relies on external OIDC / OAuth identity providers).

## Roadmap alignment

- v0.12 (Q2 2026, weeks 2-6): Argument-level provenance ships;
  `ProvenanceLabel` lattice formalized; AgentDojo live submission
  infra.
- v0.13 (Q3 2026, weeks 6-14): RFC 8707 audience binding
  enforced on every MCP token; per-MCP delegation scoping;
  Sigstore-signed manifests with three trust tiers; Helm chart
  + air-gapped install + ArgoCD templates; WIMSE / draft-klrc-
  aiagent-auth alignment in delegation token canonical form.
- v0.14 (Q4 2026, weeks 14-22): Multi-turn / memory poisoning /
  lethal-trifecta detectors; community red-team corpus v1;
  Garak-compatible probe runner; agentgateway upstream
  contributions (SPIFFE plugin + audit sink + MCP-drift scanner).
- v1.0 (Q1 2027, weeks 22-30): API freeze; signed MCP registry
  mirror; model-specific paired scorecards; foundation
  governance proposal drafted for v1.1.

The NCCoE practice-guide reference implementation tracks the
v0.13 release (Phase 2 in the plan). Tessera commits to
delivering a runnable reference deployment matching the NCCoE
concept paper's architecture by end of Q3 2026, conditional on
the practice guide draft text being available by mid-Q3 2026.

## Engagement format

- Tessera maintainer attends NCCoE working-group calls (typically
  bi-weekly) starting Q2 2026.
- Tessera contributes draft text for the practice guide sections
  on SPIFFE-based workload identity, RFC 8707 audience binding,
  and tamper-evident audit.
- Tessera maintains the NCCoE reference repository alongside
  the upstream Tessera + AgentMesh repositories, with
  bidirectional sync.

## Authors and contact

Drafted by the Tessera maintainer (Kenith Philip) on 2026-04-24
as part of the v0.12 to v1.0 plan, Phase 0 wave 0E. To be
submitted via the NCCoE intake form for the AI Agent Identity
and Authorization initiative.

## References

- CAISI January 2026 RFI: securing agentic AI systems
- NCCoE February 2026 concept paper: AI agent identity and
  authorization
- Tessera GitHub: https://github.com/kenithphilip/Tessera
- AgentMesh GitHub: https://github.com/kenithphilip/AgentMesh
- Tessera v0.12 to v1.0 strategy:
  `docs/strategy/2026-04-engineering-brief.md`
