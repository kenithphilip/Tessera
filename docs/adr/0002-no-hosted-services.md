# ADR 0002: No Tessera-hosted commercial services

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

The strategic review proposes a 4-tier pricing structure (Cloud
Starter $29 / month, Team $199 / month, Enterprise $25K+ / year)
plus threat-intel feed hosting, a public scorecard service, and
SOC 2 / HIPAA / FedRAMP certifications. Each of these would
generate revenue and aid sustainability. Each also commits the
maintainer to operating a hosted service with availability SLAs
and to maintaining audit-grade compliance certifications that
attach to a service rather than a library.

The Tessera + AgentMesh OSS repositories cannot host commercial
services without changing their character: foundation
discussions (ADR 0003) become governance-conflicted; community
contributors face uncertainty about whether their code is
contributing to OSS or to a commercial offering; security
audits of OSS releases get conflated with audits of the
commercial service.

## Decision

Tessera and AgentMesh (the OSS repositories) do not host any
commercial service. All revenue-bearing services attach to a
separate `agentmesh-cloud` repository and corresponding
business entity / GitHub organization, distinct from the OSS
governance.

Specifically, the following move out of this plan and into
AgentMesh Cloud:

1. Pricing tiers (Cloud Starter, Team, Enterprise).
2. SOC 2 Type II + HIPAA BAA + FedRAMP-in-process certifications.
3. `scorecard.tessera.dev` operated as a hosted service.
   Tessera ships the static-site code (Phase 3 wave 3E,
   published from CI artifacts to GitHub Pages); AgentMesh
   Cloud may operate a richer hosted variant.
4. Threat-intel feed hosting with SLA. Tessera ships the schema
   (Phase 2 wave 2J) and a reference file-based feed (Phase 3
   wave 3F); hosting is AgentMesh Cloud.
5. Compliance evidence service (auto-generated SOC 2 / EU AI Act
   evidence bundles). Tessera ships the audit log + attestation
   schema; the service that bundles them is AgentMesh Cloud.
6. Managed SPIRE infrastructure.
7. LLM guardrail fine-tuning on customer data.

## Consequences

Positive:
- OSS governance stays clean for foundation discussions
  (ADR 0003).
- Maintainer time on the OSS repositories is spent on engineering
  and standards, not on running a service or chasing audit
  evidence.
- Contributors know their work goes into open infrastructure,
  not into a commercial product.

Negative:
- Sustainability funding has to come from AgentMesh Cloud (or
  external sponsorship / consulting), not from the OSS
  repositories directly.
- Operational lessons from running AgentMesh Cloud do not
  automatically flow back into the OSS code unless explicitly
  upstreamed.

Neutral:
- The OSS surface and the commercial surface stay loosely
  coupled by design; neither blocks the other.

## Alternatives considered

- **Allow Tessera repo to host scorecard.tessera.dev.** Rejected
  because operating a public service at the OSS layer creates
  perpetual cost and SLA commitments that the maintainer cannot
  guarantee.
- **Allow Tessera repo to claim SOC 2.** Rejected because SOC 2
  applies to a service, not a library; claiming it on a library
  release is misleading.

## Implementation

- The `agentmesh-cloud` repository / org is created when
  AgentMesh Cloud has its first paying customer or design
  partner, not before.
- The Tessera + AgentMesh OSS repositories link to AgentMesh
  Cloud in their READMEs as a hosted option, comparable to how
  Grafana OSS links to Grafana Cloud.

## References

- `docs/strategy/2026-04-mesh-review.md` Section "Commercialization
  strategy"
- Grafana / Mattermost / Plausible split precedent
