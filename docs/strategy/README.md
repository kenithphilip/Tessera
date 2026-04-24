# Strategy documents

Source documents that drive the v0.12 to v1.0 plan. Vendored
verbatim on 2026-04-24 from external analyses; preserved unchanged
so future maintainers can audit the reasoning behind each ADR.

## Index

| File | Source | Purpose |
|------|--------|---------|
| `2026-04-mesh-review.md` | External positioning analysis, April 2026 | Competitive landscape (agentgateway v1.0 LF backing, Microsoft Agent Governance Toolkit, consolidation wave). The 10 priority gaps in the project's own GAP_ANALYSIS_AGENTDOJO.md re-ranked. The four-tier pricing analysis (Cloud Starter $29, Team $199, Enterprise $25K+). The 6 / 12 / 24 month strategic moves. |
| `2026-04-engineering-brief.md` | External engineering design brief, April 2026 | Implementation-grade specification of four coupled workstreams: Section 1 argument-level provenance (CaMeL + FIDES + PCAS hybrid), Section 2 Action Critic (LlamaFirewall AlignmentCheck-equivalent), Section 3 MCP as security surface (SEP-1913 + Sigstore + RFC 8707 + trust tiers), Section 4 Evaluation-as-a-Product (signed Security Attestation v1 + community red-team corpus). |

## Relationship to the v0.12 to v1.0 plan

The plan itself lives outside the repo (in the maintainer's
private plan workspace) but is summarized in
`docs/adr/0001-license-split.md` through `0007-provenance-label-v2.md`
as individual ADRs. Each ADR cites the relevant section of the
strategy documents above.

## Editing policy

These two files are immutable history. New analyses go into
sibling files (e.g. `2026-Q3-followup-review.md`) rather than
amending the originals.
