# Threat-model review vendor selection brief (Wave 2K, decision input)

## Status

Decision input for the engagement scoping in
[`external_review_2026.md`](external_review_2026.md). Vendor
selection target date: 2026-05-15. Engagement length: 4 weeks.
Budget envelope (per Wave 2K scoping): $35-65k.

## How this brief reads

The six review priorities in `external_review_2026.md` decompose
into two skill clusters:

- **Cluster A (cryptographic protocol depth)**. Priorities 4 and
  5: Sigstore + DSSE + Rekor inclusion proof; canonical-JSON
  malleability; RFC 8707 audience binding; OAuth 2.1 resource
  metadata.
- **Cluster B (program-analysis and adversarial-ML depth)**.
  Priorities 1, 2, 3, and 6: lattice algebra invariants; AST
  instrumentation coverage including `compile`/`exec` paths;
  declassification-boundary adversarial cases at the Worker
  recovery; same-planner-as-critic threat model.

Cluster B carries 4 of 6 priorities and is the higher-risk
surface because the AST rewrite is the only code path in Tessera
that *cannot* be exhaustively unit-tested (it depends on every
caller's bytecode shape). A finding here would force re-shaping
the substrate before v1.0.

## Comparison

| Column | NCC Group | Trail of Bits | Doyensec |
| --- | --- | --- | --- |
| **Scope-fit (Cluster A: Sigstore + DSSE + RFC 8707)** | Strong. Published Sigstore review work; deep cryptographic-protocol audit history (TLS, signing flows, key-management). | Strong. Published research on transparency-log integrity and supply-chain signing; OAuth review chops. | Adequate. Web/OAuth fluency is the firm's bread and butter; less depth on Sigstore/DSSE specifically. |
| **Scope-fit (Cluster B: AST + lattice + adversarial-ML)** | Adequate. Solid AppSec; adversarial-ML practice is growing but not the firm's center of gravity. | Strong. Authors of Manticore (symbolic execution), Slither (Solidity static analysis), and Echidna (property-testing). Adversarial-ML practice is named and active. AST/program-analysis depth is differential. | Limited. Web-app focus; no published program-analysis tooling. |
| **Cost range (4-week engagement)** | $50-80k estimated; high end of the bracket. Pending RFP. | $45-70k estimated; mid-to-high bracket. Pending RFP. | $30-50k estimated; mid-bracket. Pending RFP. |
| **Lead time (kickoff after signature)** | 6-10 weeks typical (queue depth) | 4-8 weeks typical | 2-4 weeks typical |
| **Prior AI / agent-security work (public)** | LLM red-team engagements with named vendors; published guidance on prompt-injection threat models. | Published research on adversarial-ML attack chains; named contributors to AI-security tooling; ongoing engagement with the supply-chain-for-models discussion. | Published web-AI threat-model writeups; less visible work specific to LLM agents. |
| **Confidentiality posture for an open-source project** | Standard NDA; comfortable publishing report after remediation. | Standard NDA; long history of publishing reports; this is a default. | Standard NDA; willing to publish. |
| **Re-test included** | Typically a separate SOW. | Bundled in most engagements. | Bundled in most engagements. |

Cost and lead-time numbers are estimates pulled from public
engagement pages and industry rates for 4-week security audits;
they are anchored to the firms' published positioning and will
move with the actual RFP responses. They are not a quote.

## Recommendation: Trail of Bits

**Rationale.** Cluster B carries the higher project-risk weight
and Trail of Bits has the deepest, most public program-analysis
practice of the three (Manticore, Slither, Echidna are direct
analogs to the kind of coverage problem the AST instrumentation
poses). Their adversarial-ML practice covers priority 6 (the
same-planner-as-critic gate) without needing a second vendor.
On Cluster A they are credible but not best-in-class. Net: one
vendor covers all six priorities at acceptable depth, which beats
splitting into two engagements at the budget envelope.

**Secondary pick: NCC Group.** If the RFP comes back with Trail
of Bits over budget or with a kickoff date past 2026-06-15
(which would push remediation past the Phase 3 cut), NCC Group
takes Cluster A as their strength and we accept slightly thinner
Cluster B coverage.

**Doyensec is not recommended for this engagement.** The web/OAuth
fluency is real but the AST + lattice + adversarial-ML weight on
this scope is not their center of gravity; the cost advantage
does not offset the coverage gap on the highest-risk priorities.
Keep them on the bench for a future scope that is OAuth-first
(MCP authorization metadata, AgentMesh proxy gateway).

## Decision checklist

Before signing the engagement letter, confirm:

- [ ] RFP responses landed from all three vendors by 2026-05-08.
- [ ] Selected vendor confirms kickoff before 2026-05-22.
- [ ] Statement of Work names every priority in
      `external_review_2026.md` Scope section.
- [ ] Re-test of remediation is in scope (bundled or separately
      priced; not deferred).
- [ ] Publication clause: report publishable after remediation,
      with vendor sign-off, in `docs/security/`.
- [ ] Deliverables include reproducible test harness for any
      finding above informational severity.
- [ ] Funding source confirmed (per ADR-0002, project
      sponsorship; not Tessera revenue).

## References

- [`external_review_2026.md`](external_review_2026.md)
  (engagement scoping and vendor candidates)
- `docs/adr/0002-no-hosted-services.md` (funding source
  constraint)
- `docs/adr/0006-arg-level-provenance-primary.md` (why ProvenanceLabel
  shape is load-bearing)
- `docs/strategy/2026-04-engineering-brief.md` Section 5
