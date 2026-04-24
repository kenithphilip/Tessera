# ADR 0003: Foundation governance proposal at v1.1, not v1.0

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

The strategic review recommends foundation governance (CNCF,
Linux Foundation AI & Data, Apache Software Foundation, or the
new Agentic AI Foundation) by v1.0 to address the solo-maintainer
bus factor and unlock enterprise trust at scale.

Foundation transition before v1.0 has costs:
- Foundations want signal that a project is worth absorbing
  (typically: design partners, real adoption, operational
  history). Premature transition reduces leverage in the
  governance terms negotiated.
- Foundation requirements (DCO already covered in ADR 0001;
  trademark transfer; project IP audit; bylaws) take 6-12
  months to satisfy and are easier with the API frozen at v1.0
  than negotiated mid-flight.

Foundation transition at v1.0 also has costs:
- Conflates the API freeze (which is engineering) with the
  governance transition (which is legal / political).
- Risks the foundation's legal review blocking the v1.0 release
  date.

## Decision

Foundation governance is a v1.1 deliverable, not v1.0. The v1.0
release ships under the existing solo-maintainer governance
with Apache-2.0 + DCO (per ADR 0001).

Phase 4 wave 4J drafts the foundation governance proposal as a
v1.1 input; the actual transition (foundation choice, bylaws
adoption, IP transfer or assignment) happens in v1.1, expected
2027-Q2 or later depending on adoption signal.

## Consequences

Positive:
- v1.0 is shippable on the planned schedule (Phase 4, weeks 22
  to 30) without external blocking dependencies.
- More leverage in foundation negotiations because v1.0 has
  shipped, has proven adopters, and has a year of operational
  evidence by transition time.

Negative:
- Solo-maintainer bus factor remains a real risk through v1.0;
  ADR 0007 captures the related concern of provenance label
  shape stability.
- Enterprise procurement may delay buying Tessera until
  foundation transition is visible.

Neutral:
- The OSS license (Apache-2.0 per ADR 0001) is foundation-
  friendly regardless of transition timing.

## Alternatives considered

- **Foundation transition at v1.0.** Rejected per the analysis
  above: bundles two large risks (engineering API freeze + legal
  / governance transition) into one release.
- **No foundation transition; stay solo-maintained.** Rejected
  because bus factor is a real procurement blocker for
  enterprise customers and a real liability for OSS
  infrastructure of this category.

## Implementation

- Phase 4 wave 4J: draft the foundation governance proposal
  document. Identifies preferred foundation (likely CNCF or LF
  AI & Data given the agentgateway precedent), proposed
  governance structure, and IP transfer terms.
- v1.1: actual transition. ADR 0008 (future) captures the
  foundation choice and rationale.

## References

- `docs/strategy/2026-04-mesh-review.md` (strategic context)
- ADR 0001 (license split)
- ADR 0002 (no hosted services)
