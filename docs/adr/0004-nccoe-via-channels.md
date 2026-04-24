# ADR 0004: NCCoE reference implementation contributed via NCCoE channels

- **Status:** Accepted
- **Date:** 2026-04-24

## Context

CAISI's January 2026 RFI on securing agentic AI systems and the
February 2026 NCCoE concept paper on AI agent identity and
authorization create a high-leverage opportunity for Tessera to
contribute as a reference implementation. The strategic review
recommends Tessera position itself as the canonical reference
implementation.

The question is *where* the reference implementation lives. Two
options:

- **Owned by Tessera.** A Tessera maintainer-owned repository
  branded as the reference implementation. Tessera controls
  release cadence, roadmap, and integrations.
- **Contributed through NCCoE channels.** The reference
  implementation lives in NCCoE's repository (the standard
  NCCoE practice-guide pattern); Tessera contributes
  engineering time and maintenance.

## Decision

The NCCoE reference implementation is contributed through NCCoE
channels, not owned by Tessera. Tessera files the proposal
(Phase 0 wave 0E, doc at
`docs/standards-engagement/nccoe-proposal.md`); the
implementation lives in NCCoE's reference repository per their
standard practice-guide pattern.

Tessera commits to:
- Maintainer time at NCCoE working-group calls.
- Engineering contributions to the NCCoE reference repository.
- Bidirectional sync between the upstream Tessera + AgentMesh
  repositories and the NCCoE reference implementation.

Tessera does not commit to:
- Owning the NCCoE reference repository.
- Funding NCCoE work beyond maintainer time.
- Exclusive reference implementation status.

## Consequences

Positive:
- NCCoE practice guides carry institutional credibility
  (NIST authority) that a maintainer-owned reference
  implementation cannot match.
- Multiple reference implementations serve different deployment
  contexts; Tessera offers one. Other contributors (Microsoft
  Agent Governance Toolkit, agentgateway) can offer parallel
  reference implementations without zero-sum competition.
- Reduces Tessera's perpetual ownership commitment.

Negative:
- Tessera does not control the NCCoE repository's release
  cadence; NCCoE's slower public-sector cycle may lag the
  upstream Tessera roadmap.
- Marketing benefit of "the official NCCoE reference impl" is
  weaker than if Tessera owned the repo.

Neutral:
- The work to keep the reference deployment in sync with
  upstream is similar in either ownership model.

## Alternatives considered

- **Tessera-owned reference repo branded for NCCoE.** Rejected
  per the consequences above; NCCoE's institutional credibility
  is the entire point.
- **Skip NCCoE engagement entirely.** Rejected because the
  competitive landscape (Microsoft Agent Governance Toolkit at
  MIT-licensed; agentgateway at LF) absorbs NCCoE attention
  if Tessera doesn't show up.

## Implementation

- Phase 0 wave 0E: file the proposal (this ADR's companion doc
  at `docs/standards-engagement/nccoe-proposal.md`).
- Phase 3 wave 3I: contribute the reference implementation
  through NCCoE channels.

## References

- `docs/standards-engagement/nccoe-proposal.md`
- `docs/strategy/2026-04-mesh-review.md` Section "Standards
  alignment and compliance posture"
- ADR 0002 (no hosted services; NCCoE deployment is a
  reference, not a hosted service)
