---
name: Tessera NCCoE Collaboration Agreement Template
description: IP terms, DCO requirements, and feedback channels for NCCoE integration
version: 0.1
date: 2026-04-25
---

# Tessera NCCoE Collaboration Agreement Template

This document establishes the terms under which Tessera contributes code, documentation, and reference implementations to the NCCoE AI Agent Identity and Authorization practice guide initiative.

## Tessera's Role and Scope

**Contributor:** Tessera is a composable security primitives library maintained by Kenith Philip. It does not seek to own or maintain the practice guide itself.

**Contribution Model:** Tessera contributes:

1. Reference implementation code (Tessera library + example scenarios)
2. Technical documentation (architecture, design decisions, threat model)
3. Test fixtures and reproducible examples
4. Maintainer time for code review, working-group attendance, and integration updates

**Repository Ownership:** The reference implementation lives in the NCCoE repository under the NCCoE's control. Tessera maintains the upstream Tessera library separately. Code shared back to Tessera upstream is synchronized via pull requests.

**Non-Deliverables:** Tessera does not provide:

- Commercial support or SLA commitments
- Funding or grant contributions
- Exclusive endorsement rights
- Trademark licensing

## License Terms

### Inbound (Tessera to NCCoE)

All Tessera contributions are provided under **Apache-2.0** license terms, with the following additional clauses:

- Tessera retains the right to share implementations back to the upstream Tessera library for educational and interop purposes.
- All contributions carry SPDX identifier: `Apache-2.0`
- Copyright attributions must preserve the Tessera maintainer name and original contribution timestamp.

### Outbound (NCCoE's Choice)

The NCCoE is free to choose the outbound license for the practice-guide reference implementation. Recommended choices:

- **CC BY 4.0** (if documentation-heavy; allows attribution-only reuse)
- **Apache-2.0** (if code-heavy; aligns with Tessera upstream)
- **NIST Open License** (if NIST prefers their standard terms)

The NCCoE will declare the outbound license in the reference-implementation repository's LICENSE file at publication time.

## Developer Certificate of Origin (DCO)

All contributors to the Tessera-sponsored reference implementation agree to the **Developer Certificate of Origin v1.1**:

```
Developer Certificate of Origin
Version 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

**Sign-off Requirement:** All commits must include a `Signed-off-by` trailer:

```
Signed-off-by: Kenith Philip <kenith.philip@example.com>
```

Git commit command:

```bash
git commit -s -m "description of change"
```

## Intellectual Property and Patent Assertions

### Patents

Tessera contributors (including Kenith Philip) grant a **royalty-free, worldwide, perpetual license** to any patents held that cover:

- The trust-label and taint-tracking primitives described in the Tessera paper
- The delegation token signing and verification logic
- The hash-chained audit-log design
- The schema-enforced dual-LLM execution pattern

This license extends to any implementations derived from Tessera's code for use in the NCCoE reference deployment and practice guide.

### Copyright and Attribution

All Tessera contributions retain their original copyright notices. When NCCoE republishes Tessera code or derivatives:

- The original copyright notice must be preserved in the source file header
- The SPDX license identifier must remain (Apache-2.0)
- Attribution to Tessera must appear in the repository README or NOTICE file

Example NOTICE entry:

```
Tessera Reference Primitives
Copyright (c) 2026 Kenith Philip
Licensed under Apache-2.0
Available at https://github.com/kenithphilip/Tessera
```

## Feedback and Change Control

### NCCoE Review Process

1. **Draft Period:** NCCoE circulates practice-guide drafts to Tessera for technical review.
2. **Feedback Window:** Tessera maintainer comments on architecture, test coverage, and integration points. Comments due within 2 weeks of draft distribution.
3. **Working Group:** Tessera maintainer attends (typically bi-weekly) NCCoE working-group calls to discuss feedback and coordinate updates to the reference implementation.
4. **Publication:** Once the practice guide is published, Tessera updates the reference implementation to match and tags a release.

### Breaking Changes

If NCCoE requirements change substantially (e.g., new WIMSE wire format), Tessera will:

- Estimate effort required for integration
- Communicate to NCCoE within 5 business days
- Propose a timeline and any scope adjustments
- Include the change in the next versioned release (e.g., v0.13 for significant changes)

### Upstream Synchronization

Code and patterns successfully tested in the NCCoE reference implementation are candidates for inclusion in the upstream Tessera library. Such changes:

- Are proposed by the Tessera maintainer via pull request to the Tessera GitHub repository
- Undergo the same code review and test requirements as any Tessera change
- Are tracked in the Tessera CHANGELOG with attribution to NCCoE feedback (if applicable)

Example changelog entry:

```
## v0.13 (Q3 2026, Week 6)

### Features
- RFC 8707 audience binding enforced on every MCP token per NCCoE practice guide requirements
- Helm chart and air-gapped install scripts (NCCoE feedback: multi-environment support)
```

## Communication and Escalation

### Points of Contact

- **NCCoE Liaison:** [NCCoE program manager name/email]
- **Tessera Maintainer:** Kenith Philip (kenith.philip@fivetran.com or personal repo)
- **Technical Escalation:** If blocking issues arise, escalate via email to both parties within 5 business days

### Cadence

- **Technical Sync:** Bi-weekly working-group calls
- **Status Update:** Monthly written summary from Tessera to NCCoE (if active work in progress)
- **Release Announcement:** Tessera announces new releases on the public repository; NCCoE may reference as available implementation

## Out of Scope

The following are explicitly out of scope for this collaboration:

- NCCoE does not provide funding or grant support
- Tessera does not commit to provide 24/7 support or SLA-backed responses
- Changes to Tessera's core threat model or invariants must be made transparently with public discussion
- Tessera does not endorse NCCoE's guide or practice recommendations; it provides a technical reference only

## Termination

Either party may discontinue collaboration by providing 30 days' written notice. The reference implementation remains open-source under the declared outbound license; future maintenance responsibilities will be clarified at that time.

## References

- Developer Certificate of Origin: https://developercertificate.org/
- Apache License 2.0: https://opensource.org/licenses/Apache-2.0
- RFC 8707: OAuth 2.0 Authorization Server Metadata
- Tessera GitHub: https://github.com/kenithphilip/Tessera
- NCCoE AI Agent Identity and Authorization Initiative: [NCCoE URL]
