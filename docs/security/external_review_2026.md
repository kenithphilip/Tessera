# External threat-model review engagement (Wave 2K)

## Status

Engagement scoping document. Vendor selection in progress; final
report and remediation plan ship in Phase 3.

## Why

Phase 1 froze the load-bearing security substrate of v1.0:
:class:`tessera.taint.label.ProvenanceLabel`, the AST
instrumentation in :mod:`tessera.taint.instrument`, the
declassification rule in :mod:`tessera.taint.label`, the MCP
manifest signing surface in :mod:`tessera.mcp.manifest`, and the
RFC 8707 audience-binding code in :mod:`tessera.mcp.oauth`.
Wave 2K commissions an independent threat-model review of these
boundaries before the v1.0 freeze (Phase 4 wave 4B) so any shape
change discovered during review can land in v0.14 (Phase 3) rather
than slipping past GA.

## Scope

The reviewer is asked to evaluate, in order of priority:

1. **ProvenanceLabel + lattice algebra**. Are the join,
   declassify, and recovery rules airtight? Does every reachable
   call path preserve the documented invariants (commutativity,
   associativity, idempotence; max-of-integrities at join; no
   silent declassification at recovery boundary)?
2. **AST instrumentation**. Does the
   ``@provenance_tracked`` rewrite cover every label-touching
   bytecode path? What happens when a function is decorated more
   than once, or when the function uses dynamic ``compile`` /
   ``exec`` of user-supplied source?
3. **Declassification boundaries**. The Worker recovery boundary in
   :mod:`tessera.worker.recovery` is the only over-taint fallback
   in the system. Walk the matched / unmatched / short-value paths
   for adversarial values; can an attacker construct a value that
   silently lowers the integrity floor?
4. **MCP manifest signing**. Sigstore + DSSE + Rekor inclusion
   proof. Is the cert-chain trust path correct? What about the
   air-gapped HMAC path: does the canonical-JSON encoding leave
   any malleability windows?
5. **RFC 8707 audience binding**. Does the
   :func:`token_audience_check` correctly reject every
   pass-through case? What about a token whose ``aud`` claim is
   the empty string or absent?
6. **Same-planner-as-critic gate**. The opt-in env var
   ``TESSERA_ALLOW_SHARED_CRITIC=1`` is documented as a known-
   weak choice; is the documented threat model accurate?

## Out of scope

Per :file:`SECURITY.md`:

- Direct prompt injection by the authenticated user
- Model-level attacks (backdoors, weight extraction)
- Compromised MCP servers themselves (we defend against them; we
  do not certify them)
- Supply-chain attacks on weights / prompts
- Sandbox escape for agent-generated code
- Semantic poisoning of agent output to the user

## Vendor candidates

Three firms with credible AI / agent security experience:

| Vendor | Rationale |
| --- | --- |
| NCC Group | Deep cryptography review track record; Sigstore + DSSE + RFC 8707 fit. |
| Trail of Bits | Strong AppSec + adversarial-ML practice; AST instrumentation depth. |
| Doyensec | Fast turnarounds on bounded scopes; web + OAuth fluency. |

Final selection: TBD by 2026-05-15. Engagement length: 4 weeks.
Estimated budget: $35-65k (within the open-infra-sustainable
range; funded out of project sponsorship, not Tessera revenue per
ADR-0002).

## Deliverables

The vendor delivers:

1. A written report (~30 pages) with severity-rated findings.
2. A reproducible test harness for any non-trivial finding.
3. A remediation review of the Tessera fixes after they land.

The Tessera team commits to:

1. Triaging every finding within 5 business days.
2. Fixing any critical or high finding before the v0.14 tag.
3. Publishing the report (with vendor sign-off) in
   `docs/security/` once remediation lands.

## Timeline

| Date | Milestone |
| --- | --- |
| 2026-04-25 | Wave 2K kickoff (this doc) |
| 2026-05-15 | Vendor selected, engagement signed |
| 2026-05-22 | Kickoff call; reviewer onboarded |
| 2026-06-19 | Draft report |
| 2026-06-26 | Final report |
| 2026-07-31 | Remediations land in v0.14 |

## References

- ``docs/strategy/2026-04-engineering-brief.md`` Section 5
- ``docs/adr/0001-license-split.md``
- ``docs/adr/0002-no-hosted-services.md``
- ``docs/adr/0006-arg-level-provenance-primary.md``
