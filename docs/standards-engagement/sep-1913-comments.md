# SEP-1913 working-group review comments

Tessera's planned engagement on the MCP Specification Enhancement
Proposal 1913 (Sam Morrow / Robert Reichel), the canonical wire
format for trust and sensitivity annotations. Drafted 2026-04-24
under v0.12 to v1.0 plan, Phase 0 wave 0D. To be filed on GitHub
PR #1913 in the modelcontextprotocol/specification repo, plus
one upstream issue.

## Why Tessera engages

Tessera implements provenance labels (`ProvenanceLabel`) that map
1:1 onto SEP-1913's annotation surface (`sensitiveHint`,
`privateHint`, `openWorldHint`, `attribution`). If SEP-1913 ships
with a schema that diverges from Tessera's existing wire format,
adapter code is required for every integration. If SEP-1913 ships
with a schema that includes Tessera's enriched fields
(`manifestDigest` per attribution, normative `applyMonotonic`),
Tessera becomes the reference implementation by default. The
engagement target is to influence SEP-1913 toward the second
outcome.

## Review comment 1: mandatory `manifestDigest` inside `attribution`

The current draft of `attribution` in SEP-1913 carries only
`uri`. This loses the binding between an attributed value and the
specific MCP manifest version that produced it. A server that
silently changes its tool definitions (rug-pull attack, see
Invariant Labs April 2025 disclosure) breaks attribution
monotonicity if the digest is not pinned per attribution entry.

Proposed schema delta (additive, backward-compatible):

```json
"attribution": [{
  "uri": "mcp://gmail.example.com/tools/send_email",
  "manifestDigest": "sha256:a1b2c3..."   // NEW; OPTIONAL in v1, MUST in v2
}]
```

Rationale:
- Matches Tessera's `SegmentRef.manifest_digest` field, which is
  already wire-compatible with the in-toto Statement format used
  in `tessera/mcp/manifest.py`.
- Aligns with the broader supply-chain integrity push: PEP 740
  (Python trusted publishers), npm provenance, Sigstore-signed
  containers all pin per-artifact digests.
- Forensic: SOC teams pivoting from a SecurityEvent to "which
  manifest version produced this label" need the digest in-band.

## Review comment 2: normative `applyMonotonic` algorithm

SEP-1913 establishes monotonic escalation as a property
(`openWorldHint=true` once, stays true for the session) but does
not specify the algorithm. Implementers will diverge on:

- Per-segment vs per-session granularity.
- Whether `sensitiveHint` escalates by string ordering
  (`low` → `med` → `high`) or by enumeration.
- Whether `privateHint` is a separate dimension or implied by
  `sensitiveHint=high`.
- Whether escalation propagates across `attribution` join.

Proposed normative algorithm in the SEP text:

```
applyMonotonic(session_state, incoming_annotation) -> session_state':
  for each annotation key K in {sensitiveHint, privateHint, openWorldHint}:
    session_state'[K] = MAX(session_state[K], incoming_annotation[K])
  for each attribution A in incoming_annotation.attribution:
    session_state'.attribution = session_state.attribution UNION A
  return session_state'

where MAX is defined as:
  - sensitiveHint: low < medium < high
  - privateHint:   false < true
  - openWorldHint: false < true
```

Rationale: without this, two compliant implementations of
SEP-1913 produce divergent session labels for the same input
sequence, which makes the spec untestable.

## Review comment 3: clarify `dataClass` vocabulary

`dataClass` is mentioned in early SEP-1913 drafts as a
free-form string. For SARIF / SIEM consumers, a fixed
vocabulary is operationally critical. Tessera proposes:

```
dataClass enum:
  - public
  - internal
  - confidential
  - regulated:gdpr
  - regulated:hipaa
  - regulated:pci-dss
  - regulated:sox
  - regulated:cui  (US Controlled Unclassified Information)
```

Allows SIEM tools to filter on `dataClass=regulated:hipaa`
without parsing free-form strings. Tessera's
`SecrecyLevel.REGULATED` already carries a parallel sidecar of
this shape; if SEP-1913 standardizes the same set, the sidecar
goes away.

## Upstream issue: signed-manifest interop test fixture

A separate upstream issue (not on PR #1913 itself):

> Title: SEP-1913 reference fixtures for signed manifest +
> annotation interop
>
> Body: As SEP-1913 stabilizes, the working group needs a small
> set of canonical input/output fixtures that any compliant
> implementation can validate against. Tessera proposes
> contributing the following:
>
> 1. A signed in-toto Statement (DSSE + Sigstore) for a sample
>    MCP manifest with three tools.
> 2. The expected `attribution` annotation shape for a tool
>    output that joins data from two of those tools.
> 3. A two-step session trace where `openWorldHint` escalates
>    from false to true on segment 2, with the expected
>    `applyMonotonic` output state after each step.
>
> These would live in
> `modelcontextprotocol/specification/fixtures/sep-1913/` and be
> referenced from the spec text as the conformance suite.
>
> Tessera maintainers commit to keeping the fixtures up to date
> through v1.0; thereafter they would transition to working-
> group ownership.

## Engagement plan

- Week 1 (Phase 0 wave 0D): file the three review comments above
  as line comments on PR #1913.
- Week 2: file the upstream issue referenced above.
- Weeks 3 onward: respond to other reviewers' replies; iterate.
- Phase 4 wave 4C: assume PR merge or ship Tessera-internal
  schema with a compat shim if PR has not merged by then.

## Authors and contact

Drafted by the Tessera maintainer (Kenith Philip) on 2026-04-24
as part of the v0.12 to v1.0 plan, Phase 0 wave 0D. Feedback
welcome via GitHub issues on the `kenithphilip/Tessera` repo.

## References

- PR #1913:
  https://github.com/modelcontextprotocol/specification/pull/1913
- in-toto Statement v1:
  https://in-toto.io/Statement/v1
- Sigstore keyless signing:
  https://docs.sigstore.dev/cosign/keyless/
- Tessera mcp/manifest.py (Phase 2 wave 2B-i):
  see `docs/strategy/2026-04-engineering-brief.md` Section 3.3
