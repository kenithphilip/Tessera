# OpenSSF Sandbox application: Tessera

This is the prepared application for OpenSSF sandbox-tier
project status. It tracks the fields requested by the OpenSSF
Project Lifecycle (https://github.com/ossf/tac/blob/main/process/project-lifecycle.md)
sandbox application form.

**Status**: drafted, awaiting maintainer go-ahead per
[`foundation_proposal_v1_1.md`](./foundation_proposal_v1_1.md).
No fields are placeholders; every value below is the value to
submit when the application is filed.

## Application metadata

| Field | Value |
| --- | --- |
| Project name | Tessera |
| Project URL | https://github.com/kenithphilip/Tessera |
| Project category | Supply chain security: signed provenance and runtime enforcement for AI agent context |
| Repository license | Apache-2.0 |
| Application date | filed when ADR-0003 maintainer acceptance lands |
| Sponsor (TAC member) | TBD: requires solicitation in OpenSSF #project-lifecycle |

## Project description (200 word abstract)

Tessera is a reference implementation of two security primitives
for LLM agent systems: signed trust labels on context segments
with taint-tracking at the tool-call boundary, and
schema-enforced dual-LLM execution that closes the
Worker-to-Planner injection channel from Simon Willison's pattern.
v1.0 ships a frozen Python library, a Rust workspace mirror, 11
crates, 2045 passing tests, and a 1091-payload red-team corpus.
The signing chain depends directly on Sigstore (existing OpenSSF
project) and the threat-model coverage maps to MITRE ATLAS,
NIST AI 600-1, ISO/IEC 42001 Annex A, CSA AICM 1.0, EU AI Act
Articles 9/12/14/15, OWASP Agentic ASI 1-10, NIST CSF, and CWE.
Three Rust plugins are filed upstream with agentgateway
(SPIFFE SVID validation, hash-chained audit sink, MCP behavioral
drift). Five framework adapters (LangChain, LangGraph, CrewAI,
LlamaIndex, PydanticAI) wire Tessera as a recommended security
callback. The library is deployed as the security substrate
under AgentMesh (separate project, AGPL-3.0).

## Maintainership

| Field | Value |
| --- | --- |
| Current maintainer count | 1 |
| Lead maintainer | Kenith Philip (`kenithphilip` on GitHub) |
| Lead maintainer email | (per OpenSSF intake form) |
| Active reviewers | none on top of the lead |
| CFP for additional maintainers | will run for 30 days following sandbox acceptance per `foundation_proposal_v1_1.md` Step 2 |
| Initial Steering Committee target | 3-5 members; CFP planned for 2026-Q4 |

The single-maintainer position is one of the explicit reasons
for filing now: sandbox tier creates the institutional home
that lets the project absorb additional maintainers under
governance instead of accumulating them ad hoc.

## Code, build, and security posture

| Field | Value |
| --- | --- |
| Primary language | Python 3.12+, Rust 1.78+ |
| LOC count | ~50,000 Python + ~21,000 Rust (cargo loc) |
| Test count | 2045 Python tests passing, ~390 Rust tests, 9 agentgateway plugin tests |
| Test runtime | ~15 s Python suite, ~30 s Rust workspace |
| CI provider | GitHub Actions |
| CI workflows | `ci.yml` (Python tests), `wheels.yml` (manylinux + macOS + Windows wheels), `publish-scorecard.yml` (Hugo gh-pages on tag), `registry-mirror.yml` (nightly cron) |
| Coverage | not measured (test count + per-invariant pinning is the equivalent contract) |
| Static analysis | mypy strict, ruff, cargo clippy, cargo deny |
| Signing | Sigstore (Fulcio + Rekor) for release wheels; HMAC fallback for air-gapped |
| Reproducible builds | yes for Rust crates; Python wheels have one source of variance (build timestamp), tracked |
| Dependency policy | tracked in `cargo deny` config + `pip-audit` in CI |
| Disclosure policy | `SECURITY.md` |

## Compliance and standards posture

Tessera's compliance taxonomy mappings (per Phase 0 wave 0C of
the v0.12-to-v1.0 plan) cover:

- MITRE ATLAS technique IDs (AML.T0051.* family) on every
  `SecurityEvent` kind via SARIF tagging.
- EU AI Act Articles 9 (risk management), 12 (logging), 14
  (human oversight), 15 (accuracy / cybersecurity).
- ISO/IEC 42001 Annex A control IDs (A.5 - A.10).
- CSA AICM 1.0 control IDs.
- NIST AI 600-1 12-risk mappings.
- OWASP Agentic ASI 1-10.
- NIST CSF.
- CWE (per scanner finding).

The compliance trail is emitted as SARIF on every
`SecurityEvent` and as in-toto attestations via the
`tessera bench emit-scorecard` CLI.

## Infrastructure and footprint

| Field | Value |
| --- | --- |
| Hosted infrastructure | None: Tessera is a library + reference data plane. AgentMesh Cloud (separate project, separate org) hosts. |
| Mailing list / forum | GitHub Discussions (to be enabled at sandbox acceptance) |
| Slack / Discord channel | OpenSSF Slack workspace channel for the project, name TBD; created via TAC channel-creation request after sandbox acceptance |
| CNAME / domains owned | none |
| Trademark | none registered |

Sandbox tier carries no infrastructure expectations; this row
is for completeness.

## Governance

The current governance model is single-maintainer with public
issue tracking. Sandbox transition triggers:

1. Adoption of the OpenSSF Charter (boilerplate).
2. Adoption of the OpenSSF Code of Conduct.
3. Setup of a public Steering Committee CFP for 30 days.
4. Adoption of the OpenSSF security-disclosure process for
   inbound vulnerability reports (extends the current
   `SECURITY.md`).

Post-sandbox, the project commits to:

- Quarterly maintainer-call schedule.
- Open-by-default decision-making (RFC PRs against
  `docs/adr/`).
- Minimum 14-day comment window on any breaking change to the
  v1.x ABI surface defined in
  `docs/api_stability/v1.0_freeze.md`.

## Sigstore / OpenSSF dependency

Tessera's MCP manifest signing pipeline
(`tessera.mcp.manifest`) and the registry mirror's re-signing
flow (`tessera.mcp.registry_mirror`) both consume Sigstore
directly via `sigstore-python`. Tessera contributing back to
OpenSSF projects (Sigstore, in-toto, SLSA, S2C2F) is part of
the alignment rationale; sandbox tier formalises the
relationship.

## Reasons sandbox is the right tier (vs. incubation)

- Single maintainer.
- Production deployment count: 0 today (v1.0 GA shipped 2026-04-25).
- Outside contribution count: 0 today (DCO sign-off was added in
  Phase 0 wave 0A; first inbound contribution is expected once
  the upstream framework PRs land downstream-of-Tessera).

Incubation tier expects multiple maintainers and active outside
contributions. Sandbox tier is the correct fit for a project at
Tessera's current point and is the on-ramp to incubation as
contributors join.

## Filing process (corrected)

The actual OpenSSF application process is a GitHub PR to
[`ossf/tac`](https://github.com/ossf/tac), not a Slack post.
Per
[`process/project-lifecycle.md`](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md):

1. Fork `ossf/tac`.
2. Add a new file
   `process/project-lifecycle-documents/tessera_sandbox_stage.md`
   using the template structure (already drafted at
   [`tessera_sandbox_stage.md`](./tessera_sandbox_stage.md) in
   this repo; copy-paste verbatim).
3. Update the project list table in the `ossf/tac` README to
   add a row for Tessera with the `Status` cell linking back to
   the new file.
4. Open the PR; it's reviewed by the TAC.
5. Sponsoring WG (Supply Chain Integrity WG or Security Tooling
   WG; see Sponsor section in the application doc) confirms
   willingness to host the project in their working group.

## Submission gate (single-maintainer blocker)

OpenSSF Sandbox tier requires **a minimum of three maintainers
across at least two different organisational affiliations**.

Tessera currently has one maintainer (Kenith Philip). The PR
above cannot land until two additional maintainers from a
different organisation have agreed to maintain the project.

Recruiting plan (companion to the PR; do this before opening it):

1. Reach out to potential co-maintainers via:
   - The 4 framework PR threads currently open (LangChain,
     LlamaIndex, PydanticAI, CrewAI) once they get reviewer
     attention.
   - The
     [`agentgateway/agentgateway#1665`](https://github.com/agentgateway/agentgateway/issues/1665)
     plugin discussion.
   - Direct outreach to the AppSec Working Group at the user's
     employer (Fivetran) and other organisations with stated
     interest in agent security.
2. Document the second-maintainer commit in a public issue at
   `kenithphilip/Tessera` so the OpenSSF TAC can verify when
   reviewing the application PR.
3. Open the `ossf/tac` PR only when the maintainer table in the
   application has 3 names with 2+ orgs.

## After the PR is accepted

- File follow-on PRs in `kenithphilip/Tessera` for OpenSSF
  Charter / Code of Conduct / security-disclosure boilerplate
  adoption per Step 1 of
  [`foundation_proposal_v1_1.md`](./foundation_proposal_v1_1.md).
- Run the public Steering Committee CFP (3-5 members) for 30
  days, per the proposal.

## References

- [`docs/adr/0003-foundation-governance.md`](../adr/0003-foundation-governance.md)
- [`docs/governance/foundation_proposal_v1_1.md`](./foundation_proposal_v1_1.md)
- OpenSSF project lifecycle:
  https://github.com/ossf/tac/blob/main/process/project-lifecycle.md
- OpenSSF charter template:
  https://github.com/ossf/tac/blob/main/process/charter-template.md
