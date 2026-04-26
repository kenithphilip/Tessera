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
| Slack / Discord channel | OpenSSF Slack channel #tessera (to be created at sandbox acceptance) |
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

## Filing checklist

- [ ] Solicit a TAC sponsor in `#project-lifecycle` on OpenSSF
      Slack. Pre-written message at
      [`openssf_slack_post.md`](./openssf_slack_post.md). Paste
      verbatim or edit before sending.
- [ ] Submit the sandbox application via the form at
      https://openssf.org/projects/.
- [ ] Open a tracking issue in `kenithphilip/Tessera` so the
      community can follow progress: already done at
      [#19](https://github.com/kenithphilip/Tessera/issues/19).
- [ ] Once accepted, file the additional artifacts (Charter,
      CoC, security-disclosure boilerplate adoption PRs) per
      Step 1 of the transition plan in
      `foundation_proposal_v1_1.md`.

## References

- [`docs/adr/0003-foundation-governance.md`](../adr/0003-foundation-governance.md)
- [`docs/governance/foundation_proposal_v1_1.md`](./foundation_proposal_v1_1.md)
- OpenSSF project lifecycle:
  https://github.com/ossf/tac/blob/main/process/project-lifecycle.md
- OpenSSF charter template:
  https://github.com/ossf/tac/blob/main/process/charter-template.md
