# Application for creating a new project at Sandbox stage

> **DRAFT FOR `ossf/tac` SUBMISSION.** This file is the
> Tessera-side draft of the document that will become
> `process/project-lifecycle-documents/tessera_sandbox_stage.md`
> in the `ossf/tac` repository when filed. Submit by opening a
> PR against [`ossf/tac`](https://github.com/ossf/tac) per
> [`process/project-lifecycle.md`](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md).
> No OpenSSF Slack channel is involved; the application is a
> PR.
>
> **Submission gate**: OpenSSF Sandbox requires **a minimum of
> three maintainers across at least two organisational
> affiliations**. Tessera currently has one maintainer (Kenith
> Philip). Two additional maintainers from a different
> organisation must agree to maintain the project before this
> PR can be opened. See
> [`openssf_sandbox_application.md`](./openssf_sandbox_application.md)
> for the broader transition rationale and recruiting plan.

## List of project maintainers

The project must have a minimum of three maintainers with a
minimum of two different organizational affiliations.

* Kenith Philip, Independent, [@kenithphilip](https://github.com/kenithphilip)
* TBD, TBD, TBD
* TBD, TBD, TBD

## Sponsor

Most projects will report to an existing OpenSSF Working Group,
although in some cases a project may report directly to the
TAC. The project commits to providing quarterly updates on
progress to the group they report to.

* **Supply Chain Integrity WG** is the closest match: Tessera's
  MCP manifest signing pipeline (`tessera.mcp.manifest`) and the
  registry mirror (`tessera.mcp.registry_mirror`) consume
  Sigstore directly via `sigstore-python`, and the trust-tier
  + drift-detection model (Wave 4D) is supply-chain-adjacent.
  Alternative: **Security Tooling WG**, where the per-segment
  taint-tracking primitive sits more naturally as a tooling
  contribution.
* The maintainer commits to attending WG calls and providing
  quarterly reports.

## Mission of the project

The project must be aligned with the OpenSSF mission and either
be a novel approach for existing areas, address an unfulfilled
need, or be initial code needed for OpenSSF WG work. It is
preferred that extensions of existing OpenSSF projects
collaborate with the existing project rather than seek a new
project.

* **Tessera** is a reference implementation of two security
  primitives for LLM agent systems: signed trust labels on
  context segments with taint-tracking at the tool-call
  boundary, and schema-enforced dual-LLM execution. v1.0 GA
  shipped 2026-04-25.
* The primitives address indirect prompt injection (the
  canonical OWASP Agentic ASI01 vector) at the agent's tool-
  call boundary: a context segment fetched from an untrusted
  source carries a cryptographically bound `TrustLabel`
  (HMAC-signed or JWT-SVID), and the policy engine's
  `Decision` is computed against the minimum trust over the
  whole context. Sensitive tool calls deny when any segment is
  UNTRUSTED, regardless of how the segment got into the
  context.
* The project does not duplicate existing OpenSSF work.
  Sigstore (already a Graduated OpenSSF project) is consumed
  for the MCP manifest signing chain; in-toto and SLSA
  attestation formats are emitted via the
  `tessera bench emit-scorecard` CLI; no Sigstore / SLSA
  competitor is being introduced.

## IP policy and licensing due diligence

When contributing an existing Project to the OpenSSF, the
contribution must undergo license and IP due diligence by the
Linux Foundation (LF).

* Tessera library: Apache-2.0 (per ADR-0001). DCO sign-off on
  every commit.
* AgentMesh service (separate repository): AGPL-3.0-or-later;
  not part of this submission.
* No CLA. All inbound contributions are DCO-signed.
* The codebase has no existing LF or other foundation IP
  attachments. The maintainer is the sole copyright holder
  of all in-repo content as of the v1.0 tag.
* Dependency licenses tracked in `pyproject.toml` and
  `cargo deny` config; spot-check confirms Apache-2.0 / MIT /
  BSD-3-Clause throughout, no copyleft transitive deps in the
  Tessera library tree.

## Project References

The project should provide a list of existing resources with
links to the repository, and if available, website, a roadmap,
contributing guide, demos and walkthroughs, and any other
material to showcase the existing breadth, maturity, and
direction of the project.

| Reference          | URL |
|--------------------|-----|
| Repo               | https://github.com/kenithphilip/Tessera |
| Threat model       | https://github.com/kenithphilip/Tessera/blob/main/SECURITY.md |
| Position paper     | https://github.com/kenithphilip/Tessera/blob/main/papers/two-primitives-for-agent-security-meshes.md |
| Contributing guide | https://github.com/kenithphilip/Tessera/blob/main/CONTRIBUTING.md |
| Foundation governance proposal | https://github.com/kenithphilip/Tessera/blob/main/docs/governance/foundation_proposal_v1_1.md |
| API stability matrix | https://github.com/kenithphilip/Tessera/blob/main/docs/api_stability/v1.0_freeze.md |
| Scorecard site     | https://kenithphilip.github.io/Tessera/scorecard/ |
| Compliance taxonomy mappings | MITRE ATLAS, NIST AI 600-1, ISO/IEC 42001 Annex A, CSA AICM 1.0, EU AI Act Articles 9/12/14/15, OWASP Agentic ASI 1-10, NIST CSF, CWE - all wired through `tessera.events_sarif` |
| Test count         | 2046 Python tests passing, ~390 Rust tests, 9 agentgateway plugin tests |
| Red-team corpus    | 1091 raw payloads (~934 unique after dedup) at `corpus/probes/` |
