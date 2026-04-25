# Foundation governance proposal (Tessera v1.1 transition)

**Status**: Draft. v1.0 ships under sole maintainer. Foundation
transition tracked for v1.1 per [ADR-0003](../adr/0003-foundation-governance.md).

## Why now

Tessera v1.0 has shipped. The primitives are frozen, the test
surface covers >2000 cases, and the wire format is committed for
the v1.x line. The project is now at the size where:

- Multiple downstream consumers (LangChain, LangGraph, CrewAI,
  LlamaIndex, PydanticAI middleware via Wave 2H) depend on the
  Tessera library
- Three Rust plugins are filed upstream with agentgateway
  (Wave 3H) and the inbound contribution flow needs a clear
  governance owner
- The MITRE ATLAS, NIST AI 600-1, ISO/IEC 42001, CSA AICM, and
  EU AI Act compliance mappings (Phase 0 wave 0C) need
  long-lived stewardship beyond a single maintainer

A foundation transition gives the project an institutional home
that survives any one maintainer's departure and signals to
enterprise adopters that the project is not a single-vendor risk.

## Foundations evaluated

Three foundations were evaluated against criteria below.

| Foundation | License fit | Existing AI work | Governance overhead | Cost |
| --- | --- | --- | --- | --- |
| Cloud Native Computing Foundation (CNCF) | Apache-2.0 default; aligned with ADR-0001 | KubeArmor, Falco, OPA, SPIRE, agentgateway (LF-backed) | Sandbox -> Incubation -> Graduated. ~12 months at minimum to Graduated. | None for sandbox; significant maintainer time for Graduated. |
| Linux Foundation AI & Data | Apache-2.0 default; aligned | LF AI & Data hosts ML projects (ONNX, PyTorch, etc.); less security-focused | Similar tier system, lighter than CNCF for incubation | None for incubation. |
| OpenSSF | Apache-2.0 default; aligned with ADR-0001; closest mission match | Sigstore, in-toto, SLSA, S2C2F. Tessera's MCP signing chain depends on Sigstore directly. | Working group structure rather than incubation tiers; faster initial velocity. | None. |

## Recommendation

Tessera proposes joining **OpenSSF** as a sandbox-tier project
in v1.1. Rationale:

1. **Mission alignment.** OpenSSF charter is "secure software";
   Tessera's mission is "secure agent software". The fit is the
   tightest of the three options.
2. **Dependency overlap.** Tessera's MCP signing chain is built
   on Sigstore (OpenSSF) and in-toto (OpenSSF). Hosting Tessera
   in the same foundation reduces cross-foundation governance
   friction.
3. **Working-group velocity.** OpenSSF's WG structure (rather
   than CNCF's tiered incubation gates) lets Tessera move faster
   in the early v1.x days when the API surface is still
   stabilizing across the v1.x line.
4. **Inbound contribution path.** OpenSSF's documented DCO + ICLA
   path matches what Tessera's CONTRIBUTING.md already requires
   (DCO from Wave 0A).

## Out-of-scope alternatives

- **Apache Software Foundation**: too heavyweight for a
  v1.0-young project; better fit when Tessera has a >5-person
  PMC.
- **Eclipse Foundation**: governance overhead higher than
  OpenSSF; no clear AI-security working group to plug into.
- **Sole-maintainer continuation**: not viable past v1.x given
  the dependency footprint; ADR-0003 commits to a transition.

## Transition steps

| Step | Owner | Target date |
| --- | --- | --- |
| 1. File OpenSSF sandbox application | maintainer | 2026-Q3 |
| 2. Public CFP for an initial Tessera Steering Committee (3-5 members) | maintainer + OpenSSF | 2026-Q4 |
| 3. Migrate `kenithphilip/Tessera` repo ownership to a `tessera-ai` GitHub org | maintainer | 2026-Q4 |
| 4. Adopt OpenSSF code-of-conduct + ICLA addendum to existing DCO | Steering Committee | 2027-Q1 |
| 5. v1.1 ships under foundation governance | Steering Committee | 2027-Q1 |

## What does NOT change

- License: Tessera library remains Apache-2.0 (AGPL-AgentMesh
  service stays AGPL per [ADR-0001](../adr/0001-license-split.md)).
- Wire format: the v1.0 frozen surface holds through v1.x.
- ADR process: existing ADRs remain authoritative; the
  Steering Committee proposes new ADRs via PR.
- Inbound contribution flow: DCO sign-off stays. ICLA is
  ADDITIVE.

## What changes

- Bug bounty + CVE disclosure flow moves from
  `security@tessera-mesh.dev` to OpenSSF's coordinated
  disclosure process.
- Trademark for the "Tessera" name held by OpenSSF (applied via
  USPTO + OpenSSF brand committee).
- Decision-making moves from "single maintainer per ADR" to
  "Steering Committee majority per RFC". ADRs in flight at the
  time of transition complete under the maintainer; new ADRs
  follow the SC process.

## Risks

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| OpenSSF sandbox application rejected | Low | Tessera's primitive list (provenance + dual-LLM + MCP signing) maps cleanly to OpenSSF's existing workstreams; rejection would surface specific feedback we can act on. |
| Initial Steering Committee can't be assembled | Medium | The framework partnership PRs (Wave 2H) plus the agentgateway PRs (Wave 3H) seed natural SC candidates from each downstream community. |
| Maintainer-led work slows after transition | Medium | Pre-transition: ship v1.0 + draft v1.1 plan so the SC inherits a settled roadmap. |
| Trademark dispute | Low | Tessera name is not a registered mark of any other entity; the OpenSSF brand committee has the experience to clear. |

## Decision deadline

This proposal is open through **2026-08-30**. Maintainer
acceptance triggers Step 1 (OpenSSF application). Rejection (or
no decision by the deadline) defers the transition to the v1.2
window.

## References

- [ADR-0001](../adr/0001-license-split.md): Tessera = Apache-2.0
- [ADR-0003](../adr/0003-foundation-governance.md): foundation
  transition tracked for v1.1
- OpenSSF Charter: https://openssf.org/about/governance/
- CNCF Process: https://github.com/cncf/toc/blob/main/process/
- LF AI & Data: https://lfaidata.foundation/
- Sigstore (Tessera dependency): https://sigstore.dev/
- in-toto (Tessera dependency): https://in-toto.io/
