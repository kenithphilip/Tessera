# ADR 0001: License split (Tessera Apache, AgentMesh AGPL)

- **Status:** Accepted
- **Date:** 2026-04-24
- **Supersedes:** the prior repo-wide AGPL-3.0-or-later license

## Context

Tessera released through and including v0.11.0 under
AGPL-3.0-or-later. The strategic review in
`docs/strategy/2026-04-mesh-review.md` identifies
AGPL-on-the-library as the single most costly OSS license choice
the project could make. The FSF position that dynamic linking
creates a derivative work means an AGPL Python library is
effectively unusable by any enterprise that embeds it in a
proprietary application. The target market for Tessera is exactly
that audience: LangChain / LangGraph / CrewAI / LlamaIndex /
PydanticAI middleware authors who would not bundle an AGPL
dependency.

The companion service AgentMesh sits in a different category.
AGPL on a service is defensible: Grafana, Mattermost, and
Plausible all use the pattern of permissive license on the
library or agents and AGPL on the server. Customers who run
their own AgentMesh deployment are not affected by AGPL's network
distribution clause; only modifications-as-a-service trigger the
copyleft.

## Decision

Tessera (the library at `src/tessera/` and the entire
`kenithphilip/Tessera` repository) re-licenses to Apache-2.0
effective with v0.11.1 on 2026-04-24. The historical AGPL text
is preserved at `LICENSE-AGPL-historical` for reference. The
Apache-2.0 text is at `LICENSE`; the rationale and contributor
sign-off requirements are in `NOTICE` and `CONTRIBUTING.md`.

The companion AgentMesh service (separate repository at
`kenithphilip/AgentMesh`) remains under AGPL-3.0-or-later and is
not affected by this ADR.

Contributions require Developer Certificate of Origin (DCO)
sign-off (`git commit -s`) rather than a CLA. DCO is sufficient
to preserve the project's right to dual-license or re-license
later if necessary, while imposing minimal contributor friction.

## Consequences

Positive:
- LangChain / LangGraph / CrewAI / LlamaIndex / PydanticAI can
  bundle Tessera as a default middleware without forcing their
  consumers into AGPL.
- Foundation contributions (CNCF, LF AI & Data) have a much
  lower legal-review barrier.
- Enterprise PoCs can install `pip install tessera-mesh` without
  mandatory legal review of the import path's license
  implications.

Negative:
- Re-license is irreversible in practice; any contributor whose
  code remains in the repository at the time of the relicense is
  presumed to have consented (the project was solo-maintained
  through v0.11.0 so this is a clean case).
- The AGPL-on-the-library theory of monetization (force SaaS
  cloners to open-source modifications) is gone. The remaining
  monetization paths are the AgentMesh service license, AgentMesh
  Cloud per ADR 0002, and the threat-intel / scorecard services
  per ADR 0002.

Neutral:
- Existing users who pinned `tessera-mesh==0.11.0` keep AGPL
  semantics for that version.

## Alternatives considered

- **Keep AGPL on both library and service.** Rejected because it
  blocks the strategic move toward becoming the default
  middleware called by LangChain et al.
- **MPL 2.0 on the library.** Rejected because Apache-2.0 is the
  more widely understood permissive license for ML / agent
  ecosystem packages (compare PyTorch, Transformers, LangChain
  itself).
- **CLA instead of DCO.** Rejected because CLAs reduce inbound
  contribution rate by 40-60% in industry data and the
  re-license rights DCO preserves are sufficient for the
  forecasted foundation transition path (ADR 0003).

## Implementation

- v0.11.1: `LICENSE` rewritten to Apache-2.0; `NOTICE` added;
  `LICENSE-AGPL-historical` preserved; `CONTRIBUTING.md` updated
  with DCO sign-off section.
- Phase 1 (v0.12) onward: every commit must pass DCO check in
  CI. The DCO bot is configured in repo settings.

## References

- `docs/strategy/2026-04-mesh-review.md` (strategic context)
- https://developercertificate.org/ (DCO text)
- Grafana Labs license precedent:
  https://grafana.com/blog/2021/04/20/grafana-loki-tempo-relicensing-to-agplv3/
