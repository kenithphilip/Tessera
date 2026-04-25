# Upstream PR Roadmap

This directory holds drafts for the eight upstream PRs called for by
Wave 2H (framework partnerships) and Wave 3H (agentgateway plugins)
of the v0.12-to-v1.0 plan.

These are drafts only. Filing them requires a human (Tessera org
account) to fork the upstream repo, push the branch, and open the PR
through the GitHub UI; CI cannot do it without committing in your
name and accepting DCO sign-off in your name. Use these documents
as the starting point, not the final state.

## Legend

| Symbol | Meaning |
| --- | --- |
| READY | The Tessera-side artifact is complete; only the upstream submit step remains. |
| GATED | The Tessera-side artifact is complete but the upstream project does not have an obvious mechanism to receive it. A discussion issue should land before the PR. |
| PARTIAL | Adapter exists but needs a usage example or a docs section before the PR is reviewable. |

## Wave 3H: agentgateway plugins

Upstream: https://github.com/agentgateway/agentgateway (Apache-2.0,
LF org). NOTE: the plan and `rust/agentgateway-plugins/README.md`
both point at `solo-io/agentgateway`, which does not exist. The
real upstream is `agentgateway/agentgateway` and the README needs
to be corrected as part of the first PR.

The repo's top-level `crates/` workspace contains `agentgateway`,
`agentgateway-app`, `cel-fork`, `celx`, `core`, `hbone`,
`htpasswd-verify-fork`, `pool`, `protos`, `xds`, `xtask`. There is
no `plugins/` directory; agentgateway does not yet appear to have a
formal plugin extension mechanism. **Each of these three PRs needs
a discussion issue first** to confirm whether the upstream wants to
absorb plugin crates wholesale, expose a plugin trait, or accept
inline integration into the existing crates.

| PR | Status | Draft |
| --- | --- | --- |
| spiffe-svid-validator | GATED | [`3h-spiffe-svid-validator.md`](./3h-spiffe-svid-validator.md) |
| audit-event-sink | GATED | [`3h-audit-event-sink.md`](./3h-audit-event-sink.md) |
| mcp-drift-scanner | GATED | [`3h-mcp-drift-scanner.md`](./3h-mcp-drift-scanner.md) |

## Wave 2H: framework partnerships

These are docs PRs: each adds a short section to the framework's
documentation showing how to wire Tessera as a recommended
guard / callback. The adapter modules already exist in
`src/tessera/adapters/`. Per ADR-0001 the bundled library is
Apache-2.0 (Tessera), not AGPL (AgentMesh service), so no license
collision with the upstream MIT projects.

| PR | Adapter module | Status | Draft |
| --- | --- | --- | --- |
| LangChain | `langchain.py` (287 lines) | READY | [`2h-langchain.md`](./2h-langchain.md) |
| LangGraph | `langgraph.py` (168 lines) | READY | [`2h-langgraph.md`](./2h-langgraph.md) |
| CrewAI | `crewai.py` (131 lines) | PARTIAL | [`2h-crewai.md`](./2h-crewai.md) |
| LlamaIndex | `llamaindex.py` (181 lines) | READY | [`2h-llamaindex.md`](./2h-llamaindex.md) |
| PydanticAI | `pydantic_ai.py` (170 lines) | READY | [`2h-pydantic-ai.md`](./2h-pydantic-ai.md) |

## Process

1. Open a tracking issue in `kenithphilip/Tessera` for each PR so
   reviewers across both repos can converge on the same thread.
2. For GATED PRs, file a discussion issue upstream first. Wait for
   maintainer signal before opening the actual PR.
3. For READY / PARTIAL PRs, fork the upstream repo, push the
   change, open the PR, and DCO-sign every commit per ADR-0001.
4. Link the upstream PR back into the Tessera issue from step 1.
