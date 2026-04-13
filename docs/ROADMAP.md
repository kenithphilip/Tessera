# Roadmap

Tessera is the primitives library for agent security meshes. It provides
signed provenance, taint-tracking policy, schema-enforced dual-LLM
execution, delegation, workload identity, and supporting infrastructure.

AgentMesh is the larger goal: a full agent security mesh (the Istio for
LLM agents) that composes Tessera with agentgateway, SPIFFE/SPIRE,
OPA/Cedar, OpenTelemetry, and framework-specific SDKs. The AgentMesh
architecture is specified in `docs/AGENT_SECURITY_MESH_V1_SPEC.md`.

This roadmap covers both. It reflects what has shipped and what we
believe is worth building next. It is not a commitment. Priorities can
change based on community feedback, standards work, and real deployment
experience.

## What has shipped

### v0.0.1 (initial public release, April 2026)

Core primitives:

- Signed `TrustLabel` with HMAC-SHA256 and JWT-SVID signing paths
- Unified `make_segment(..., signer=...)` accepting any `LabelSigner`
- Taint-tracking `Policy` engine enforcing `min(trust_level)` at the
  tool-call boundary
- `QuarantinedExecutor` implementing the dual-LLM pattern
- `strict_worker` Pydantic validator closing the Worker-to-Planner
  free-form-text channel
- Safe-by-default `WorkerReport` with no free-form string fields

Infrastructure:

- FastAPI sidecar proxy reference with chat, discovery, and A2A ingress
- MCP interceptor with auto-labeling and org-level tool registry
- Signed delegation tokens with delegate-to-agent binding in policy and proxy
- Signed prompt provenance envelopes and manifests
- Inbound workload identity verification with proof-of-possession binding
- Live SPIRE Workload API adapters for JWT-SVID retrieval and JWT bundle verification
- SPIFFE-aware mTLS transport identity enforcement from ASGI TLS and trusted XFCC
- A2A security carriage helpers plus live A2A JSON-RPC mediation in the reference proxy
- Binary content marker-ification preventing base64 smuggling
- OpenTelemetry instrumentation across proxy, MCP, policy, quarantine
- Structured `SecurityEvent` with stdout, OTel, and webhook sinks
- SPIRE docker-compose reference deployment

Documentation:

- Position paper with test-pinned invariants (Appendix A)
- CLAUDE.md, README.md, SECURITY.md, CONTRIBUTING.md, ARCHITECTURE.md
- Offline quarantine demo, OpenAI-backed quarantine demo, injection demo

Test coverage:

- 153 tests, runtime under 4 seconds
- Integration tests against the real `mcp` Python package
- SPIFFE JWT-SVID round-trip tests with in-test RSA keypairs
- SPIRE Workload API adapter tests against modern `spiffe` and legacy `pyspiffe` shapes
- mTLS transport identity tests covering ASGI TLS and trusted XFCC
- Security event emission tests
- Binary content smuggling prevention test

## What is likely next (v0.1, v0.2)

Ordered by security payoff per engineering effort.

### High leverage, small effort

1. **Benchmark against CaMeL's reported 6.6x latency cost.** A
   microbenchmark suite for the Tessera primitives in isolation has
   landed under `benchmarks/` and pins the end-to-end per-request
   overhead at roughly 32 microseconds, with Pydantic validation at
   approximately 1 microsecond per call. Paper Section 4.5 has been
   updated with the numbers. What remains is a like-for-like comparison
   against CaMeL on the same workload (a single-LLM baseline, the
   Tessera `strict_worker` dual-LLM path, and a CaMeL interpreter
   reimplementation). That is still open and still the single most
   credibility-building thing we can do next.

2. **Credential isolation at the proxy.** A first cut has landed in
   `tessera.redaction`. The proxy now accepts a `SecretRegistry` and
   scrubs every occurrence of the registered values from outbound
   chat-completion payloads and inbound responses, emitting a
   `SECRET_REDACTED` security event on every hit. This closes the
   "agent accidentally includes a real token in an LLM prompt" and
   "LLM response echoes a known secret back to the agent" classes.

   What is NOT yet built and is still the endgame here: full
   substitute-on-egress for downstream tool calls. The production
   pattern wants the agent process to hold only placeholder tokens and
   have the proxy substitute real values as requests leave the trust
   boundary toward downstream services. That requires the proxy to
   mediate tool traffic (not just chat completions), which is a
   larger architectural change tracked as a follow-up.

2. **Token budget enforcement per principal per day.** Denial-of-wallet
   defense. We now gate delegated `max_cost_usd` per action, but we still
   lack cumulative principal or session budget accounting.

3. **Real SPIRE stand-up in CI.** The `deployment/spire/` reference now
   has live runtime adapters in code, but we still do not prove them
   against a real SPIRE server in CI. Stand up the stack, issue a
   JWT-SVID to a workload, present it as `ASM-Agent-Identity`, and
   verify it from live trust bundles.

### Next tier

4. **Cedar or OPA integration.** `Policy` is now strong, but still
   local. If Tessera is going to smell like enterprise infrastructure,
   it needs a portable policy surface and a real backend for
   attribute-based decisions, policy packaging, and evaluation beyond one
   process.

5. **Performance program.** Build a benchmark harness for proxy latency,
   policy throughput, A2A and MCP hot paths, and attack-effectiveness
   evaluations. Right now we have correctness and security properties,
   but not an infrastructure performance story.

6. **Observability hardening.** Finish the OTel story with GenAI
   semantic convention attributes, convert the sync webhook sink to a
   bounded async path, and add evidence-oriented exports instead of
   relying only on raw event sinks.

### Bigger bets

7. **Rust data plane maturation.** A reference Rust gateway has landed
   in `rust/tessera-gateway/` with HMAC/JWT label verification,
   taint-floor policy, OPA callout, A2A JSON-RPC support, mTLS with
   SPIFFE SAN extraction, evidence bundles, and 40 tests. The next
   step is contributing these primitives upstream to agentgateway as a
   middleware plugin, not maintaining a parallel proxy.

8. **AgentMesh SDK.** The integration layer that composes Tessera with
   agentgateway, SPIFFE/SPIRE, OPA/Cedar, and OpenTelemetry into a
   single installable package with framework adapters. This is the
   "AgentMesh" product layer on top of the Tessera primitives library.

### Still valuable, but not first

9. **DPoP token binding (RFC 9449) for agent-to-tool calls.** Each agent
   instance holds a non-extractable private key; tool calls carry
   DPoP-bound tokens that cannot be replayed by other agents.
   Eliminates the confused-deputy class of attacks. Standard OAuth
   infrastructure, not AI-specific.

10. **MCP SEP-1913 interop.** Once the SEP lands, the MCP interceptor
    should ingest `trust_level` annotations from tool outputs directly,
    rather than relying on per-deployment external-tool registries.

11. **Multi-principal `Context`.** Current `Context.principal` returns
    the first USER segment's principal. Real shared agents carry
    segments from multiple users, and policy decisions should reflect
    all of them, not just one. Adds a `principals()` iterator and a
    richer `POLICY_DENY` event carrying the full set.

12. **IETF draft for content-bound provenance labels.** Submit a short
    draft to the WIMSE working group specifying the TrustLabel
    structure, its canonical serialization, and its HMAC and JWT-SVID
    signing modes. Gives the agent mesh ecosystem a shared interop
    format instead of each project inventing its own.

13. **OWASP Agentic AI Top 10 entry for "unconstrained worker output in
    dual-model architectures."** Submit as a named weakness category.
    Provisional name: ASI-DUAL-LLM-BYPASS.

## What we are deliberately not building

14. **A production control plane.** `tessera.control_plane` is a
    reference integration surface for testing policy distribution and
    agent heartbeats. It is not a production control plane. Istio has
    Istiod, agentgateway is building its own control plane, Microsoft
    has the Agent Governance Toolkit. AgentMesh should compose with
    those, not compete. The reference module exists so the primitives
    have something to integrate against in tests, not as a product.

15. **A competing data plane proxy.** The Rust gateway in
    `rust/tessera-gateway/` is a reference implementation proving the
    primitives port cleanly to a Rust data plane. The goal is to
    contribute these primitives upstream to agentgateway (Linux
    Foundation) or an equivalent production proxy, not to maintain a
    parallel gateway long-term.

16. **Attention-level trust masking (CIV).** The paper acknowledges this
    as experimental and single-author. We are not in a position to
    verify or validate this line of work. If it matures and the
    academic community validates it, we can add it as an optional
    enforcement layer.

17. **Firecracker or gVisor orchestration.** Real work, wrong team. E2B,
    Blaxel, and Google's Agent Sandbox on GKE own this space. Tessera
    and AgentMesh should interop with them at the proxy level, not
    replicate them.

18. **Tetragon TracingPolicy templates for agent workloads.** Platform
    team responsibility, not security library responsibility. Tessera
    should document how to compose with Tetragon, not ship policies.

19. **A new MCP client implementation.** The official `mcp` package is
    fine, and the Protocol-based abstraction in `tessera.mcp` lets us
    wrap any client that satisfies the interface. We are not building
    a competing MCP client.

20. **A dashboard or UI.** Security events go to SIEMs, observability
    data goes to OTel backends. Both of those ecosystems have mature
    UIs. We do not need to build another one.

## Versioning policy

Tessera uses semantic versioning with the understanding that everything
before v1.0.0 is experimental. We will bump:

- **Patch version** (0.0.x) for bug fixes and docs.
- **Minor version** (0.x.0) for new features that do not break the
  public API.
- **Major version** (x.0.0) for breaking changes to the public API.

v1.0.0 is gated on:

- Completion of items 1, 2, 4, 5, and either 7 or 12 above.
- At least one independent production deployment.
- Stable `TrustLabel` serialization format that we are willing to
  freeze as an interop standard.

We do not have a date for v1.0.0. We will get there when the primitives
are stable in real deployments, not before.

## Contributing to the roadmap

If you think an item belongs higher, lower, or on the "not building"
list, open an issue. The roadmap is a living document and the best
argument wins, not the loudest.
