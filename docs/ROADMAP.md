# Roadmap

Tessera is a reference implementation of two primitives documented in
[`../papers/two-primitives-for-agent-security-meshes.md`](../papers/two-primitives-for-agent-security-meshes.md).
This roadmap reflects what has shipped and what we believe is worth
building next. It is not a commitment. Priorities can change based on
community feedback, standards work, and real deployment experience.

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

- FastAPI sidecar proxy reference (~160 lines)
- MCP interceptor with auto-labeling and org-level tool registry
- Binary content marker-ification preventing base64 smuggling
- OpenTelemetry instrumentation across proxy, MCP, policy, quarantine
- Structured `SecurityEvent` with stdout, OTel, and webhook sinks
- SPIRE docker-compose reference deployment

Documentation:

- Position paper with test-pinned invariants (Appendix A)
- CLAUDE.md, README.md, SECURITY.md, CONTRIBUTING.md, ARCHITECTURE.md
- Offline quarantine demo, OpenAI-backed quarantine demo, injection demo

Test coverage:

- 65 tests, ~1,200 lines, 2-second runtime
- Integration tests against the real `mcp` Python package
- SPIFFE JWT-SVID round-trip tests with in-test RSA keypairs
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

2. **Credential isolation at the proxy.** GitHub Agent Workflow Firewall
   pattern: the proxy holds real API keys, the agent process receives
   only placeholder tokens, the proxy substitutes on outbound calls.
   Prevents credential exfiltration via prompt injection. Roughly 100
   lines and one real attack class closed.

3. **Token budget enforcement per principal per day.** Denial-of-wallet
   defense. One counter, one policy check, ~50 lines.

4. **GenAI OTel semantic convention attributes on existing spans.**
   Standardize on `gen_ai.system`, `gen_ai.request.model`,
   `gen_ai.usage.input_tokens`, etc. Interop with the broader
   observability ecosystem for free. ~30 lines.

5. **Convert `otel_log_sink` to real OTel Log Records.** Currently uses
   `span.add_event`, which is not a first-class log. Moving to the OTel
   Logs API lets Datadog Logs, Loki, and other log backends receive
   security events as proper logs.

6. **Async `webhook_sink` with a bounded queue.** Current implementation
   uses synchronous `httpx.Client`. Fine for low event rates, but under
   high deny volume a slow SIEM can stall the agent loop. Add a
   background worker with a bounded queue.

### Medium leverage, medium effort

7. **DPoP token binding (RFC 9449) for agent-to-tool calls.** Each agent
   instance holds a non-extractable private key; tool calls carry
   DPoP-bound tokens that cannot be replayed by other agents.
   Eliminates the confused-deputy class of attacks. Standard OAuth
   infrastructure, not AI-specific.

8. **MCP SEP-1913 interop.** Once the SEP lands, the MCP interceptor
   should ingest `trust_level` annotations from tool outputs directly,
   rather than relying on per-deployment external-tool registries.

9. **Cedar or OPA policy backend integration.** The `Decision` object
   is designed to compose with attribute-based engines. A reference
   integration would let users evaluate taint first (Tessera) and
   attributes second (Cedar/OPA) in a single pipeline.

10. **Agent Card `.well-known/agent.json` served by the proxy.** A2A
    discovery protocol primitive. Lets other mesh components find and
    authenticate to a Tessera-protected agent.

11. **Multi-principal `Context`.** Current `Context.principal` returns
    the first USER segment's principal. Real shared agents carry
    segments from multiple users, and policy decisions should reflect
    all of them, not just one. Adds a `principals()` iterator and a
    richer `POLICY_DENY` event carrying the full set.

12. **Real SPIRE stand-up in CI.** The `deployment/spire/` compose file
    is correct by inspection but has not been exercised end-to-end.
    GitHub Actions workflow that brings up the stack, issues a JWT-SVID
    to a test workload, signs a labeled segment, and verifies it from
    a second workload. Turns "reference" into "continuously verified."

### High leverage, larger effort

13. **Rust port of the proxy primitives.** The FastAPI reference is a
    specification, not a production artifact. The primitives belong in
    a data-plane proxy that can handle 10k+ QPS. Obvious targets:
    agentgateway (Linux Foundation), kgateway (CNCF), a standalone Rust
    sidecar. Must pin the same invariants the Python reference pins,
    enforced by the same test names listed in Appendix A of the paper.

14. **IETF draft for content-bound provenance labels.** Submit a short
    draft to the WIMSE working group specifying the TrustLabel
    structure, its canonical serialization, and its HMAC and JWT-SVID
    signing modes. Gives the agent mesh ecosystem a shared interop
    format instead of each project inventing its own.

15. **OWASP Agentic AI Top 10 entry for "unconstrained worker output in
    dual-model architectures."** Submit as a named weakness category.
    Provisional name: ASI-DUAL-LLM-BYPASS.

## What we are deliberately not building

16. **A new control plane.** Istio has Istiod, agentgateway is building
    its own control plane, Microsoft has the Agent Governance Toolkit.
    Tessera should not compete. The primitives must work under any
    control plane, from none to fully distributed. A Tessera-branded
    control plane would fragment the ecosystem we are trying to
    integrate with.

17. **Attention-level trust masking (CIV).** The paper acknowledges this
    as experimental and single-author. We are not in a position to
    verify or validate this line of work. If it matures and the
    academic community validates it, we can add it as an optional
    enforcement layer.

18. **Firecracker or gVisor orchestration.** Real work, wrong team. E2B,
    Blaxel, and Google's Agent Sandbox on GKE own this space. Tessera
    should interop with them at the proxy level, not replicate them.

19. **Tetragon TracingPolicy templates for agent workloads.** Platform
    team responsibility, not security library responsibility. Tessera
    should document how to compose with Tetragon, not ship policies.

20. **A new MCP client implementation.** The official `mcp` package is
    fine, and the Protocol-based abstraction in `tessera.mcp` lets us
    wrap any client that satisfies the interface. We are not building
    a competing MCP client.

21. **A dashboard or UI.** Security events go to SIEMs, observability
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

- Completion of items 1, 2, 4, 7, and either 13 or 14 above.
- At least one independent production deployment.
- Stable `TrustLabel` serialization format that we are willing to
  freeze as an interop standard.

We do not have a date for v1.0.0. We will get there when the primitives
are stable in real deployments, not before.

## Contributing to the roadmap

If you think an item belongs higher, lower, or on the "not building"
list, open an issue. The roadmap is a living document and the best
argument wins, not the loudest.
