# Agent Security Mesh Gap Audit

**Date:** April 10, 2026

**Scope:** Current Tessera code and docs, plus gap mapping against:

- [README.md](../README.md)
- [SECURITY.md](../SECURITY.md)
- [docs/ROADMAP.md](./ROADMAP.md)
- [docs/AGENT_SECURITY_MESH_V1_SPEC.md](./AGENT_SECURITY_MESH_V1_SPEC.md)
- [docs/OWASP_NIST_CONTROL_MATRIX.md](./OWASP_NIST_CONTROL_MATRIX.md)
- local research drafts at `/Users/kenith.philip/Downloads/AgentMesh.md`
- local research drafts at `/Users/kenith.philip/Downloads/agentmesh-v2-specification.md`

**Standards references used in this audit:**

- NIST AI RMF official resources and playbook
- NIST AI security and resilience guidance
- OWASP GenAI Security Project official release for the Top 10 for Agentic Applications

## Bottom Line

Tessera is no longer a toy. It now provides real deterministic security
primitives for:

- signed trust labels
- signed prompt provenance
- taint-tracked policy evaluation
- signed delegation
- schema-constrained dual-LLM isolation
- MCP security carriage
- A2A security carriage helpers
- a reference proxy with discovery and policy enforcement

That said, it is still not an Istio, Cilium, or Linkerd equivalent for
agents. It is a security library plus a reference proxy. The things that
make infrastructure into infrastructure, production data plane,
control plane, runtime isolation, fleet governance, policy distribution,
compliance evidence, and cross-provider federation, are still missing.

## Verified Repo Status

Verified locally on April 10, 2026:

- `env PYTHONPATH=src .venv/bin/python -m pytest -q` -> `125 passed in 2.39s`
- `wc -l src/tessera/*.py tests/*.py`
  - source: 15 Python modules, about 3,237 lines
  - tests: 14 test files, about 2,856 lines
  - total reviewed Python lines: 6,093

At audit start, several repo documents were stale. Those metadata
drifts have since been corrected in the current tree.

## What Is Implemented Today

### 1. Content Integrity And Provenance

Implemented:

- [src/tessera/labels.py](../src/tessera/labels.py): content-bound `TrustLabel`, HMAC signing, origin and trust enums
- [src/tessera/signing.py](../src/tessera/signing.py): JWT signing and verification, JWKS verification, SPIFFE-friendly verifier paths
- [src/tessera/provenance.py](../src/tessera/provenance.py): `ContextSegmentEnvelope` and `PromptProvenanceManifest`

Assessment:

- This is one of the strongest parts of the project.
- The repo now has a real signed provenance primitive, not just spotlighting markers.

### 2. Deterministic Tool Authorization

Implemented:

- [src/tessera/context.py](../src/tessera/context.py): ordered segments, `min_trust`, spotlighted rendering
- [src/tessera/policy.py](../src/tessera/policy.py): deny-by-default policy engine driven by context taint floor

Assessment:

- This is the core security invariant and it is real.
- Delegation constraints now participate directly in policy evaluation.
- Delegated human approval and domain allowlist checks now participate
  directly in policy evaluation.
- Policy is deterministic and testable without invoking a model.

### 3. Delegation And Local Identity Binding

Implemented:

- [src/tessera/delegation.py](../src/tessera/delegation.py): signed delegation tokens
- [src/tessera/policy.py](../src/tessera/policy.py): delegation-aware policy evaluation
- [src/tessera/proxy.py](../src/tessera/proxy.py): delegate-to-local-identity binding on incoming delegation headers

Assessment:

- This moved beyond proxy-only denial logic.
- The recent fix that binds `delegate` to the local `agent_id` closed a real replay class across agents sharing keys and audiences.
- This is credible application-layer delegation, not yet a complete workload identity stack.

### 4. Dual-LLM Isolation

Implemented:

- [src/tessera/quarantine.py](../src/tessera/quarantine.py): `strict_worker`, `WorkerReport`, `split_by_trust`, `QuarantinedExecutor`

Assessment:

- This is still the cleanest end-to-end control in the codebase.
- It provides a meaningful hardening primitive for high-risk flows.
- It does not replace sandboxing or full plan interpreters like CaMeL-style execution.

### 5. MCP Security Carriage

Implemented:

- [src/tessera/mcp.py](../src/tessera/mcp.py): auto-labeling of tool outputs, binary markerization, `MCPSecurityContext`
- [src/tessera/registry.py](../src/tessera/registry.py): org-level external tool classification

Assessment:

- Good library-level security seam.
- Not yet an MCP-aware gateway or broker.

### 6. A2A Security Carriage

Implemented:

- [src/tessera/a2a.py](../src/tessera/a2a.py): `A2ATaskRequest`, `A2ASecurityContext`, attach/extract helpers, fail-closed verification

Assessment:

- This is a real improvement over pure proxy-only work.
- It creates a consistent security context for agent-to-agent payloads.
- It is still not live A2A mediation.

### 7. Reference Proxy And Discovery

Implemented:

- [src/tessera/proxy.py](../src/tessera/proxy.py): OpenAI-style chat proxy, label verification, prompt provenance verification, delegation verification, policy gating, `/.well-known/agent.json`
- [src/tessera/cli.py](../src/tessera/cli.py): local operator entrypoint

Assessment:

- Useful reference and test harness.
- Explicitly not a production data plane.
- Discovery is honest that MCP transport remains absent and A2A is only
  exposed when a handler is configured on the reference proxy.

### 8. Security Events And Telemetry

Implemented:

- [src/tessera/events.py](../src/tessera/events.py): structured security events
- [src/tessera/telemetry.py](../src/tessera/telemetry.py): OpenTelemetry spans for proxy, policy, MCP, and quarantine

Assessment:

- Solid base for auditability.
- A control matrix now exists at [docs/OWASP_NIST_CONTROL_MATRIX.md](./OWASP_NIST_CONTROL_MATRIX.md).
- Still short of enterprise evidence pipelines and provenance graphing.

## What Is Partial Or Reference-Only

### 1. Proxy And Deployment Model

- The FastAPI proxy is still a reference artifact, per [SECURITY.md](../SECURITY.md).
- There is no ambient or node-level deployment surface.
- There is no high-QPS Rust or Envoy-class implementation.

### 2. SPIFFE And Workload Identity

- JWT/JWKS verification exists.
- SPIFFE-shaped agent IDs exist in discovery and delegation binding.
- End-to-end SPIRE issuance and verification is still not continuously exercised in CI, per [docs/ROADMAP.md](./ROADMAP.md).

### 3. Principal Handling

- [src/tessera/context.py](../src/tessera/context.py) still tracks only the first user principal for attribution.
- Multi-principal context remains an acknowledged future item in [docs/ROADMAP.md](./ROADMAP.md).

### 4. A2A And MCP Infrastructure

- A2A carriage exists only as a library seam.
- MCP security carriage exists only as a client wrapper.
- There is no centralized gateway or federated mediation path.

### 5. Telemetry

- Spans exist.
- Proper OTel log records, GenAI semantic attrs, provenance DAGs, and audit evidence export do not.

## What Is Missing Relative To The Target Architecture

This is the main delta against the target state in the research drafts.

### 1. No Production Data Plane

Missing:

- Rust or Envoy-class proxy
- streaming-aware mediation for SSE and provider streaming APIs
- MCP broker and federation
- A2A runtime endpoint and mediation
- ambient or gateway mode deployment

Why it matters:

- This is the difference between a useful library and mesh infrastructure.
- Your research docs explicitly call for ambient mode and agentgateway-class mediation.

### 2. No Control Plane

Missing:

- policy bundle server
- xDS-like config distribution
- fleet agent registry backend
- centralized trust-domain metadata
- policy versioning and rollout engine
- shadow mode and staged enforcement

Why it matters:

- The “integration layer” is the main missing piece called out in [AgentMesh.md](/Users/kenith.philip/Downloads/AgentMesh.md).
- Without it, Tessera cannot credibly claim mesh behavior across fleets.

### 3. No Real Runtime Containment

Missing:

- Firecracker or gVisor orchestration
- seccomp or syscall policy
- eBPF or Tetragon integration
- egress allowlists and network containment
- kill switches for rogue agent activity

Why it matters:

- Application-layer tool gating is necessary, not sufficient.
- OWASP-style tool misuse and rogue behavior scenarios need hard runtime boundaries.

### 4. No Enterprise-Grade Identity Fabric

Missing:

- mTLS session enforcement
- DPoP token binding
- WIMSE proof tokens
- SPIRE-backed live issuance path in CI or runtime
- cross-provider federation
- standardized agent identity claim set

Why it matters:

- Current identity is artifact-level and application-level.
- Target architecture requires real workload identity and proof-of-possession.

### 5. No Policy Backend Or Portable Policy Surface

Missing:

- Cedar integration
- OPA/Rego integration
- portable policy input schema
- policy compilation, bundling, and distribution
- approval workflows and human-in-the-loop enforcement

Why it matters:

- Current `Policy` is useful but local.
- It does not yet function as a provider-neutral enterprise authorization layer.

### 6. No Supply Chain Security Plane

Missing:

- signed tool manifests
- signed prompt or system-prompt provenance
- attestation for agent packages
- attestation for MCP servers
- Sigstore or SLSA integration

Why it matters:

- Your research docs correctly flag agent supply chain as one of the biggest blind spots.
- The current repo does nothing here.

### 7. No Compliance Evidence Plane

Missing:

- NIST AI RMF profile
- formal implementation profile beyond the current control matrix
- evidence export for audits
- control-to-event traceability
- policy-to-requirement mapping
- operator workflows for approval and override tracking

Why it matters:

- “Compliant” is not a feeling.
- Today Tessera offers primitives, not an audit-ready control system.

### 8. No Performance Program

Missing:

- proxy latency benchmarks
- policy evaluation benchmarks under load
- A2A and MCP throughput tests
- warm path and cold path performance budgets
- attack effectiveness evaluations against a standardized suite

Why it matters:

- The v2 research draft makes performance budgets a first-class design constraint.
- Tessera currently has correctness tests, not an infrastructure performance story.

## Gap Map Against The Research Drafts

### Implemented Now

- signed context segments
- signed prompt provenance manifests
- deterministic taint-tracked tool authorization
- delegation token primitive
- local identity binding for delegation
- dual-LLM isolation
- security event emission
- basic discovery document
- MCP carriage
- A2A carriage

### Partially Implemented

- workload identity
- proxy mediation
- observability
- discovery
- SPIFFE integration
- enterprise policy

### Missing Entirely

- control plane
- ambient mesh deployment
- production proxy
- runtime sandboxing
- eBPF enforcement
- egress control
- budget enforcement
- supply-chain verification
- compliance evidence plane
- cross-provider federation
- portable SDK and framework auto-instrumentation

## OWASP Agentic Security Alignment

Official OWASP material as of December 9, 2025 highlights threats including
agent behavior hijacking, tool misuse and exploitation, identity and
privilege abuse, human trust manipulation, and rogue autonomous
behaviors.

Tessera alignment:

- Strong:
  - behavior hijacking at the tool boundary
  - delegated tool authorization
  - attribution of deny decisions
  - structured provenance and trust binding
- Partial:
  - identity and privilege abuse
  - auditability and observability
  - agent-to-agent trust carriage
- Weak or Missing:
  - runtime containment
  - rogue autonomous behavior response
  - supply-chain risk reduction
  - human trust manipulation controls
  - fleet-wide discovery, inventory, and governance

Inference:

- Tessera is currently best positioned as a strong control for indirect
  prompt injection and tool-boundary authorization.
- It is not yet a full answer to the OWASP top 10 for agentic systems.

## NIST AI RMF Alignment

The NIST AI RMF Core is organized around `Govern`, `Map`, `Measure`, and
`Manage`, and NIST identifies `Secure and Resilient` as a primary
trustworthiness characteristic.

Tessera alignment:

### Govern

Partial:

- security policy primitive exists
- structured security events exist

Missing:

- risk ownership and governance workflows
- formal profiles
- approval processes
- documentation of organizational roles and escalation
- compliance evidence and reporting

### Map

Partial:

- prompt provenance gives real data-origin visibility
- discovery metadata exists for one reference proxy

Missing:

- full fleet inventory
- agent registry
- dependency and provider mapping
- supply-chain mapping
- multi-principal and multi-tenant risk modeling

### Measure

Partial:

- unit and integration tests are strong
- deny decisions are observable

Missing:

- attack-eval program
- benchmark program
- risk scoring
- false positive and false negative tracking
- provenance DAG analytics

### Manage

Partial:

- requests can be denied deterministically
- delegation constraints can fail closed

Missing:

- staged rollout and shadow mode
- budget controls
- egress controls
- human override and approval workflows
- incident response hooks and kill switches

Inference:

- Tessera supports some `Secure and Resilient` technical controls.
- It does not yet provide a credible end-to-end NIST AI RMF implementation profile by itself.

## Most Important Overclaims To Avoid

Do not claim today that Tessera is:

- a production agent mesh
- OWASP-complete
- NIST AI RMF compliant
- enterprise-ready across providers
- a runtime isolation or sandboxing system
- a control plane

The honest claim is narrower and stronger:

Tessera is a reference implementation of several load-bearing primitives
that a real agent security mesh needs, and those primitives are now
substantially more complete than the repo docs currently acknowledge.

## Priority Backlog To Become Real Infrastructure

### Tier 0, Immediate Credibility

1. Update stale repo docs and metrics.
2. Add an explicit control matrix mapping current controls to OWASP and NIST categories.
3. Add benchmark harnesses for proxy, policy, MCP, and A2A paths.

### Tier 1, Data Plane

4. Build a real A2A endpoint into the proxy with verified security context carriage.
5. Add MCP gateway or broker behavior rather than only client wrapping.
6. Implement credential isolation and egress policy enforcement.

### Tier 2, Identity And Policy

7. Integrate Cedar or OPA with a stable policy input schema.
8. Add proof-of-possession paths, DPoP/WIMSE style, and live SPIFFE-backed verification.
9. Add multi-principal context and tenant-safe attribution.

### Tier 3, Runtime And Governance

10. Integrate sandbox orchestration and kill switches for dangerous tools.
11. Build a control plane for policy distribution, registry, and rollout.
12. Add audit evidence exports and approval workflows.

### Tier 4, Federation

13. Standardize cross-provider delegation and provenance interchange.
14. Add supply-chain attestations for prompts, tools, and agent packages.
15. Align the implementation with a real ambient or gateway deployment model.

## Recommended Positioning Right Now

Tessera should be positioned as:

- a reference implementation of signed provenance, delegation-aware taint
  tracking, and dual-LLM isolation
- a useful substrate for a future agent security mesh
- a good place to prototype policy and provenance standards

Tessera should not be positioned as:

- the full mesh
- the control plane
- the production data plane
- the compliance story

## Sources

Local repo sources:

- [README.md](../README.md)
- [SECURITY.md](../SECURITY.md)
- [docs/ROADMAP.md](./ROADMAP.md)
- [docs/AGENT_SECURITY_MESH_V1_SPEC.md](./AGENT_SECURITY_MESH_V1_SPEC.md)
- [src/tessera/](../src/tessera/)
- [tests/](../tests/)

External standards and official guidance:

- [NIST AI RMF overview](https://www.nist.gov/document/about-nist-ai-rmf)
- [NIST AI RMF Core / Playbook](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
- [NIST AI security and resilience guidance](https://www.nist.gov/artificial-intelligence/ai-research-security-and-resilience)
- [OWASP Agentic AI threats and mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [OWASP Top 10 for Agentic Applications release](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
