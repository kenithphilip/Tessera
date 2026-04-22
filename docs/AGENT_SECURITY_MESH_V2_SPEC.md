# AgentMesh v2: Production Specification for Agent Security Infrastructure

**A tiered, performance-budgeted security control plane for agentic AI, from hobby projects to enterprise scale.**

*Version 2.0, April 2026*

**Status:** Architecture spec. AgentMesh ships v0.7.0 on PyPI as
`agentmesh-mesh`: a FastAPI proxy with 39 HTTP endpoints, 15 SDK
adapters (11 framework adapters and 4 coding-agent hook adapters), and
the v0.7.0 supporting primitives (hash-chained audit, decision replay,
deterministic and LLM-driven policy builder, SSRF guard, URL rules)
wired through. The full tiered deployment surface and complete
framework matrix described in this document remain the build target;
the Tessera primitives that underpin them are real and tested. See
`AGENT_SECURITY_MESH_V1_SPEC.md` for the current specification.

---

## Executive Summary

AgentMesh is an open architecture for securing AI agent workloads, modeled on how Istio and Cilium transformed Kubernetes networking. This v2 specification solves three problems the v1 left open: it defines **three concrete deployment tiers** (Solo, Team, Enterprise) so the architecture scales from a single developer to thousands of agents; it provides **hard performance budgets** backed by real benchmarks; and it specifies an **SDK-first developer experience** requiring two lines of code to instrument an agent.

The landscape has moved fast. Microsoft shipped the Agent Governance Toolkit (April 2, 2026), a seven-package system with sub-millisecond policy enforcement. Solo.io's agentgateway hit v1.0 under Linux Foundation governance. The IETF published draft-klrc-aiagent-auth. OWASP released the Agentic AI Top 10. AgentMesh v2 doesn't reinvent these, it composes them into a single coherent system and fills the gaps none of them cover alone.

---

## Part 1: Performance Budget, The Non-Negotiable Numbers

Every security layer adds latency. AgentMesh's design principle is that **total mesh overhead must remain below 1% of end-to-end agent latency**. Since a typical LLM API call takes 500ms–5000ms, the mesh budget is 5–50ms total for all security operations combined.

### Measured Component Latencies

| Component | Operation | Measured Latency | Source |
|-----------|-----------|-----------------|--------|
| **Policy evaluation** (OPA, linear Rego) | Single tool-call authz | **~36μs median, 134μs p99** | OPA benchmarks, prepared queries |
| **Policy evaluation** (OPA, embedded Go lib) | In-process evaluation | **<1μs** (sub-microsecond) | OPA Go library mode |
| **Policy evaluation** (Cedar) | ABAC decision | **<0.1ms p99** | Microsoft AGT benchmarks |
| **Policy evaluation** (WASM-compiled Rego) | Embedded evaluation | **~20× faster than Go interpreter** | OPA WASM benchmarks |
| **agentgateway proxy** | MCP/A2A routing | **sub-millisecond at 10K+ QPS** | Solo.io spec |
| **agentgateway CEL** | Per-expression | **5–500× faster** after v1.0 refactor | agentgateway v1.0 release notes |
| **Istio Ambient (L4 mTLS)** | Per-hop encryption | **8% latency increase** over baseline | arXiv 2411.02267 |
| **Istio Sidecar (L7)** | Per-hop full proxy | **166% latency increase** at 3.2K RPS | arXiv 2411.02267 |
| **Firecracker microVM** | Cold boot to user-space | **≤125ms** (~100ms typical) | Firecracker spec |
| **Firecracker** | Creation rate | **150 microVMs/second/host** | AWS spec |
| **Firecracker** | Memory overhead per VM | **<5 MiB** | Firecracker spec |
| **Tetragon eBPF** | Kernel enforcement | **<1% overhead** | Cilium benchmarks |
| **OpenTelemetry** | Span export (async) | **~0ms on hot path** (batched) | OTel design |

### Total Overhead by Tier

| Tier | Total Added Latency | Components Active |
|------|--------------------|--------------------|
| **Solo** | **<0.5ms** | Embedded policy (WASM) + OTel auto-instrumentation |
| **Team** | **<5ms** | Gateway proxy + OPA/Cedar + OTel + trust labels |
| **Enterprise** | **<15ms** (without sandbox) / **<150ms** (with cold sandbox) | Full mesh: proxy + policy + mTLS + sandbox + eBPF |

These numbers matter because an LLM API call costs 500–5000ms. Even the heaviest Enterprise tier adds <3% overhead. The Solo tier is imperceptible.

---

## Part 2: Three Deployment Tiers

### Tier 1, Solo Mode (Single Developer / Hobby)

**Goal:** Security with zero infrastructure. One `pip install`, two lines of code.

**Architecture:** Everything runs in-process. No sidecar, no proxy, no Kubernetes. The entire mesh collapses to an embedded library.

```
┌─────────────────────────────────────┐
│         Your Python Process          │
│  ┌─────────────────────────────┐    │
│  │   AgentMesh SDK (embedded)   │    │
│  │  ┌──────┐ ┌──────┐ ┌─────┐ │    │
│  │  │Policy│ │ OTel │ │Trust│ │    │
│  │  │(WASM)│ │Auto  │ │Label│ │    │
│  │  └──────┘ └──────┘ └─────┘ │    │
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │   Your Agent (LangChain,     │    │
│  │   CrewAI, OpenAI SDK, etc.)  │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

**What you get:**
- Policy-as-code via YAML (no Rego knowledge needed) or WASM-compiled Rego for power users
- Tool-call allow/deny lists with parameter constraints
- Auto-instrumented OTel traces exported to any backend (Jaeger, Grafana, console)
- Trust labels on tool outputs (Spotlighting-style datamarking)
- Local audit log (JSON lines to stdout or file)
- Token budget enforcement (per-session, per-model)

**What you don't get:** mTLS, cryptographic agent identity, sandbox isolation, eBPF enforcement, multi-agent trust protocols.

**SDK, Two Lines to Start:**

```python
# Python
from agentmesh import init
init()  # Auto-detects framework, loads default policy

# That's it. Your LangChain/CrewAI/OpenAI agent is now instrumented.
```

```typescript
// TypeScript
import { init } from '@agentmesh/sdk';
init();
```

Under the hood, `init()` does four things: (1) monkey-patches supported LLM client libraries (OpenAI, Anthropic, Google) to intercept API calls, (2) hooks into framework extension points (LangChain callbacks, CrewAI decorators, ADK plugins), (3) loads policy from `agentmesh.yaml` in the project root (or uses sensible defaults), (4) initializes OTel auto-instrumentation via OpenLLMetry.

**Default Policy (agentmesh.yaml):**

```yaml
version: "1"
mode: solo

defaults:
  allow_all_tools: true  # Start permissive
  log_level: info
  token_budget:
    per_session: 100000
    per_minute: 10000

rules:
  - name: block-shell-execution
    match: { tool: "shell_exec" }
    action: deny
    message: "Shell execution blocked by default"

  - name: block-dangerous-urls
    match: { tool: "web_fetch", args: { url: { pattern: ".*\\.(exe|sh|bat)$" } } }
    action: deny

  - name: require-approval-for-writes
    match: { tool: { pattern: ".*write.*|.*delete.*|.*send.*" } }
    action: ask_human
    message: "This tool modifies data. Approve?"

trust_labels:
  enabled: true
  mark_tool_outputs: true
  mark_web_content: true

observability:
  export: console  # or "otlp", "file:./traces.jsonl"
```

**Install:**

```bash
pip install agentmesh              # Python
npm install @agentmesh/sdk         # TypeScript
cargo add agentmesh                # Rust
dotnet add package AgentMesh       # .NET
```


### Tier 2, Team Mode (Startup / Small Team)

**Goal:** Shared gateway with centralized policy, suitable for 2–50 agents running in containers or cloud functions.

**Architecture:** A single agentgateway instance acts as the MCP/A2A-aware proxy. Agents connect through it. Policy evaluation happens at the gateway (not in-process). OTel traces flow to a shared collector.

```
┌───────────────────────────────────────────────┐
│                CONTROL PLANE                   │
│  Policy Store (Git) → OPA/Cedar Bundle Server  │
│  Agent Registry (Agent Cards / .well-known)    │
└──────────────────┬────────────────────────────┘
                   │ Policy push
┌──────────────────▼────────────────────────────┐
│            agentgateway (Rust)                  │
│  MCP proxy │ A2A proxy │ LLM API proxy         │
│  ┌────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │Cred    │ │OPA/Cedar │ │Trust Label       │ │
│  │Isolate │ │Policy    │ │Injection         │ │
│  └────────┘ └──────────┘ └──────────────────┘ │
│  ┌────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │Token   │ │Guardrail │ │OTel Span         │ │
│  │Budget  │ │(pluggable│ │Export            │ │
│  └────────┘ └──────────┘ └──────────────────┘ │
└──────────────────┬────────────────────────────┘
          ┌────────┼────────┐
     ┌────▼──┐ ┌───▼───┐ ┌─▼─────┐
     │Agent 1│ │Agent 2│ │Agent N│
     │(SDK)  │ │(SDK)  │ │(SDK)  │
     └───────┘ └───────┘ └───────┘
```

**What Team adds over Solo:**
- Credential isolation: agents never see real API keys (GitHub Agent Workflow Firewall pattern)
- Centralized policy: Git-backed, version-controlled, shadow/dry-run mode before enforcement
- Egress control: restrict which network endpoints agents can reach
- Pluggable guardrails: inline Lakera Guard, NeMo Guardrails, or LLM Guard via gRPC
- Shared observability: all agent traces correlated in a single Grafana/Jaeger instance
- Cost attribution: per-agent, per-team token consumption and cost tracking
- Basic agent identity: API-key-based with HMAC-signed request headers

**Deploy with Docker Compose:**

```yaml
# docker-compose.yml
services:
  gateway:
    image: ghcr.io/agentgateway/agentgateway:v1.0
    ports: ["8080:8080"]
    volumes:
      - ./policies:/etc/agentmesh/policies
      - ./gateway.yaml:/etc/agentmesh/gateway.yaml
    environment:
      - OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    ports: ["4318:4318"]

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports: ["16686:16686"]
```


### Tier 3, Enterprise Mode (Regulated / Multi-Tenant)

**Goal:** Full defense-in-depth with cryptographic identity, sandbox isolation, kernel enforcement, compliance automation, and cross-provider federation.

**Architecture:** The complete five-layer stack from v1, now with concrete implementation choices and tested performance characteristics.

```
┌──────────────────────────────────────────────────────────┐
│                   CONTROL PLANE (HA)                      │
│  SPIRE Server │ Policy Mgmt │ Registry │ Compliance       │
│  (3-replica)  │ (GitOps)    │ (A2A)    │ (MS AGT)         │
└──────┬────────┬─────────────┬──────────┬─────────────────┘
       │        │             │          │
  ┌────▼────────▼─────────────▼──────────▼─────────────────┐
  │ L5: IDENTITY, SPIFFE SVIDs + DPoP + WIMSE Proofs       │
  │ L4: POLICY, OPA/Cedar, <0.1ms p99, shadow mode         │
  │ L3: OBSERVABILITY, OTel GenAI + Provenance DAGs         │
  │ L2: DATA PLANE, agentgateway (ambient, not sidecar)     │
  │ L1: SANDBOX, Firecracker per-tool + Tetragon eBPF       │
  └──────────────────────────────────────────────────────────┘
```

**What Enterprise adds over Team:**

**Cryptographic Identity (SPIFFE/SPIRE):**
- Every agent instance gets a short-lived X.509 SVID: `spiffe://acme.com/ns/trading/agent/analyst/i/a8f3`
- SVIDs carry agent-specific claims: model hash, system prompt hash, tool manifest hash, delegating user
- Automatic rotation (default: 1 hour TTL)
- mTLS on all agent-to-proxy and proxy-to-tool connections
- DPoP-bound OAuth tokens prevent confused-deputy attacks on tool calls
- WIMSE Proof Tokens for inter-agent authentication

**Execution Sandboxing:**
- Firecracker microVMs for untrusted code execution (code interpreters, web scrapers)
- Warm pool of pre-booted VMs eliminates cold-start penalty for interactive workloads
- gVisor for enhanced container isolation of tool servers
- Per-tool-call resource limits (CPU, memory, network, wall-clock time)

**Kernel Enforcement (Cilium Tetragon):**
- eBPF TracingPolicies define per-agent-process OS-level boundaries
- Block unauthorized file access, network connections, binary execution
- Synchronous enforcement: violations blocked before syscall completes
- Limitation acknowledged: eBPF sees syscalls but not LLM semantics, use as baseline guardrail only

**Compliance Automation (Microsoft AGT integration):**
- Automated mapping to EU AI Act, HIPAA, SOC2, PCI-DSS requirements
- OWASP ASI 2026 compliance verification: `agent-compliance verify` produces signed attestation
- Immutable audit logs with tamper-evident hashing
- Evidence collection covering all ten OWASP agentic AI risk categories

**Multi-Tenancy:**
- Namespace-based isolation: each tenant gets its own policy scope, identity trust domain, and observability partition
- Cross-tenant agent calls require explicit federation agreements
- Resource quotas (token budgets, tool call rates) per tenant

**High Availability:**
- SPIRE Server: 3+ replicas with shared datastore (PostgreSQL/MySQL)
- Policy engine: stateless, horizontally scalable (Microsoft AGT pattern)
- Gateway: multiple replicas behind load balancer with sticky sessions for streaming
- Graceful degradation: if control plane is unreachable, data plane continues with last-known-good policy (fail-closed for new agents, fail-open for existing ones, configurable)

---

## Part 3: The SDK Specification

### Design Philosophy: Invisible Security

The SDK follows the OpenTelemetry model: auto-instrumentation that requires minimal code changes. Security should be the default path, not an opt-in feature.

### Auto-Instrumentation Matrix

| Framework | Hook Mechanism | Auto-Detection |
|-----------|---------------|----------------|
| LangChain | Callback handlers | `langchain` import detected |
| CrewAI | Task decorators | `crewai` import detected |
| OpenAI Agents SDK | Middleware | `openai` import detected |
| Google ADK | Plugin system | `google.adk` import detected |
| Anthropic SDK | Client wrapper | `anthropic` import detected |
| LlamaIndex | TrustedAgentWorker | `llama_index` import detected |
| Haystack | Pipeline component | `haystack` import detected |
| PydanticAI | Adapter | `pydantic_ai` import detected |
| Raw HTTP (any provider) | HTTP client patch | Always available |

### SDK Architecture

```
┌──────────────────────────────────────────────┐
│                  AgentMesh SDK                 │
│                                               │
│  ┌──────────┐  ┌──────────┐  ┌─────────────┐│
│  │Framework │  │ Policy   │  │   OTel      ││
│  │Adapters  │  │ Engine   │  │ Exporter    ││
│  │(auto-    │  │(embedded │  │(OpenLLMetry ││
│  │ detect)  │  │ WASM or  │  │ + GenAI     ││
│  │          │  │ remote)  │  │ conventions)││
│  └────┬─────┘  └────┬─────┘  └──────┬──────┘│
│       │              │               │        │
│  ┌────▼──────────────▼───────────────▼──────┐│
│  │            Interceptor Core               ││
│  │  Pre-call: policy check, trust labeling   ││
│  │  Post-call: audit log, token accounting   ││
│  └───────────────────────────────────────────┘│
└──────────────────────────────────────────────┘
```

### Core API

```python
import agentmesh

# Minimal init, auto-detects everything
agentmesh.init()

# Full control
agentmesh.init(
    tier="team",                          # "solo" | "team" | "enterprise"
    policy="./agentmesh.yaml",            # Path, URL, or inline dict
    gateway="http://gateway:8080",        # Team/Enterprise: gateway URL
    identity="spiffe://...",              # Enterprise: SPIFFE ID
    otel_endpoint="http://collector:4318",
    on_deny="log",                        # "log" | "raise" | "ask_human"
)

# Manual policy check (if you need fine-grained control)
decision = agentmesh.check(
    agent_id="researcher-1",
    action="tool_call",
    tool="database_query",
    args={"query": "SELECT * FROM users"},
)
# decision.allowed: bool
# decision.reason: str
# decision.policy_id: str

# Explicit trust labeling
labeled = agentmesh.label(
    content="<web page text>",
    source="web_fetch",
    trust_level="untrusted",
)

# Token budget query
budget = agentmesh.budget()
# budget.remaining: int
# budget.used: int
# budget.limit: int
```

### Policy Language, Three Options

**Option 1: YAML (Solo/Team, no learning curve):**

```yaml
rules:
  - name: restrict-database
    match:
      tool: database_query
      args:
        query: { not_contains: ["DROP", "DELETE", "UPDATE"] }
    action: allow

  - name: email-only-to-contacts
    match:
      tool: send_email
    condition: args.recipient in user.contact_list
    action: allow

  - name: default-deny
    match: { tool: "*" }
    action: deny
```

**Option 2: OPA/Rego (Team/Enterprise, full expressiveness):**

```rego
package agentmesh.policy

default allow := false

allow if {
    input.action == "tool_call"
    input.tool == "database_query"
    not contains(input.args.query, "DROP")
    input.agent.trust_tier >= 2
}

allow if {
    input.action == "tool_call"
    input.tool == "web_search"
    # Any agent can search
}
```

**Option 3: Cedar (Enterprise, formally verified):**

```cedar
permit(
    principal is Agent,
    action == Action::"tool_call",
    resource == Tool::"database_query"
) when {
    principal.trust_tier >= 2 &&
    !(resource.args.query like "*DROP*")
};
```

All three compile to the same internal representation. YAML policies auto-convert to Rego for execution via OPA's WASM backend.

---

## Part 4: Trust Boundary Enforcement, Pragmatic Defense-in-Depth

The v1 spec described trust-labeled context windows as "the hardest unsolved problem." The v2 provides a practical, tiered approach that teams can deploy today.

### Level 0, Baseline (Solo mode, zero config)

**Mechanism:** The SDK automatically wraps tool outputs with Spotlighting-style delimiters before they enter the LLM context.

```
[SYSTEM_DATA_BEGIN source=tool:web_search trust=UNTRUSTED timestamp=2026-04-10T10:00:00Z]
<tool output content here>
[SYSTEM_DATA_END]
```

**Effectiveness:** Reduces indirect prompt injection success from >50% to <2% per Microsoft Research's Spotlighting paper. Not a hard boundary, relies on model behavior.

**Overhead:** Zero measurable latency (string wrapping).

### Level 1, Policy-Gated Actions (Team mode)

**Mechanism:** The gateway evaluates every tool call against policy BEFORE execution. Even if prompt injection succeeds in manipulating the agent's reasoning, the gateway blocks unauthorized actions.

This is where the real security value lives. The model may be tricked into wanting to exfiltrate data, but the policy engine prevents it from calling `send_email` with an unauthorized recipient or accessing a tool outside its allow-list.

**Effectiveness:** Blocks 100% of unauthorized tool calls regardless of prompt injection (deterministic enforcement). Cannot prevent information leakage through authorized channels.

**Overhead:** <0.1ms per policy decision.

### Level 2, Dual-LLM Execution (Enterprise, high-security workflows)

**Mechanism:** Following CaMeL's architecture, separate the planning LLM (sees user instructions, generates execution plans) from the worker LLM (processes untrusted content, has no tool access).

```
User Instruction → Privileged LLM → Execution Plan (pseudo-code)
                                          │
                                    ┌─────▼──────┐
                                    │ Interpreter  │ ← Enforces capabilities
                                    └─────┬──────┘
                                          │
              ┌───────────┬───────────────┼──────────┐
              │           │               │          │
         Tool Call    Tool Call     Quarantined LLM  Tool Call
         (allowed)   (allowed)     (processes web    (allowed)
                                    content, NO
                                    tool access)
```

**Effectiveness:** CaMeL achieves 0% attack success rate for control-flow hijacking. Agent-Sentry achieves 3.7% ASR with 76.3% utility (better tradeoff for most use cases).

**Overhead:** ~3-6× latency increase due to multiple LLM calls and interpreter overhead. Use only for high-risk workflows (financial transactions, code execution, data modification).

### Recommendation Matrix

| Risk Level | Example | Recommended Level |
|-----------|---------|-------------------|
| Low | Search assistant, Q&A bot | Level 0 (Spotlighting) |
| Medium | Document analysis, report generation | Level 1 (Policy-gated) |
| High | Financial transactions, code execution | Level 1 + Level 2 for critical paths |
| Critical | Healthcare decisions, infrastructure management | Level 2 everywhere + human approval gates |

---

## Part 5: Observability, From Traces to Provenance

### Auto-Instrumentation (Two Lines)

The SDK integrates OpenLLMetry for automatic tracing of all LLM calls, tool invocations, and agent-to-agent messages. No manual span creation needed.

```python
agentmesh.init()  # This is all you need

# Everything below is automatically traced:
# - Every LLM API call (model, tokens, latency, cost)
# - Every tool invocation (tool name, args, result, policy decision)
# - Every agent-to-agent message (A2A task ID, sender, receiver)
# - Framework-specific spans (LangChain chains, CrewAI tasks, etc.)
```

### Semantic Conventions (OpenTelemetry GenAI)

All spans follow the emerging OTel GenAI semantic conventions:

```
Span: "llm.chat_completion"
  Attributes:
    gen_ai.system: "openai"
    gen_ai.request.model: "gpt-4o"
    gen_ai.usage.input_tokens: 1523
    gen_ai.usage.output_tokens: 847
    gen_ai.response.finish_reason: "stop"
    agentmesh.agent_id: "researcher-1"
    agentmesh.session_id: "ses_7f3a9b2c"
    agentmesh.policy_decision: "allow"
    agentmesh.trust_tier: 3
  Events:
    gen_ai.content.prompt: {role: "user", content: "..."}
    gen_ai.content.completion: {role: "assistant", content: "..."}
```

### Provenance DAGs (Enterprise)

Beyond linear traces, enterprise deployments track data provenance as directed acyclic graphs. Every piece of data carries metadata about its origin and the transformations applied to it, answering: "Which untrusted source influenced this financial decision?"

The provenance tracker annotates data flow at the proxy level, building a DAG that can be queried post-hoc for compliance investigations.

### Export Targets

| Backend | Solo | Team | Enterprise |
|---------|------|------|------------|
| Console (stdout) | Default | Available | Available |
| JSON Lines file | Available | Available | Available |
| Jaeger/Zipkin | Available | Default | Available |
| Grafana Tempo | Available | Available | Recommended |
| Langfuse/Arize | Available | Available | Available |
| Custom OTLP endpoint | Available | Available | Available |

---

## Part 6: Existing Components, What to Use, What to Build

### Use As-Is (Production-Ready)

| Component | What It Does | Maturity |
|-----------|-------------|----------|
| **agentgateway** (Linux Foundation) | MCP/A2A-aware proxy, Rust, sub-ms latency | v1.0, production |
| **SPIFFE/SPIRE** (CNCF Graduated) | Workload identity, SVID issuance, mTLS | Battle-tested |
| **OPA** (CNCF Graduated) | Policy engine, Rego, WASM compilation | Battle-tested |
| **Cedar** (AWS) | Formally verified policy language | Production (Bedrock) |
| **Firecracker** (AWS) | microVM sandboxing, <125ms boot, <5MiB overhead | Powers Lambda |
| **Cilium Tetragon** (CNCF) | eBPF runtime enforcement, <1% overhead | Production |
| **OpenTelemetry** (CNCF) | Distributed tracing, metrics, logs | Industry standard |
| **OpenLLMetry** (Traceloop) | Auto-instrumentation for 20+ LLM providers | Production |
| **Microsoft AGT** (MIT License) | Policy engine, identity, compliance, 7 packages | v1.0, April 2026 |

### Compose and Extend (Integration Needed)

| Gap | Current Best | What's Missing |
|-----|-------------|----------------|
| **Unified SDK** | MS AGT (Python/TS/.NET), OpenLLMetry (Python/TS/Go/Ruby) | Single SDK wrapping both + framework auto-detection |
| **Trust label injection at proxy** | Spotlighting (research), MCP SEP-1913 (proposal) | Production proxy plugin for agentgateway |
| **Agent identity token format** | SPIFFE SVIDs + MS AGT DIDs | Standardized claim set combining structural + delegation + behavioral claims |
| **Cross-provider federation** | None | Federated identity enabling Anthropic-issued agents to auth with OpenAI tools |
| **Provenance DAGs** | Agent-Sentry (research), CaMeL (research) | Production OTel exporter that builds and queries provenance graphs |
| **Behavioral anomaly detection** | MS AGT trust scoring (0-1000) | ML-based anomaly detection integrated with dynamic policy adjustment |

### Build from Scratch (Novel)

| Component | Why It Doesn't Exist | Complexity |
|-----------|---------------------|------------|
| **Agent supply chain verifier** | Agent configs are dynamic, not static build artifacts | Medium, adapt SLSA for runtime tool discovery |
| **Cross-framework policy portability** | Each framework has its own extension model | Medium, adapter layer per framework |
| **Attention-level trust enforcement** | Requires model architecture changes | Research-grade, monitor CIV paper progress |
| **AI-AI mutual authentication** | Agent-to-agent security is nascent | High, no existing protocol covers this fully |

---

## Part 7: Implementation Roadmap (Compressed)

### Phase 1, Foundation (Months 1-4)

**Deliverable: AgentMesh SDK + Solo Mode**

- Build unified Python/TypeScript SDK with auto-detection for top 8 frameworks
- Embed OPA WASM for in-process policy evaluation (sub-microsecond)
- Integrate OpenLLMetry for automatic OTel instrumentation
- Implement YAML policy language with compilation to Rego
- Implement Spotlighting-style trust labeling
- Ship `pip install agentmesh` and `npm install @agentmesh/sdk`
- 20 tutorials, one per framework integration

### Phase 2, Team Mode (Months 3-8, overlapping)

**Deliverable: agentgateway integration + Team deployment**

- Build agentgateway configuration for AgentMesh policies
- Implement credential isolation (agent never sees real keys)
- Add OPA/Cedar policy evaluation at gateway
- Implement token budget enforcement and cost attribution
- Build Docker Compose and Helm chart for one-command deployment
- Implement shadow/dry-run mode for policy testing
- Integrate 2+ guardrail backends (Lakera, NeMo)

### Phase 3, Enterprise Mode (Months 6-14, overlapping)

**Deliverable: Full mesh with identity, sandbox, compliance**

- Deploy SPIFFE/SPIRE with agent-specific attestation selectors
- Integrate Firecracker sandboxing with warm pool orchestrator
- Deploy Tetragon with agent-specific TracingPolicies
- Integrate Microsoft AGT compliance package
- Implement human-in-the-loop approval workflows
- Build behavioral anomaly detection with dynamic trust scoring
- Implement dual-LLM execution mode for high-security workflows

### Phase 4, Federation (Months 12-18)

**Deliverable: Cross-provider, industry-standard mesh**

- Cross-trust-domain SPIFFE federation
- Contribute agent identity extensions to IETF WIMSE
- Portable policy bundles working across all supported frameworks
- SLSA-based supply chain verification for agent configs
- Publish AgentMesh as CNCF sandbox project proposal

---

## Part 8: Architecture Decision Records

### ADR-001: Ambient Mode, Not Sidecars

**Decision:** Deploy gateway-level or node-level enforcement from day one. Never per-agent proxies.

**Rationale:** Istio learned this lesson the hard way. Sidecar mode adds 166% latency vs 8% for ambient mode. Per-agent proxies also create operational overhead that discourages adoption. The gateway pattern (agentgateway) provides equivalent security with dramatically lower overhead.

### ADR-002: External Enforcement is Non-Negotiable

**Decision:** Every security boundary exists in deterministic code outside the model.

**Rationale:** LLMs are probabilistic systems. You cannot formally verify their safety properties. Prompting a model to "ignore malicious instructions" is not a security control, it's a suggestion that works most of the time. The mesh enforces all invariants in deterministic code (Rust proxy, Go policy engine, eBPF kernel hooks) that the model cannot bypass.

### ADR-003: Start Permissive, Tighten Over Time

**Decision:** Default Solo mode allows all tools with logging. Default Team mode runs 7 days in shadow before enforcement.

**Rationale:** Security tools that break workflows on day one get uninstalled on day two. The mesh provides value immediately through observability and audit logging. Policy enforcement ramps up as teams understand their agents' behavior patterns. Microsoft AGT's shadow mode and behavioral trust tiers (Intern → Junior → Senior → Lead) encode this philosophy.

### ADR-004: WASM for Embedded Policy

**Decision:** Compile Rego to WASM for Solo-mode in-process evaluation.

**Rationale:** OPA-as-a-Go-library achieves sub-microsecond evaluation but only works in Go programs. OPA-as-a-sidecar adds network hop latency. WASM-compiled Rego runs 20× faster than the Go interpreter and can be embedded in any language runtime (Python via wasmtime, Node via V8, Rust natively). This eliminates the need for any external process in Solo mode.

### ADR-005: Compose, Don't Compete

**Decision:** AgentMesh composes existing CNCF/LF projects rather than building competitors.

**Rationale:** SPIFFE, OPA, agentgateway, Tetragon, and OpenTelemetry are individually mature. What's missing is the integration layer, the Istiod equivalent that orchestrates them. Building another policy engine or another proxy wastes effort and fragments the ecosystem. The unique value is the composition, the tiered deployment model, and the SDK that makes it accessible.

---

## Part 9: Regulatory Alignment

| Regulation | Deadline | AgentMesh Coverage |
|-----------|----------|-------------------|
| **EU AI Act** (high-risk obligations) | August 2026 | Audit trails (Art. 12), risk management (Art. 9), human oversight (Art. 14) via policy gates |
| **Colorado AI Act** | June 2026 | Impact assessments, disclosure requirements via compliance reporting |
| **OWASP Agentic AI Top 10** | Published Dec 2025 | All 10 categories addressed: policy enforcement (ASI01-03), identity (ASI05), sandbox (ASI06), supply chain (ASI04), observability (ASI07-10) |
| **NIST AI RMF** | Ongoing | Map, Measure, Manage, Govern functions via observability + policy + compliance packages |
| **SOC2** | Continuous | Immutable audit logs, access controls, policy versioning, encrypted communications |
| **HIPAA** | Continuous | PHI handling policies, access logging, encryption in transit (mTLS), minimum necessary principle via tool-level authz |

---

## Conclusion: The Path to Production

AgentMesh v2 reduces the distance between "I'm experimenting with agents" and "my agents are production-secured" to a single pip install. The tiered architecture means a solo developer and a Fortune 500 company use the same SDK, they just configure different tiers as their needs grow.

The building blocks are production-grade. The performance budgets are met. The regulatory deadlines are real. The organization that ships this as an open-source, CNCF-track project in the next 6-12 months defines the security infrastructure for the agentic era.

The agent service mesh isn't a theoretical architecture anymore. It's a composition problem with a tight deadline. Let's build it.

---

**References & Key Papers:**
- CaMeL (Google DeepMind, 2025), arxiv.org/abs/2503.18813
- Agent-Sentry (2025), arxiv.org/html/2603.22868
- Spotlighting (Microsoft Research, 2024), microsoft.com/research
- Systems Security Foundations for Agentic Computing (IACR, 2025), eprint.iacr.org/2025/2173
- IETF AI Agent Authentication, datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00
- CIV: Contextual Integrity Verification (2025), arxiv.org/abs/2508.09288
- Service Mesh Performance Comparison (arXiv, 2024), arxiv.org/abs/2411.02267
- OWASP Agentic AI Top 10 (2025), genai.owasp.org
- Microsoft Agent Governance Toolkit, github.com/microsoft/agent-governance-toolkit
- agentgateway, agentgateway.dev
