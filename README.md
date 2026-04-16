# Tessera

**Signed provenance, delegation-aware taint tracking, and schema-enforced
dual-LLM execution for agent security meshes.**

![tests](https://img.shields.io/badge/tests-1173%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12%2B-blue)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)
![status](https://img.shields.io/badge/status-experimental-orange)

Tessera is a Python library and sidecar proxy that implements two primitives
recent agent security surveys identify as unimplemented in production:

1. **Signed trust labels on context segments**, with deterministic
   taint tracking at the tool-call boundary. A tool call requiring USER
   trust cannot fire if any segment in the context carries WEB trust,
   regardless of how convincingly that segment impersonates a user
   instruction.

2. **Schema-enforced dual-LLM execution.** The Worker model is
   structurally prevented from returning free-form text by a Pydantic
   validator, closing the convention-based hole in Simon Willison's
   dual-LLM pattern without requiring a custom interpreter.

Both primitives are documented in
[papers/two-primitives-for-agent-security-meshes.md](papers/two-primitives-for-agent-security-meshes.md).

---

## Why this exists

LLM agents concatenate everything they see into one trust-undifferentiated
context: user instructions, scraped web pages, tool outputs, memory entries,
retrieved documents. The model has no structural way to tell them apart.
That is the root cause of indirect prompt injection, and no amount of
system-prompting fixes it.

Existing guardrails are WAFs for LLMs: pattern-matching on strings. Tessera
treats this as an identity and data-flow problem, not a filtering problem.
Every segment of context carries a cryptographic provenance label. The
policy engine evaluates tool calls against the minimum trust level observed
in the data that could have influenced them. The dual-LLM quarantine
executor structurally isolates untrusted content from the model that
emits tool calls.

None of the enforcement happens inside the LLM. It happens in deterministic
Python outside the model. That is the only way to get guarantees against a
probabilistic system.

---

## The core invariant

```
allow(tool, ctx) iff required_trust(tool) <= min_{s in ctx.segments} s.trust_level
```

A tool call may execute only if every segment of context that could have
influenced the decision has a trust level at or above the tool's required
level. The taint-tracking primitive is the use of `min`, not `max`. A
single untrusted segment drags the whole context to the floor.

The invariant is enforced in `tessera.policy.Policy.evaluate`, is
deterministic, and is testable without invoking an LLM. See
[tests/test_policy.py](tests/test_policy.py) for the proofs.

---

## Architecture

```
   +--------+    +------------------------+    +-----------+
   | User   |--> | Tessera sidecar        |--> | LLM API   |
   +--------+    |                        |    +-----------+
                 |  - verify label sigs   |
   +--------+    |  - spotlight untrusted |
   | Web    |--> |  - taint-track context |
   +--------+    |  - gate tool calls     |
                 |  - emit security events|
   +--------+    |                        |
   | MCP    |--> +----+-------------------+
   +--------+         |
                      v
            +--------------------+    +------------------+
            | tessera.policy     |    | tessera.events   |
            | taint-tracking     |    | SIEM webhook,    |
            +--------------------+    | OTel span events |
                                      +------------------+

            +-----------------------------+
            | tessera.quarantine          |
            |                             |
            |   PLANNER      WORKER       |
            |   (tools)   (no tools)      |
            |      ^          |           |
            |      |   strict_worker      |
            |      +-- WorkerReport ------+
            +-----------------------------+
```

Every chunk of text entering the model carries a signed label:

```python
TrustLabel(
    origin="web",           # user | system | tool | memory | web
    principal="alice",      # who the content belongs to
    trust_level=0,          # 0=untrusted, 50=tool, 100=user, 200=system
    nonce="...",            # 128-bit random
    signature="..."         # HMAC-SHA256 or JWT-SVID over content + metadata
)
```

---

## What's in the box

| Module | Purpose |
|---|---|
| `tessera.labels` | Signed `TrustLabel`, HMAC-SHA256 primitives |
| `tessera.signing` | HMAC and JWT-based label signing and verification, with clock-skew leeway |
| `tessera.context` | `LabeledSegment`, `Context`, Spotlighting delimiters |
| `tessera.delegation` | Signed delegation tokens for bounded user-to-agent authority |
| `tessera.provenance` | Signed context segment envelopes and prompt provenance manifests |
| `tessera.identity` | Inbound workload identity tokens, proof-of-possession, replay checks |
| `tessera.mtls` | SPIFFE-aware transport identity extraction from ASGI TLS and trusted XFCC |
| `tessera.policy` | Taint-tracking policy engine with per-tool trust requirements, CEL rules, MCP RBAC, hierarchical scopes |
| `tessera.policy_backends` | External deny-only policy backends, including OPA integration and audit metadata |
| `tessera.cel_engine` | CEL expression engine for deny-only policy refinements (requires `[cel]`) |
| `tessera.approval` | Human-in-the-loop approval gates with fail-closed webhook delivery |
| `tessera.sessions` | Encrypted in-memory session store for pending approvals, with TTL expiry |
| `tessera.ir` | Intermediate representation: compile YAML/dict policy config to live `Policy` instances |
| `tessera.hooks` | gRPC extension hooks (PostPolicyEvaluate, PostToolCallGate), deny-only, fail-closed |
| `tessera.xds` | xDS-compatible resource distribution over HTTP/SSE and gRPC ADS (requires `[xds]`) |
| `tessera.scanners` | Content-aware injection scoring (directive, intent, heuristic), canary leakage detection, PII entity detection, prompt screening, tool output schema enforcement, tool shadow detection |
| `tessera.risk` | Irreversibility scoring, salami attack chain detection, adaptive cooldown escalation |
| `tessera.compliance` | NIST SP 800-53 and CWE enrichment, hash-chain tamper-evident audit log |
| `tessera.ratelimit` | Per-principal token budget enforcement for denial-of-wallet defense |
| `tessera.quarantine` | `QuarantinedExecutor`, `strict_worker`, safe-by-default `WorkerReport` |
| `tessera.mcp` | MCP interceptor that auto-labels tool outputs |
| `tessera.a2a` | A2A security context carriage and verification helpers |
| `tessera.spire` | Live SPIRE Workload API adapters for JWT-SVIDs and trust bundles |
| `tessera.registry` | Org-level external-tool registry, registry-wins-on-inclusion |
| `tessera.events` | Structured `SecurityEvent` with stdout, OTel, and webhook sinks |
| `tessera.evidence` | Signed evidence bundles for audit export and offline verification |
| `tessera.output_monitor` | Output manipulation defense: detects when model outputs deviate from verified tool results |
| `tessera.delegation_intent` | Delegation intent verification: ensures delegated tool calls match the stated purpose |
| `tessera.trust_decay` | Time-based trust decay: segments lose trust as they age, configurable per origin |
| `tessera.plan_verifier` | Plan verification: validates multi-step agent plans against policy before execution |
| `tessera.side_channels` | Side-channel mitigations: constant-time comparison, timing jitter, output padding |
| `tessera.claim_provenance` | Claim provenance tracking: binds model assertions to the tool outputs that produced them |
| `tessera.confidence` | Confidence scoring for scanner results with model-targeting and tense-aware filtering |
| `tessera.taint` | Value-level taint tracking wired into the policy evaluator and adapter layer |
| `tessera.telemetry` | Optional OpenTelemetry spans across proxy, MCP, policy, quarantine |
| `tessera.proxy` | FastAPI reference proxy with chat and A2A JSON-RPC mediation |
| `tessera.adapters.langchain` | LangChain callback handler: labels segments, gates tool calls, scans outputs (requires `[langchain]`) |
| `tessera.adapters.mcp_proxy` | Transparent MCP sidecar proxy: sits between any MCP client and a real MCP server, adding trust labels and policy gates to every tool call (requires `[mcp]`) |
| `tessera.adapters.openai_agents` | OpenAI Agents SDK hook adapter: policy gate on tool start, output labeling, session risk on end (requires `[openai-agents]`) |
| `tessera.adapters.agentdojo` | AgentDojo benchmark adapter: policy gates and injection scoring in AgentDojo evaluation pipelines (requires `[agentdojo]`) |
| `tessera.adapters.crewai` | CrewAI step callback: labels segments, gates tool calls, tracks session risk (requires `[crewai]`) |
| `tessera.adapters.google_adk` | Google ADK before/after tool callbacks: policy enforcement and output labeling (requires `[google-adk]`) |
| `tessera.adapters.llamaindex` | LlamaIndex callback handler: tool-call gating and output labeling (requires `[llamaindex]`) |
| `tessera.adapters.haystack` | Haystack pipeline component: policy gate as a pipeline node (requires `[haystack]`) |
| `tessera.adapters.langgraph` | LangGraph tool node wrapper: gates tool invocations within graph execution (requires `[langgraph]`) |
| `tessera.adapters.pydantic_ai` | PydanticAI tool wrapper: policy-enforced tool decorator (requires `[pydantic-ai]`) |
| `tessera.adapters.upstream` | Ready-to-use `UpstreamFn` callables: `openai_upstream` (OpenAI, Mistral, Deepseek, xAI, Qwen, Groq, Ollama, vLLM) and `anthropic_upstream` (with full schema translation) |
| `tessera.liveness` | Agent liveness attestation via heartbeat TTL (three-property gate: identity AND authority AND liveness) |
| `tessera.hooks.compatibility` | Decision-event compatibility matrix for hook authoring validation |
| `tessera.content_inspector` | Content-type-aware multimodal inspection pipeline |
| `tessera.scanners.binary_content` | PDF/image binary threat scanning |
| `tessera.scanners.pdf_inspector` | Sandboxed PDF analysis with CDR |
| `tessera.scanners.image_inspector` | Steganography, adversarial, invisible text detection |
| `tessera.mcp_allowlist` | MCP server allowlist with rug-pull detection |
| `tessera.read_only_guard` | Read-only tool argument validation with toxic flow detection |
| `tessera.rag_guard` | RAG/vector store scan-on-retrieval with PoisonedRAG defense |
| `tessera.policy_invariant` | Runtime control-flow invariant enforcement |
| `tessera.guardrail` | Optional LLM-based semantic injection classifier with provider-agnostic client, structured-only output, and SHA-256 cached decisions |
| `tessera.adapters.enhanced` | Full defense stack composing all security components |

Reference deployments:

- [`deployment/spire/`](deployment/spire/): SPIRE docker-compose with
  workload registration walkthrough
- [`rust/tessera-gateway/`](rust/tessera-gateway/): Rust data plane with native
  TLS transport identity, chat mediation, and A2A enforcement
- [`examples/injection_blocked.py`](examples/injection_blocked.py):
  minimal offline demo
- [`examples/quarantine_demo.py`](examples/quarantine_demo.py):
  dual-LLM demo with a stub planner and worker, no API key required
- [`examples/quarantine_openai.py`](examples/quarantine_openai.py):
  dual-LLM demo with real OpenAI API calls (gpt-4o-mini as worker,
  gpt-4o as planner), schema-enforced via `EarningsFacts`

---

## Defense layers (v0.2.0)

Beyond the two core primitives, Tessera v0.2.0 adds layered defenses that
compose with the taint-tracking policy engine:

- **Content analysis scanners.** Directive detection, intent classification,
  and heuristic scoring identify injected instructions in tool outputs and
  retrieved content. Scanners run in parallel with configurable confidence
  thresholds, model-targeting checks, and past-tense filters to reduce
  false positives.
- **Output manipulation defense.** The output monitor detects when a model's
  response contradicts or fabricates data relative to the tool outputs it
  received, catching post-hoc injection where the model is tricked into
  misrepresenting verified results.
- **Trust decay.** Segments lose trust over time based on configurable
  per-origin decay curves. A tool output that was trustworthy five minutes
  ago may not be trustworthy five hours later, and the policy engine
  reflects this automatically.
- **Plan verification.** Multi-step agent plans are validated against the
  policy before execution begins. The verifier checks that every step in
  the proposed plan would be permitted given the current context, preventing
  the agent from committing to a sequence it cannot complete.
- **Side-channel mitigations.** Constant-time label comparison, timing
  jitter on policy evaluation, and output padding defend against
  adversaries who probe the system by measuring response timing or output
  length to infer trust decisions.
- **Prompt screening.** Inbound prompts are screened for known injection
  patterns before they enter the context, providing an early-reject path
  that avoids polluting the taint-tracking state with content that would
  have been blocked anyway.
- **Multimodal content scanning.** The content inspector pipeline handles
  PDF, image, audio, HTML, and base64 payloads. PDF analysis includes
  raw key scanning, hex-encoded JS detection, CDR sanitization, and URL
  analysis. Image analysis covers LSB steganography, adversarial
  perturbation, and invisible text detection.
- **MCP server allowlist with rug-pull detection.** The allowlist tracks
  tool definitions over time and detects silent changes to tool schemas,
  descriptions, or capabilities that could indicate a compromised or
  malicious MCP server.
- **Read-only argument validation with toxic flow detection.** Per-tool
  argument policies (FIDES-inspired) enforce read-only constraints on
  tool arguments, with toxic flow detection (PCAS-inspired) identifying
  data flows that violate intended access patterns.
- **PoisonedRAG defense.** Retrieval pattern tracking detects anomalous
  retrieval distributions, and embedding anomaly detection identifies
  outlier vectors that may indicate poisoned documents in the vector store.
- **Burst detection and session lifetime rate limiting.** Per-session tool
  call rate limits enforce burst detection with cooldown and session
  lifetime caps, preventing denial-of-wallet and resource exhaustion
  attacks.
- **LLM guardrail.** Optional semantic classification layer for ambiguous
  tool outputs. Fires only when deterministic scanners are uncertain.
  Provider-agnostic, structured-output-only, cached.
- **Post-generation output integrity verification.** The output monitor
  checks model responses for n-gram similarity to untrusted inputs,
  task relevance drift, and injection output patterns, catching cases
  where the model has been influenced by injected content.

## Framework adapters

Tessera integrates with fourteen agent frameworks through drop-in adapters.
Each adapter wires policy gates, trust labels, and security events into
the framework's native extension points:

LangChain, OpenAI Agents SDK, AgentDojo, MCP (transparent sidecar proxy),
CrewAI, Google ADK, LlamaIndex, Haystack, LangGraph, PydanticAI,
Nemo Guardrails, LlamaFirewall, upstream provider callables, and the
enhanced full-defense-stack adapter.

See the module table above for per-adapter details and optional
dependency groups.

---

## Quickstart

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Offline injection demo:

```bash
python examples/injection_blocked.py
python examples/quarantine_demo.py
```

Labeling a segment with HMAC:

```python
from tessera import make_segment, Origin, TrustLevel, Context, Policy

KEY = b"replace-with-a-real-key"

ctx = Context()
ctx.add(make_segment("email bob about the report",
                     origin=Origin.USER, principal="alice", key=KEY))
ctx.add(make_segment("<html>scraped content</html>",
                     origin=Origin.WEB, principal="alice", key=KEY))

policy = Policy()
policy.require("send_email", TrustLevel.USER)

decision = policy.evaluate(ctx, "send_email")
assert not decision.allowed
print(decision.reason)
# context contains a segment at trust_level=0, below required 100 for tool 'send_email'
```

Outbound workload identity with a SPIRE JWT-SVID:

```python
from tessera import SpireJWTSource

source = SpireJWTSource(socket_path="unix:///tmp/spire-agent-api/api.sock")
headers = source.identity_headers(audience="spiffe://example.org/ns/proxy/i/abcd")

assert "ASM-Agent-Identity" in headers
```

Dual-LLM execution with schema enforcement:

```python
from tessera import QuarantinedExecutor, strict_worker, WorkerReport

async def raw_worker(untrusted_ctx):
    # call your Worker LLM, return a dict matching WorkerReport
    ...

worker = strict_worker(WorkerReport, raw_worker)

async def planner(trusted_ctx, report: WorkerReport):
    # planner sees only trusted segments + the validated report
    ...

executor = QuarantinedExecutor(planner=planner, worker=worker)
result = await executor.run(full_context)
```

Proxy wired to any LLM provider:

```python
from tessera.adapters.upstream import openai_upstream, anthropic_upstream, PROVIDERS
from tessera.proxy import create_app

# OpenAI (or drop in Mistral, Deepseek, xAI, Qwen, Groq, Ollama -- same call)
upstream = openai_upstream(api_key="sk-...", base_url=PROVIDERS["mistral"])

# Anthropic (schema translation is handled automatically)
upstream = anthropic_upstream(api_key="sk-ant-...")

app = create_app(policy=policy, verifier=verifier, upstream=upstream)
```

Security event emission to a SIEM:

```python
from tessera import register_sink, webhook_sink

register_sink(webhook_sink("https://siem.example.com/tessera"))
# Now every POLICY_DENY and WORKER_SCHEMA_VIOLATION is POSTed as JSON.
```

---

## Threat model

Tessera defends against **indirect prompt injection**: an attacker controls
some segment of data entering the agent's context window and tries to
cause the agent to take a privileged action the delegating user did not
authorize.

Tessera does NOT defend against:

- Direct prompt injection by the authenticated user
- Model-level attacks (backdoors, data poisoning, weight extraction)
- Compromise of the underlying tool servers or MCP implementations
- Supply-chain attacks on model weights, system prompts, or tool manifests
- Sandbox escape for agent-generated code (use Firecracker or gVisor)
- Semantic poisoning of the agent's natural-language output to the user

See Section 2 of the paper for the full threat model and explicit
out-of-scope list.

---

## Tessera and AgentMesh

Tessera is the primitives library. It provides the building blocks for
agent security: signed provenance labels, taint-tracking policy,
schema-enforced dual-LLM execution, delegation tokens, workload identity,
and supporting infrastructure. It is designed to compose with any agent
mesh, not to be one.

**AgentMesh** is the larger goal: a full agent security mesh for AI
workloads, analogous to what Istio and Cilium provide for Kubernetes
networking. AgentMesh composes Tessera with production infrastructure
(agentgateway, SPIFFE/SPIRE, OPA/Cedar, OpenTelemetry) into a unified
security control plane with tiered deployment from solo developer to
enterprise scale.

The AgentMesh architecture is proposed in
[docs/AGENT_SECURITY_MESH_V1_SPEC.md](docs/AGENT_SECURITY_MESH_V1_SPEC.md).
Tessera is the core library that AgentMesh is built on. The Rust gateway
in [`rust/tessera-gateway/`](rust/tessera-gateway/) is a reference
implementation for contributing primitives upstream to agentgateway.

---

## Composition with existing mesh infrastructure

Tessera is designed to slot into any agent mesh, not to replace one:

- **Identity:** custom label JWTs integrate via `JWTSigner` and
  `JWKSVerifier`, while live SPIRE JWT-SVID retrieval and trust-bundle
  verification integrate via `tessera.identity` and `tessera.spire`
- **Transport identity:** the reference proxy can enforce SPIFFE caller
  identity from the ASGI TLS extension, or from `X-Forwarded-Client-Cert`
  when the immediate proxy host is explicitly trusted
- **Policy:** the `Decision` object composes with Cedar or OPA for
  attribute-based rules (evaluate taint first, attributes second)
- **Data plane:** the FastAPI reference proxy now covers chat mediation,
  signed delegation, signed prompt provenance, discovery, and A2A
  JSON-RPC ingress. It is still a reference surface meant to be ported
  into a Rust proxy like agentgateway for production
- **Observability:** OTel spans emit across `proxy.request`,
  `proxy.upstream`, `policy.evaluate`, `mcp.tool_call`, `quarantine.run`
- **Sandbox:** orthogonal, Tessera operates at the application layer

---

## Status

**Experimental.** v0.2.0 ships ~21,700 lines of Python across 101
modules, ~17,400 lines of tests (1171 passing), and a Rust reference
gateway. The invariants are testable and the primitives compose, but the
API will change, the ergonomics will change, and the integrations with
existing mesh infrastructure are not yet battle-tested at scale.

What is stable:

- The core invariant and its test coverage
- The `TrustLabel` structure (HMAC and JWT-SVID signing modes)
- The `strict_worker` contract and the safe-by-default `WorkerReport`

What is likely to change:

- The FastAPI proxy shape (production deployments should port primitives
  into a Rust data plane)
- The MCP interceptor interface as MCP SEP-1913 lands
- The `SecurityEvent` sink API as we integrate with more SIEMs
- The xDS and hooks gRPC wire format (adding delta-xDS and full ACK/NACK
  in a later release)

---

## Contributing

Contributions are welcome, particularly:

- Like-for-like CaMeL latency comparison (microbenchmarks for primitive
  overhead have landed, head-to-head workload comparison is still open)
- Contributing Tessera primitives upstream to agentgateway as a
  middleware plugin
- MCP SEP-1913 interop once the standard lands
- Additional framework adapters or improvements to the existing fourteen
  (LangChain, OpenAI Agents SDK, AgentDojo, MCP, CrewAI, Google ADK,
  LlamaIndex, Haystack, LangGraph, PydanticAI, Nemo, LlamaFirewall,
  upstream, enhanced)
- Additional test coverage for edge cases in the taint-tracking invariant

Open an issue with questions, corrections, or proposals. Pull requests
should include tests that pin the invariant being added or changed.

---

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).

The AGPL ensures that anyone running Tessera or AgentMesh as a network
service must make their source code available to users of that service.
This closes the SaaS loophole that permits companies to run open-source
software as a service without contributing improvements back.

The accompanying paper in [`papers/`](papers/) is licensed under
CC BY 4.0.

---

## Citation

If you use Tessera or the primitives described in the paper:

```
Philip, K. (2026). Two Primitives for Agent Security Meshes:
Trust-Labeled Context and Schema-Enforced Dual-LLM Execution.
Draft for discussion. https://github.com/kenithphilip/Tessera
```

---

## Author

Kenith Philip.

Questions, corrections, and implementation feedback are welcome via
GitHub issues once the repository is published publicly.
