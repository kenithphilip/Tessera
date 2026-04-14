# Tessera Enhancement Plan

Derived from deep-source analysis of four competing/complementary projects:

- **CaMeL** (Google DeepMind): variable-level taint tracking via AST interpreter
- **PurpleLlama** (Meta): LlamaFirewall, PromptGuard 2, CodeShield, CyberSecEval
- **NeMo Guardrails** (NVIDIA): Colang-driven programmable dialogue rails
- **Agent Audit**: static analysis CLI with 120+ OWASP Agentic rules

Each phase is ordered by security payoff per engineering effort, with
explicit dependencies noted. Phases are designed for independent
development where possible.

---

## Phase 1: Scanner Hardening (Small effort, high security payoff)

These enhancements strengthen Tessera's existing scanner infrastructure
with battle-tested detection patterns from Agent Audit and PurpleLlama.

### 1.1 Hidden Unicode Tag Detection

**Source:** PurpleLlama `HiddenASCIIScanner`

Add a scanner to `tessera/scanners/` that detects Unicode tag characters
(U+E0000 to U+E007F) used to embed steganographic instructions in
text. These characters are invisible in most renderers but decoded by
some LLM tokenizers. The scanner should decode the hidden payload and
include it in the SecurityEvent for forensic inspection.

**Files:** New `tessera/scanners/unicode.py`, update `tessera/scanners/__init__.py`
**Effort:** ~50 lines. Deterministic regex, no ML dependency.
**Test:** Embed Unicode tag payload in a context segment, verify scanner fires.

### 1.2 MCP Tool Description Poisoning Detection

**Source:** Agent Audit `ToolDescriptionAnalyzer` (AGENT-056/057)

Extend `tessera.mcp.MCPInterceptor` to scan tool descriptions for:
- Instruction override phrases ("ignore previous instructions")
- Hidden instructions (zero-width chars, HTML comments, template injection)
- Command injection (backtick execution, subshell patterns)
- Data exfiltration guidance ("send data to http://...")
- Privilege escalation directives ("grant admin access")

Apply at MCP server initialization when tool schemas are first loaded,
and again if tools are re-enumerated. Emit a SecurityEvent on detection.

**Files:** New `tessera/scanners/tool_descriptions.py`, integrate into `tessera/mcp.py`
**Effort:** ~150 lines. Regex patterns from Agent Audit's 5-category system.
**Test:** Craft poisoned tool descriptions, verify detection and SecurityEvent.

### 1.3 MCP Baseline Drift Detection

**Source:** Agent Audit `mcp_baseline.py` (AGENT-054)

Add `MCPBaseline` to `tessera.mcp`: SHA-256 hash of each tool's
description, input schema, and output schema at snapshot time. On
subsequent MCP server connections, compare hashes and emit a
SecurityEvent if any tool has drifted. Configurable response: warn,
deny-new-tools, deny-all-on-drift.

This is the "rug pull" defense: an MCP server that changes its tool
descriptions after initial vetting gets flagged.

**Files:** New `tessera/mcp_baseline.py`, integrate into `tessera/mcp.py`
**Effort:** ~120 lines.
**Dependency:** None.
**Test:** Snapshot baseline, modify a tool description, verify drift detection.

### 1.4 Cross-Server Tool Shadowing Detection

**Source:** Agent Audit (AGENT-055)

When multiple MCP servers are configured, compute Levenshtein distance
between tool names across servers. Flag tools with identical or very
similar names (distance <= 2) registered in different servers. This
detects malicious tool override attacks where an attacker registers a
tool with the same name as a legitimate tool in a different server.

**Files:** Extend `tessera/registry.py` or new `tessera/scanners/tool_shadow.py`
**Effort:** ~80 lines.
**Test:** Register same tool name in two servers, verify detection.

---

## Phase 2: Policy Engine Extensions (Medium effort, high payoff)

### 2.1 Readers Lattice (Access-Control Model)

**Source:** CaMeL `Capabilities.readers_set`

Extend `TrustLabel` with an optional `readers: frozenset[str] | None`
field. When present, `Context` computes the intersection of all
segment readers sets alongside `min_trust`. Tool calls that would
exfiltrate data to principals outside the intersection are denied.

This is additive to existing invariants. `readers=None` means
`Public()` (backwards compatible). The intersection semantics match
CaMeL's `get_all_readers()`: a composite value is only as readable
as its most restrictive ingredient.

Use case: an email tool checks that the body's effective readers
include all recipients. If any segment in the context has readers
restricted to `{"internal"}`, sending to an external address is denied.

**Files:** Extend `tessera/labels.py`, `tessera/context.py`, `tessera/policy.py`
**Effort:** ~200 lines.
**Dependency:** None.
**Breaking:** No. New optional field, existing code works unchanged.
**Test:** Build context with mixed readers, verify intersection and policy denial.

### 2.2 Fnmatch-Based Policy Rules

**Source:** CaMeL `SecurityPolicyEngine`

Add glob pattern matching to `Policy.require()`:

```python
policy.require("send_*", TrustLevel.USER)  # all send-like tools
policy.require("read_*", TrustLevel.TOOL)  # all read-like tools
```

Currently `Policy` uses exact tool name matching. Fnmatch patterns
reduce configuration verbosity for large tool sets.

**Files:** Extend `tessera/policy.py`
**Effort:** ~30 lines. `fnmatch.fnmatch` in `evaluate()`.
**Test:** Pattern matches, non-matches, precedence (exact beats glob).

### 2.3 Side-Effect Classification on Tools

**Source:** CaMeL `no_side_effect_tools`

Add an optional `side_effects: bool = True` parameter to
`Policy.require()`. Tools marked `side_effects=False` are exempt from
taint-floor denial (they can read tainted data but cannot act on it).

This matches CaMeL's insight: read-only tools like `search` or
`extract_entities` should be allowed even when the context contains
untrusted segments, because they cannot exfiltrate data or cause harm.
Only side-effecting tools (`send_email`, `write_file`, `execute_code`)
need the full taint-floor check.

**Files:** Extend `tessera/policy.py`
**Effort:** ~50 lines.
**Dependency:** None.
**Breaking:** No. Default `side_effects=True` preserves existing behavior.
**Test:** Read-only tool allowed with tainted context, write tool denied.

### 2.4 OWASP Agentic Top 10 Compliance Mapping

**Source:** Agent Audit ASI-01 through ASI-10 taxonomy

Extend `tessera.compliance.enrich_event` to add OWASP Agentic Top 10
category IDs (ASI-01 through ASI-10) alongside existing NIST SP 800-53
and CWE mappings. This gives SecurityEvents a third taxonomy dimension
for cross-correlation with Agent Audit findings.

Mapping table:
- POLICY_DENY on taint-floor -> ASI-01 (Prompt Injection)
- WORKER_SCHEMA_VIOLATION -> ASI-01
- DELEGATION_NARROWING_VIOLATION -> ASI-03 (Excessive Agency)
- TOOL_CALL_DENIED -> ASI-02 (Tool Misuse)
- PII_DETECTED -> ASI-04 (Sensitive Data Exposure)
- CANARY_DETECTED -> ASI-04

**Files:** Extend `tessera/compliance.py`
**Effort:** ~60 lines (mapping table + enrichment).
**Test:** Verify ASI categories on enriched events.

---

## Phase 3: ML-Backed Detection (Medium effort, high payoff)

### 3.1 PromptGuard 2 Integration (Optional Scanner)

**Source:** PurpleLlama PromptGuard 2 (86M and 22M)

Add an optional `PromptGuardScanner` to `tessera.scanners` that wraps
Meta's PromptGuard 2 model for neural prompt injection detection.
The scanner takes a text string and returns a jailbreak probability
score (0.0 to 1.0). Block threshold configurable (default 0.9).

Tessera's advantage over LlamaFirewall's use of PromptGuard: Tessera
can target the scanner using cryptographic trust labels. Only segments
with `origin=WEB` or `origin=TOOL` need scanning, because USER and
SYSTEM segments are trusted by definition. This reduces false positives
and compute cost compared to scanning everything.

**Files:** New `tessera/scanners/promptguard.py`
**Effort:** ~100 lines wrapper.
**Dependency:** `torch`, `transformers` (heavy, must be optional extra).
**Install:** `pip install tessera[promptguard]`
**Test:** Score known injection text, verify threshold behavior.

### 3.2 CodeShield Integration (Tool Output Scanner)

**Source:** PurpleLlama CodeShield

When Tessera's MCP interceptor receives a tool response containing
code (detected by content-type heuristics or explicit code fences),
optionally route the content through CodeShield's
`insecure_code_detector.analyze()`. Emit a SecurityEvent with CWE ID
on detection.

**Files:** New `tessera/scanners/codeshield.py`
**Effort:** ~80 lines wrapper.
**Dependency:** `codeshield>=1.0.1` (optional extra).
**Install:** `pip install tessera[codeshield]`
**Test:** Submit insecure Python code, verify CWE detection.

### 3.3 Perplexity-Based Jailbreak Heuristic

**Source:** NeMo Guardrails `checks.py`

Add a GPT-2-based perplexity scorer to `tessera.scanners` that detects
GCG-style gradient-based adversarial suffixes. Two checks:
- Length/perplexity ratio >= threshold (targets garbled suffixes)
- Prefix/suffix perplexity >= threshold (targets appended noise)

This catches a class of attacks that neither heuristic injection
scoring nor PromptGuard reliably detect: adversarial token sequences
optimized to bypass neural classifiers.

**Files:** New `tessera/scanners/perplexity.py`
**Effort:** ~120 lines.
**Dependency:** `transformers` (shared with PromptGuard extra).
**Test:** GCG-style adversarial suffix triggers detection.

---

## Phase 4: Evaluation and Benchmarking (Medium effort, critical for credibility)

### 4.1 Injection Variant Taxonomy

**Source:** CyberSecEval prompt injection benchmark

Extend the benchmark suite to categorize injection test cases by:
- `injection_type`: direct vs indirect
- `injection_variant`: instruction override, context manipulation,
  role hijacking, payload smuggling
- `risk_category`: data exfiltration, unauthorized action, privilege
  escalation, information disclosure

This makes Tessera's test results directly comparable to CyberSecEval
published numbers.

**Files:** Extend `benchmarks/comparison/workload.py`, new test fixtures.
**Effort:** ~200 lines of test infrastructure.

### 4.2 AgentDojo Evaluation

**Source:** PromptGuard 2 model card, CaMeL paper

Run Tessera's full stack against AgentDojo to produce:
- Attack Prevention Rate (APR) at 3% utility reduction
- Per-suite breakdown (banking, workspace, travel, slack)

This is the single most important benchmark for external credibility.
PromptGuard 2 reports 81.2% APR. CaMeL reports near-100%. Tessera
should have a number.

**Files:** New `benchmarks/agentdojo/` directory.
**Effort:** ~400 lines of harness code.
**Dependency:** `agentdojo` package.

### 4.3 Recall@FPR Metrics for Scanners

**Source:** PromptGuard 2 model card

Adopt Recall@1%FPR as the primary metric for all Tessera scanners.
This is the operationally correct metric: high recall (catch attacks)
at very low false positive rate (don't degrade user experience).

**Files:** New `benchmarks/scanner_eval/` directory.
**Effort:** ~150 lines of evaluation harness.

---

## Phase 5: Runtime Infrastructure (Larger effort, high production value)

### 5.1 Scanner Result Caching (LFU)

**Source:** NeMo Guardrails LFU cache

Add an LFU cache to `tessera.scanners` for ML-backed scanners
(PromptGuard, perplexity, CodeShield). Cache key: normalized hash of
input text. Configurable `maxsize` with statistics logging.

Rationale: ML scanners are 10-100ms per call. Caching identical or
near-identical inputs across a conversation avoids redundant inference.

**Files:** New `tessera/scanners/cache.py`, integrate into scanner dispatch.
**Effort:** ~100 lines.
**Test:** Cache hit/miss counting, eviction behavior.

### 5.2 Parallel Scanner Execution

**Source:** NeMo Guardrails `run_input_rails_in_parallel`

When multiple scanners are configured, run them concurrently with
`asyncio.gather` and take the most restrictive result. Currently
scanners run sequentially.

**Files:** Extend scanner dispatch in `tessera/scanners/__init__.py` or `tessera/mcp.py`.
**Effort:** ~60 lines.
**Test:** Two scanners run concurrently, most restrictive wins.

### 5.3 Per-Call Scanner Selection

**Source:** NeMo Guardrails `GenerationOptions`

Allow callers to enable/disable specific scanners per policy
evaluation call:

```python
decision = policy.evaluate(
    ctx, "send_email",
    scanners=["injection", "pii"],  # only these scanners
)
```

This avoids running expensive ML scanners on calls where they are
not needed (e.g., read-only tool calls).

**Files:** Extend `tessera/policy.py` evaluate signature.
**Effort:** ~40 lines.

### 5.4 Confidence-Tiered SecurityEvents

**Source:** Agent Audit BLOCK/WARN/INFO/SUPPRESSED tiers

Add a `confidence: float` field to `SecurityEvent` and a tier
classification: BLOCK (>= 0.92), WARN (>= 0.60), INFO (>= 0.30).
Scanner results carry confidence scores; the policy engine uses the
tier to decide whether to deny (BLOCK), log (WARN/INFO), or suppress.

Context-aware gating: events from test/example code contexts get
confidence multiplied by < 1.0, preventing false positives from test
fixtures from reaching BLOCK tier.

**Files:** Extend `tessera/events.py`, `tessera/scanners/`.
**Effort:** ~100 lines.
**Breaking:** No. `confidence` defaults to 1.0 for existing events.

### 5.5 SARIF Output for CI Integration

**Source:** Agent Audit SARIF 2.1.0 formatter

Add a `sarif_sink` to `tessera.events` that collects SecurityEvents
and outputs SARIF 2.1.0 JSON. This enables GitHub Code Scanning
integration: Tessera security events appear as code scanning alerts
in GitHub PRs.

**Files:** New `tessera/events_sarif.py`.
**Effort:** ~150 lines.
**Test:** Emit events, validate SARIF schema compliance.

---

## Phase 6: Advanced Taint Tracking (Larger effort, differentiating)

### 6.1 Dependency Accumulator for Control-Flow Taint

**Source:** CaMeL interpreter `dependencies` thread

Add an optional dependency tracking mode to Tessera's policy engine.
When enabled, the policy engine maintains a per-session dependency
accumulator that grows as tool results are used in control-flow
decisions. If a tool result from an untrusted source was used in any
conditional that led to the current tool call, the call is tainted
even if the tool result is not directly passed as an argument.

This closes a gap where Tessera's context-level `min_trust` cannot
distinguish "the untrusted segment was in the context but not used"
from "the untrusted segment drove the control flow that produced
this tool call."

**Files:** Extend `tessera/context.py`, `tessera/policy.py`.
**Effort:** ~200 lines.
**Dependency:** Phase 2.3 (side-effect classification).
**Test:** Untrusted data used in if-condition taints downstream tool call.

### 6.2 `have_enough_information` Guard on WorkerReport

**Source:** CaMeL `quarantined_llm.py`

Add a required `have_enough_information: bool` field to the default
`WorkerReport` schema. If the Worker returns `False`, the
`QuarantinedExecutor` re-queries with more context rather than
acting on partial output.

This forces the Worker to signal uncertainty rather than hallucinate,
reducing the class of attacks where the Worker is manipulated into
returning plausible-but-wrong structured data.

**Files:** Extend `tessera/quarantine.py`.
**Effort:** ~40 lines.
**Breaking:** Yes, adds a required field to WorkerReport. Needs migration.
**Test:** Worker returns have_enough_information=False, executor retries.

### 6.3 Security-Aware Error Redaction

**Source:** CaMeL `format_camel_exception` with `is_trusted()` check

When a SecurityEvent or error message originates from untrusted data,
redact its content before exposing it to the LLM or logging it in
detail. This prevents oracle attacks where an attacker crafts inputs
specifically to learn about the security policy from error messages.

**Files:** Extend `tessera/events.py`.
**Effort:** ~50 lines.
**Test:** Error from untrusted source is redacted in event payload.

---

## Phase 7: Composability Layer (Larger effort, ecosystem value)

### 7.1 NeMo Guardrails Adapter

Build a `tessera.adapters.nemo` module that:
- Exposes Tessera policy evaluation as a NeMo `@action`
- Injects trust labels as NeMo context variables (`$trust_level`,
  `$segment_origin`, `$readers`)
- Routes NeMo tracing spans to Tessera `register_sink`

This lets NeMo Guardrails deployments add cryptographic provenance
and taint tracking without replacing their existing rail configuration.

**Files:** New `tessera/adapters/nemo.py`.
**Effort:** ~200 lines.
**Dependency:** `nemoguardrails` (optional extra).

### 7.2 LlamaFirewall Scanner Adapter

Build a `tessera.adapters.llamafirewall` module that wraps
LlamaFirewall's `scan()` as a Tessera scanner. Tessera provides the
trust-label-based targeting (only scan untrusted segments),
LlamaFirewall provides the scanner implementations (PromptGuard,
CodeShield, HiddenASCII, AlignmentCheck).

**Files:** New `tessera/adapters/llamafirewall.py`.
**Effort:** ~100 lines.
**Dependency:** `llamafirewall` (optional extra).

### 7.3 Agent Audit SARIF Correlation

Build a sink that ingests Agent Audit SARIF output and correlates
static findings with runtime SecurityEvents by OWASP category. When a
runtime event fires for a tool that Agent Audit flagged statically,
enrich the SecurityEvent with the static finding's details.

**Files:** New `tessera/compliance_sarif.py`.
**Effort:** ~150 lines.
**Dependency:** Phase 2.4 (OWASP mapping), Phase 5.5 (SARIF output).

---

## Phase 8: Evaluation Infrastructure (Ongoing)

### 8.1 CyberSecEval-Compatible Benchmark Suite

**Source:** PurpleLlama CybersecurityBenchmarks

Build a benchmark harness that runs Tessera-protected agent pipelines
against CyberSecEval's prompt injection dataset and reports results
in CyberSecEval-compatible format. This produces numbers directly
comparable to Meta's published model evaluations.

**Files:** New `benchmarks/cyberseceval/` directory.
**Effort:** ~300 lines.

### 8.2 Autonomous Injection Resistance Test

**Source:** CyberSecEval autonomous uplift benchmark

Build an end-to-end test that runs a Tessera-protected agent against
a poisoned environment (MCP server with injected tool descriptions,
web content with embedded injections, compromised RAG documents) and
measures whether any injected instruction survives the taint-tracking
policy to reach a privileged tool call.

**Files:** New `benchmarks/e2e_injection/` directory.
**Effort:** ~400 lines.

---

## Implementation Priority Matrix

| Phase | Effort | Security Payoff | Dependencies | Recommended Order |
|-------|--------|-----------------|--------------|-------------------|
| 1.1 Unicode tags | XS | High | None | Week 1 |
| 1.2 Tool desc poisoning | S | High | None | Week 1 |
| 1.3 MCP baseline drift | S | High | None | Week 1 |
| 1.4 Tool shadowing | S | Medium | None | Week 1 |
| 2.2 Fnmatch patterns | XS | Medium | None | Week 2 |
| 2.3 Side-effect classification | S | High | None | Week 2 |
| 2.4 OWASP mapping | S | Medium | None | Week 2 |
| 2.1 Readers lattice | M | High | None | Week 3 |
| 4.1 Injection taxonomy | M | Medium | None | Week 3 |
| 5.4 Confidence tiers | S | Medium | None | Week 3 |
| 3.1 PromptGuard 2 | M | High | torch | Week 4 |
| 3.2 CodeShield | S | Medium | codeshield | Week 4 |
| 3.3 Perplexity heuristic | M | Medium | transformers | Week 4 |
| 5.1 Scanner caching | S | Medium | Phase 3 | Week 5 |
| 5.2 Parallel scanners | S | Medium | Phase 3 | Week 5 |
| 5.5 SARIF output | M | Medium | None | Week 5 |
| 4.2 AgentDojo eval | L | Critical | Phases 1-3 | Week 6 |
| 6.1 Dependency accumulator | M | High | Phase 2.3 | Week 7 |
| 6.2 have_enough_info | S | Medium | None | Week 7 |
| 6.3 Error redaction | S | Medium | None | Week 7 |
| 7.1 NeMo adapter | M | Medium | nemoguardrails | Week 8 |
| 7.2 LlamaFirewall adapter | S | Medium | llamafirewall | Week 8 |
| 8.1 CyberSecEval compat | L | High | Phase 4 | Week 9 |

XS = < 50 lines, S = 50-150 lines, M = 150-300 lines, L = 300+ lines

---

## What We Are Deliberately Not Building

### Full AST interpreter (CaMeL-style)

CaMeL's 2,700-line Python AST interpreter is the right solution for
environments where the LLM generates executable code. Tessera's threat
model assumes the LLM calls tools via a framework (LangChain, OpenAI
Agents SDK, MCP), not via generated Python. Adding an AST interpreter
would be scope creep, and CaMeL already exists under Apache 2.0.
Instead, we compose: Phase 2.1 (readers lattice) and Phase 6.1
(dependency accumulator) adopt CaMeL's security insights without
reimplementing the interpreter.

### Colang or dialogue state machine

NeMo's Colang is a DSL for conversation flow control. Tessera is a
security primitives library, not a dialogue engine. Conversation flow
belongs in the agent framework (LangChain, CrewAI, etc.) or in NeMo
Guardrails itself. Tessera composes with NeMo via the Phase 7.1
adapter rather than reimplementing Colang.

### RAG knowledge base

NeMo includes a built-in RAG knowledge base with vector embeddings.
This is an application concern, not a security primitive. Tessera
should label retrieved content with trust levels (it already does via
MCP interceptor auto-labeling), not manage the retrieval itself.

### Content safety model training

PromptGuard 2 is an 86M parameter fine-tuned mDeBERTa. Training and
maintaining a competing classifier is not the right use of engineering
time. Phase 3.1 integrates PromptGuard 2 as an optional backend.

### Hallucination detection

NeMo's self-consistency hallucination check (sample N completions,
compare) is valuable but orthogonal to Tessera's threat model. Tessera
defends against indirect prompt injection, not model hallucination.
If hallucination detection is needed, compose with NeMo via Phase 7.1.

### Multi-vendor content safety plugin ecosystem

NeMo ships 16+ content safety vendor integrations. Building competing
integrations with ActiveFence, Cleanlab, CrowdStrike, etc. is not
differentiated work. Tessera's value is cryptographic provenance and
taint tracking. Content safety vendors are integrated at the scanner
layer via generic adapters (Phase 3, Phase 7.2).

---

## Competitive Positioning Summary

| Capability | Tessera | CaMeL | PurpleLlama | NeMo | Agent Audit |
|---|---|---|---|---|---|
| Cryptographic provenance | Yes (HMAC, JWT) | No | No | No | No |
| Taint tracking | Context-level | Variable-level | No | No | Static only |
| Schema-enforced dual-LLM | Yes | Partial | No | No | No |
| Delegation tokens | Yes | No | No | No | No |
| Workload identity (SPIFFE) | Yes | No | No | No | No |
| ML injection detection | After Phase 3 | No | PromptGuard 2 | GPT-2 perplexity | No |
| Code security scanning | After Phase 3 | No | CodeShield | No | Python AST |
| Dialogue flow control | No (compose) | No | No | Colang | No |
| Static code analysis | No (compose) | No | No | No | Yes |
| OWASP Agentic mapping | After Phase 2 | No | No | No | Yes |
| MCP baseline drift | After Phase 1 | No | No | No | Yes |
| AgentDojo evaluation | After Phase 4 | Yes | Partial | No | No |
| Readers lattice (ACL) | After Phase 2 | Yes | No | No | No |
| SIEM integration | Yes | No | No | OTel only | SARIF |
| Human-in-the-loop gates | Yes | No | Scanner-level | Colang flows | No |
| Rust data plane | Yes | No | No | No | No |

After completing Phases 1-4, Tessera will have the broadest security
coverage of any single tool in this space, while maintaining its core
differentiator: cryptographic provenance and taint tracking are
properties none of the other tools provide.
