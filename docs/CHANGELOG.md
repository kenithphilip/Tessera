# Changelog

All notable changes to Tessera are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Everything before v1.0.0 is experimental; API changes may occur in any
minor release.

## [0.3.0] - 2026-04-16

### Added

- tessera.guardrail: LLM guardrail layer for semantic injection classification. Optional fallback that fires only on ambiguous FREE_TEXT tool outputs where deterministic scanners cannot decide. Provider-agnostic (Anthropic, OpenAI-compatible). Structured-output-only (Pydantic model, no free-form text). GuardrailCache with SHA-256 keyed LRU.
- EventKind.GUARDRAIL_DECISION with NIST SI-10/SC-7, CWE-77, OWASP ASI-01 mappings
- benchmarks/agentdojo_live/run_baseline.py: baseline evaluator without Tessera for honest utility comparison
- Content-type-aware taint: FREE_TEXT tools use directive + override-confirmed only, structured tools use full corroboration

### Changed

- Adapter guardrail integration: optional guardrail parameter on TesseraToolLabeler, EnhancedSecurityAdapter, TesseraCallbackHandler
- Scanner corroboration: sliding-window heuristic needs regex or directive confirmation
- Schema registry: file/review/calendar tools as FREE_TEXT, price/rating as STRUCTURED, key:value markers suppress prose detection
- Taint binding: bind_from_tool_output prefers highest-trust segment, model-generated values treated as clean
- LangChain adapter: shared context (not per-run), correct callback attributes, verified against real framework
- Override regex broadened: added "override" verb, flexible word order

### Verified

- Live evaluation: Claude Haiku 4.5, 100% APR (80/80), 3.1pp utility cost vs baseline
- Baseline comparison: 46.4% without Tessera, 43.3% with Tessera (banking identical at 62.5%)
- Replay evaluator: 100% APR, 100% utility, 3893 trials, zero false positives
- LangChain adapter: injection blocked, clean flow allowed, verified with real model

## [0.2.0] - 2026-04-15

### Added

- tessera.content_inspector: multimodal inspection pipeline (image, PDF, audio, HTML, binary)
- tessera.scanners.binary_content: PDF active content, image metadata injection, MIME validation, base64 payload scanning
- tessera.scanners.pdf_inspector: 5-phase sandboxed PDF analysis (raw key scan, hex-encoded JS detection, CDR sanitization, sandboxed text extraction, URL analysis)
- tessera.scanners.image_inspector: LSB steganography detection, invisible text detection, adversarial perturbation detection
- tessera.mcp_allowlist: rug-pull detection via ToolDefinitionTracker, registration pattern scanning, version pinning, certificate fingerprint fields
- tessera.read_only_guard: per-tool argument policies (FIDES-inspired), toxic flow detection (PCAS-inspired)
- tessera.rag_guard: RetrievalPatternTracker for PoisonedRAG defense, EmbeddingAnomalyChecker for outlier detection
- tessera.ratelimit.ToolCallRateLimit: burst detection with cooldown, session lifetime limits
- tessera.output_monitor: post-generation output integrity checker (n-gram similarity, task relevance, injection output patterns)
- tessera.policy_invariant: runtime control-flow invariant enforcement (PolicyBypassError)
- tessera.adapters.enhanced: reference adapter composing all security components
- specs/tessera_control_flow.tla: TLA+ control-flow invariant spec
- Live AgentDojo evaluation with Mistral Large: 100% APR (80/80), 0% false positive rate

### Changed

- Directive scanner wired into live adapter labeler (fixes travel breach)
- Value-level taint (DependencyAccumulator) wired into live adapter guard
- Pipeline ordering fixed: guard runs BEFORE ToolsExecutor
- Scanner false positive improvements: model-targeting check, past-tense filters, target qualifiers
- Test count: 1171 passing (up from 991 at v0.1.0)
- Python source: ~21,700 lines across 101 modules (up from ~18,200/92)

### Removed

- findings.md (audit artifact)
- docs/AGENT_SECURITY_MESH_GAP_AUDIT_2026-04-10.md (timestamped audit)
- benchmarks/agentdojo_live/*.json (benchmark results with API metadata)

## [0.1.0] - 2026-04-14

### Added

- `benchmarks/` microbenchmark suite (`python -m benchmarks`) covering
  HMAC sign and verify, `make_segment`, `Context.min_trust` and
  `Context.render`, `Policy.evaluate` allow and deny, `WorkerReport`
  validation, and an end-to-end per-request path
- `docs/benchmarks.md` reference snapshot of benchmark results on an
  Apple Silicon laptop running Python 3.12
- Paper Section 4.5 updated with concrete benchmark numbers
- `tessera.delegation` with signed delegation tokens and verification
- `tessera.provenance` with signed context segment envelopes and prompt
  provenance manifests
- `tessera.a2a` with A2A security carriage helpers and fail-closed
  verification
- `tessera.identity` with workload identity tokens, proof-of-possession,
  and replay protection
- `tessera.mtls` with SPIFFE-aware transport identity extraction from
  the ASGI TLS extension and trusted XFCC
- `tessera.spire` with live SPIRE Workload API adapters for JWT-SVID
  retrieval and trust-bundle-backed verifier configuration
- A2A JSON-RPC ingress, prompt provenance enforcement, and delegation
  enforcement on the FastAPI reference proxy
- Inbound mTLS transport identity enforcement on the proxy with SPIFFE
  URI SAN extraction and trusted-proxy XFCC support
- `tessera.cel_engine` CEL expression engine for deny-only policy
  refinements via `[cel]` optional dependency
- `tessera.policy`: `ResourceType` enum for MCP RBAC, `PolicyScope` enum
  with `Policy.merge()`, `DecisionKind.REQUIRE_APPROVAL` for
  human-in-the-loop gating
- `tessera.approval` human-in-the-loop approval gates with fail-closed
  webhook delivery
- `tessera.sessions` encrypted in-memory session store for pending
  approvals with TTL expiry
- `tessera.ir` intermediate representation: compile YAML/dict policy
  config to live `Policy` instances
- `tessera.hooks` gRPC extension hook dispatcher with deny-only semantics
  and fail-closed behavior
- `tessera.xds` xDS-compatible resource distribution over HTTP/SSE and
  gRPC ADS
- `tessera.scanners.directive` directive injection scanner
- `tessera.scanners.intent` intent classification scanner
- `tessera.scanners.prompt_screen` inbound prompt screening
- `tessera.scanners.tool_output_schema` schema enforcement on tool outputs
- `tessera.scanners.canary` canary token tracking and leakage detection
- `tessera.scanners.tool_shadow` tool description shadow detection
- `tessera.output_monitor` output manipulation defense
- `tessera.delegation_intent` delegation intent verification
- `tessera.trust_decay` time-based trust decay per origin
- `tessera.plan_verifier` multi-step plan verification against policy
- `tessera.side_channels` constant-time comparison, timing jitter, output
  padding
- `tessera.claim_provenance` binds model assertions to source tool outputs
- `tessera.confidence` confidence scoring with model-targeting and
  tense-aware filtering
- `tessera.taint` value-level taint tracking
- `tessera.adapters.crewai` CrewAI step callback adapter
- `tessera.adapters.google_adk` Google ADK before/after tool callbacks
- `tessera.adapters.llamaindex` LlamaIndex callback handler
- `tessera.adapters.haystack` Haystack pipeline component
- `tessera.adapters.langgraph` LangGraph tool node wrapper
- `tessera.adapters.pydantic_ai` PydanticAI tool wrapper
- `tessera.adapters.agentdojo` AgentDojo benchmark adapter
- YAML policy DSL completion with `side_effects` and `critical_args`
  declarations
- Memory poisoning defense via taint-aware retrieval scoring
- `benchmarks/adversarial/` adversarial injection benchmark scenario
- `benchmarks/agentdojo/` AgentDojo integration benchmark scenario
- `benchmarks/injection_taxonomy/` injection taxonomy benchmark scenario
- Rust gateway: filter pipeline with `Filter` trait, `FilterChain`, and
  `SecretString` credential management via the `secrecy` crate
- `proto/tessera/xds/v1/` and `proto/tessera/hooks/v1/` protobuf
  definitions
- Human-in-the-loop approval gates integrated into `Policy` via
  `requires_human_approval()`

### Changed

- Value-level taint now wired into the policy evaluator and adapter layer
- Scanner precision improvements with model-targeting check and
  past-tense filters to reduce false positives
- Heuristic injection patterns updated with target qualifiers
- Test suite: 991 passing tests (up from 65 at v0.0.1)
- Python source: ~18,200 lines across 92 modules (up from ~2,500 at
  v0.0.1)
- Test code: ~15,700 lines (up from ~1,200 at v0.0.1)
- Removed employer attribution; Tessera is a personal project
- `pyproject.toml` xds optional dependency bumped to `grpcio>=1.70`

### Fixed

- CEL engine `ListType` API call updated for cel-python 0.5 compatibility
- Rust gateway secrets routed through `expose_secret()` instead of
  raw access

## [0.0.1] - 2026-04-10

### Initial public release

First public release of the two primitives described in
[`../papers/two-primitives-for-agent-security-meshes.md`](../papers/two-primitives-for-agent-security-meshes.md):
signed trust labels with taint tracking, and schema-enforced dual-LLM
execution.

### Added

**Core primitives:**

- `tessera.labels.TrustLabel` with HMAC-SHA256 signing bound to content
- `tessera.signing.JWTSigner`, `JWTVerifier`, `JWKSVerifier` for
  SPIFFE JWT-SVID signing with 30-second clock-skew leeway
- `tessera.signing.HMACSigner`, `HMACVerifier` wrapper classes
  satisfying the `LabelSigner` / `LabelVerifier` protocol
- `tessera.context.make_segment` accepting either an HMAC key or any
  `LabelSigner`, with exactly-one validation
- `tessera.context.Context` with `min_trust`, `max_trust`, and
  `principal` properties
- Spotlighting delimiter rendering for untrusted segments
- `tessera.policy.Policy` taint-tracking engine with deny-by-default
  and per-tool trust requirements
- `tessera.quarantine.QuarantinedExecutor` implementing the dual-LLM
  pattern with `split_by_trust`
- `tessera.quarantine.strict_worker` Pydantic-enforced worker wrapper
- `tessera.quarantine.WorkerReport` safe-by-default schema with no
  free-form string fields
- `tessera.quarantine.WorkerSchemaViolation` terminal exception

**Infrastructure:**

- `tessera.mcp.MCPInterceptor` auto-labeling tool outputs via a
  Protocol-based MCP client abstraction
- `tessera.mcp._default_extract` with binary content marker-ification
  preventing base64 smuggling
- `tessera.registry.ToolRegistry` org-level external-tool classification
  with registry-wins-on-inclusion semantics
- `tessera.events.SecurityEvent` structured event type
- `tessera.events.EventKind` with `POLICY_DENY`,
  `WORKER_SCHEMA_VIOLATION`, `LABEL_VERIFY_FAILURE`
- Built-in sinks: `stdout_sink`, `otel_log_sink`, `webhook_sink(url)`
- `tessera.telemetry` OpenTelemetry spans for proxy, MCP, policy,
  quarantine with no-op fallback
- `tessera.proxy` FastAPI sidecar with OpenAI-compatible endpoint
- `tessera.cli` with `tessera serve` entrypoint

**Documentation:**

- Position paper at `papers/two-primitives-for-agent-security-meshes.md`
  with threat model, invariants, primitives, and standardization asks
- `README.md` public entry point with usage examples
- `CLAUDE.md` context file for AI assistants working in the repo
- `SECURITY.md` with threat model and coordinated disclosure policy
- `CONTRIBUTING.md` with contribution standards
- `docs/ARCHITECTURE.md` module-level architecture overview
- `docs/ROADMAP.md` forward-looking plan
- `docs/CHANGELOG.md` this file

**Examples:**

- `examples/injection_blocked.py` minimal offline demo
- `examples/quarantine_demo.py` dual-LLM demo with stub models
- `examples/quarantine_openai.py` real OpenAI API demo with
  `EarningsFacts` schema

**Deployment reference:**

- `deployment/spire/docker-compose.yml` with SPIRE server, agent, and
  retrieval workload
- `deployment/spire/server.conf` and `deployment/spire/agent.conf`
- `deployment/spire/README.md` walkthrough

### Security invariants pinned by tests

The following invariants are enforced by the test suite. See Appendix A
of the paper for the full list with test names.

- Tool calls deny when any context segment is below the tool's required
  trust level (`test_web_content_taints_context_and_blocks_sensitive_tool`)
- Tampered label signatures are rejected at the proxy boundary
  (`test_proxy_rejects_tampered_signature`)
- Worker output that does not validate against the schema raises
  `WorkerSchemaViolation` and emits a security event
  (`test_free_form_text_fails_closed`, `test_worker_schema_violation_emits_event`)
- Binary content from MCP tools is replaced with a marker rather than
  passed through as base64
  (`test_real_mcp_image_content_does_not_leak_base64`)
- JWT label round-trip validates with default clock-skew leeway
  (`test_jwt_round_trip`, `test_jwt_verifier_has_default_leeway`)

### Known limitations

- `deployment/spire/` has not been exercised end-to-end in CI. See
  `deployment/spire/STATUS.md` for details.
- `examples/quarantine_openai.py` requires an `OPENAI_API_KEY` and is
  not covered by the automated test suite.
- `Context.principal` returns the first USER segment's principal;
  multi-principal contexts are not yet supported.
- No benchmark against CaMeL's reported 6.6x latency cost. The paper
  flags this explicitly in Section 4.5.
- HMAC is the default signing mode and requires all workloads to share
  a symmetric key. Multi-workload deployments should use JWT-SVIDs.
- FastAPI proxy is a reference implementation, not a production
  artifact. Production deployments should port the primitives into a
  Rust data plane.

### Test suite at initial release

- 65 tests passing at initial publication
- ~1,200 lines of test code
- Runtime: ~2 seconds
- Coverage includes integration tests against the real `mcp` Python
  package, JWT round-trip tests with in-test RSA keypair generation,
  and security event emission tests

---

## [Unreleased]

No unreleased changes. Next planned items are tracked in
[`ROADMAP.md`](ROADMAP.md).
