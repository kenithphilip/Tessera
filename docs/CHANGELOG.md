# Changelog

All notable changes to Tessera are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Everything before v1.0.0 is experimental; API changes may occur in any
minor release.

## [Unreleased]

### Added

- `benchmarks/` microbenchmark suite (`python -m benchmarks`) covering
  HMAC sign and verify, `make_segment`, `Context.min_trust` and
  `Context.render`, `Policy.evaluate` allow and deny, `WorkerReport`
  validation, and an end-to-end per-request path.
- `docs/benchmarks.md` reference snapshot of benchmark results on an
  Apple Silicon laptop running Python 3.12.
- Paper Section 4.5 updated with the concrete numbers from the
  benchmark suite: approximately 1 microsecond for Pydantic validation,
  approximately 32 microseconds for the full per-request path, and
  roughly 0.016 percent overhead against a 200-millisecond LLM round-trip.
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
- A2A JSON-RPC `tasks.send` ingress on the FastAPI reference proxy
- prompt provenance enforcement and delegation enforcement on the proxy
- inbound `ASM-Agent-Identity` and `ASM-Agent-Proof` enforcement on the
  proxy
- inbound mTLS transport identity enforcement on the proxy, including
  SPIFFE URI SAN extraction and explicit trusted-proxy XFCC support
- delegate-to-agent identity binding on delegated requests
- MCP security context carriage for delegation and provenance
- delegated `requires_human_for` and domain allowlist checks in policy
- `tessera.cel_engine` CEL expression engine for deny-only policy
  refinements via `[cel]` optional dependency; `CELRule` and
  `CELPolicyEngine` evaluate against request, context, and delegation
  attributes
- `tessera.policy`: `ResourceType` enum (TOOL, PROMPT, RESOURCE) for
  MCP RBAC per-resource authorization; `PolicyScope` enum (MESH, TEAM,
  AGENT) with `Policy.merge()` enforcing higher scopes as trust floors;
  `DecisionKind.REQUIRE_APPROVAL` for human-in-the-loop gating
- `tessera.approval` human-in-the-loop approval gates with fail-closed
  webhook delivery; `HumanApprovalGate` blocks tool calls that require
  human authorization and dispatches a signed webhook request
- `tessera.sessions` encrypted in-memory session store for pending
  approvals; `SessionStore` with TTL expiry and optional Fernet
  encryption; expired sessions auto-resolve as DENY
- `tessera.ir` intermediate representation for policy configuration;
  `PolicyIR` compiled from YAML or dict via `from_yaml_string()` and
  `from_dict()`; `compile_policy()` converts IR to a live `Policy`
- `tessera.hooks` gRPC extension hook dispatcher; `HookDispatcher`
  with `PostPolicyEvaluateHook` and `PostToolCallGateHook` protocols,
  deny-only semantics, and fail-closed behavior on timeout or error;
  `RemoteHookClient` for calling external extension servers
- `tessera.xds` xDS-compatible resource distribution; `XDSServer`
  with content-addressed versioning, HTTP/SSE push via `add_to_app()`,
  and gRPC `AggregatedDiscoveryService` via `GRPCXDSServer`
  (`StreamResources` bidirectional streaming, `FetchResources` unary);
  `PolicyBundleResource`, `ToolRegistryResource`, `TrustConfigResource`
  with full serialization support
- Rust gateway: filter pipeline with `Filter` trait and `FilterChain`
  extracting `LabelVerificationFilter`, `IdentityVerificationFilter`,
  `PolicyEvaluationFilter`, and `UpstreamFilter` from the monolithic
  handler; `SecretString` credential management via the `secrecy` crate
- `proto/tessera/xds/v1/` and `proto/tessera/hooks/v1/` protobuf
  definitions (package `tessera_proto.xds.v1` and `tessera_proto.hooks.v1`)
- Human-in-the-loop approval gates now integrated into the policy engine
  via `Policy.requires_human_approval()`
- GitHub repository topics for discoverability: llm-security,
  agent-security, prompt-injection, indirect-prompt-injection,
  taint-tracking, dual-llm, mcp, spiffe, grpc, and more

### Changed

- Removed employer attribution from README, paper byline, and ROADMAP
  v1.0.0 gate. Tessera is a personal project.
- Test suite now stands at 350 passing tests (up from 216 at last entry)
- `pyproject.toml` xds optional dependency bumped to `grpcio>=1.70` to
  match generated stub requirements
- Repository assistant context and roadmap statistics updated to match
  the current tree
- SPIRE reference docs now describe live JWT-SVID identity retrieval and
  trust-bundle verification instead of treating JWT-SVIDs as signing keys

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

## Unreleased

No unreleased changes. Next planned items are tracked in
[`ROADMAP.md`](ROADMAP.md).
