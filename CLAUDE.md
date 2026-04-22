# CLAUDE.md

Context file for AI assistants working in the Tessera repository.

## What this project is

Tessera is a Python library of composable security primitives for LLM
agent systems. Two load-bearing invariants drive the design and are
specified in
[`papers/two-primitives-for-agent-security-meshes.md`](papers/two-primitives-for-agent-security-meshes.md).
That paper is the authoritative specification of those two invariants
and remains the security target the code is held to. The library has
grown around them since the paper was published; the supporting
primitives compose with the two invariants but do not replace them.

The two load-bearing invariants are:

1. **Signed trust labels on context segments, with taint tracking at the
   tool-call boundary.** Every chunk of text entering the LLM's context
   carries a cryptographically bound label (HMAC or JWT-SVID). The policy
   engine evaluates tool calls against `min(trust_level)` across the
   context, which drags the whole context to the floor as soon as any
   untrusted segment is present. The core invariant is in
   `tessera.policy.Policy.evaluate`.

2. **Schema-enforced dual-LLM execution.** The Worker model is structurally
   prevented from returning free-form text via a Pydantic schema validator
   (`tessera.quarantine.strict_worker`). The default `WorkerReport`
   contains no free-form string fields. This closes the Worker-to-Planner
   injection channel in Simon Willison's dual-LLM pattern without
   requiring a custom interpreter.

Supporting primitives that compose with the two invariants:

- `tessera.audit_log`: append-only JSONL hash chain. Persistent record
  of policy decisions; tamper detection without the signing key.
- `tessera.replay`: re-runs historical decisions against any candidate
  policy callable. Reads the audit log, scores agreement, surfaces
  fixed / regressed counts driven by ground-truth labels.
- `tessera.policy_builder` and `tessera.policy_builder_llm`:
  deterministic and LLM-driven proposers that emit scored
  `ToolRequirement` adjustments.
- `tessera.ssrf_guard`: outbound URL gate with encoded-IP decoding,
  DNS-rebinding defense, cloud-metadata-specific rule IDs.
- `tessera.url_rules`: deterministic URL allow / deny tier evaluated
  before the SSRF guard and scanners.

These do not change the two load-bearing invariants. They add
durability, replayability, and policy authoring on top.

## Threat model (narrow on purpose)

We defend against **indirect prompt injection**: an attacker controls some
segment of data entering the agent's context window and attempts to
trigger a privileged action the delegating user did not authorize.

We do NOT defend against:

- Direct prompt injection by the authenticated user
- Model-level attacks (backdoors, data poisoning, weight extraction)
- Compromised MCP servers or tool implementations
- Supply-chain attacks on weights, prompts, or tool manifests
- Sandbox escape for agent-generated code
- Semantic poisoning of the agent's output to the user

If a bug report is about one of the above, it is out of scope. Point the
reporter at `SECURITY.md` and the threat model section of the paper.

## Load-bearing invariants that must not be weakened

These are enforced by tests. If you change code that affects them, the
tests will break. If you change the tests too, you are weakening the
security primitive. Do not do that without explicit discussion.

1. **`Context.min_trust` drives policy decisions.** Never add a code path
   that evaluates tool calls against any segment's trust level in
   isolation. Always use the minimum across the context.
2. **`WorkerReport` has no free-form string fields.** Do not add
   `summary: str`, `notes: str`, `description: str`, or any field whose
   type is a plain `str` without a validator or enum constraint. If a
   use case needs free-form text, the user must define their own schema
   and document how the Planner treats that field.
3. **`strict_worker` emits a `SecurityEvent` before raising
   `WorkerSchemaViolation`.** Do not move the emit after the raise. The
   emit must fire even if the caller catches the exception.
4. **Policy denies emit `SecurityEvent` events.** Allow paths do not.
   Keep it this way, SIEM volume depends on it.
5. **Binary content from MCP tool outputs is replaced with a structured
   marker.** Never pass base64 data fields through as text. The
   `_default_extract` function in `tessera.mcp` handles this, with a
   test that pins the behavior against real `mcp.types.ImageContent`.
6. **JWT verifiers have a 30-second clock-skew leeway by default.** Do
   not remove it without replacing it with a documented justification.

## Tessera vs AgentMesh

Tessera is the primitives library: signed provenance labels, taint-tracking
policy, schema-enforced dual-LLM execution, delegation, workload identity,
audit, replay, policy synthesis, scanners, and the supporting
infrastructure. It is designed to compose with any agent mesh, not to be
one.

AgentMesh is the deployed mesh built on Tessera: a FastAPI proxy
(39 HTTP endpoints) that wires the Tessera primitives into a single
service, plus 15 SDK adapters (11 frameworks: LangChain, OpenAI Agents,
CrewAI, Google ADK, LlamaIndex, LangGraph, Haystack, PydanticAI,
NeMo Guardrails, AgentDojo, generic; 4 coding-agent hooks: Claude Code,
Cursor, Copilot, Gemini). AgentMesh ships v0.7.0 on PyPI as
`agentmesh-mesh` and depends on `tessera-mesh>=0.7.0`.

When writing about this project, do not conflate the two. Tessera is the
library; AgentMesh is the mesh deployment built from it.

## Project state

- **Version:** v0.7.0, published April 2026
- **Python source:** ~26,800 lines across 98 implementation modules in `src/tessera/`
  (excludes `__init__.py` and protobuf-generated `_pb2*` files)
- **Rust gateway:** ~8,200 lines in `rust/tessera-gateway/` (reference data plane)
- **Python tests:** 1409 passing, runtime ~10 seconds
- **Rust tests:** 45 tokio::test functions in `lib.rs`
- **Python:** 3.12+ only
- **Dependencies:** FastAPI, Pydantic, PyJWT with cryptography, httpx,
  the `mcp` Python package, optional OpenTelemetry SDK

Stable APIs (unlikely to change before v1.0):

- `tessera.labels.TrustLabel`, `Origin`, `TrustLevel`
- `tessera.context.make_segment`, `Context`
- `tessera.policy.Policy`, `Decision`
- `tessera.delegation.DelegationToken`, `sign_delegation`, `verify_delegation`
- `tessera.provenance.ContextSegmentEnvelope`, `PromptProvenanceManifest`
- `tessera.quarantine.QuarantinedExecutor`, `strict_worker`, `WorkerReport`
- `tessera.signing.HMACSigner`, `HMACVerifier`, `JWTSigner`, `JWTVerifier`, `JWKSVerifier`
- `tessera.events.SecurityEvent`, `register_sink`
- `tessera.redaction.SecretRegistry`, `redact_nested`
- `tessera.audit_log.JSONLHashchainSink`, `ChainedRecord`, `ReplayEnvelope`,
  `make_replay_detail`, `verify_chain`, `iter_records`
- `tessera.replay.ReplayCase`, `LabelStore`, `iter_replay_cases`,
  `run_replay`, `score`
- `tessera.ssrf_guard.SSRFGuard`, `SSRFCheckResult`
- `tessera.url_rules.URLRulesEngine`, `URLRule`, `URLDecision`

Less stable, expected to change:

- `tessera.proxy` (FastAPI reference, production deployments use the Rust gateway or agentgateway)
- `tessera.mcp` interceptor interface (will change when MCP SEP-1913 lands)
- `tessera.a2a` transport and verification helpers
- `tessera.identity` workload identity and proof-of-possession
- `tessera.mtls` transport identity extraction
- `tessera.spire` Workload API adapters
- `tessera.policy_backends` external policy backend integration
- `tessera.evidence` evidence bundle format
- `tessera.control_plane` reference control plane (not for production use)
- `tessera.cel_engine` CEL expression engine (cel-python API may evolve)
- `tessera.approval` and `tessera.sessions` approval gate design is early
- `tessera.ir` intermediate representation (schema will grow with new config features)
- `tessera.hooks` gRPC hook wire format (may change before v1.0)
- `tessera.xds` gRPC wire format (delta-xDS and ACK/NACK planned for later release)
- `tessera.scanners` content analysis (heuristic, canary, PII detection)
- `tessera.risk` session-level risk intelligence (irreversibility, salami, cooldown)
- `tessera.compliance` NIST/CWE enrichment (separate from `tessera.audit_log`'s hash chain)
- `tessera.ratelimit` token budget enforcement
- `tessera.mcp.MCPSecurityContext`
- `tessera.policy_builder` and `tessera.policy_builder_llm` proposal
  templates (will grow; the underlying scoring path via replay is stable)
- `tessera.guardrail.LLMGuardrail` breaker tuning surface and event
  detail shape
- Security event sink API (will grow as more SIEM integrations land)

## Development workflow

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

All tests must pass before any change is committed. The suite is fast
(~6 seconds); there is no excuse to skip it.

To run a specific test:
```bash
pytest tests/test_policy.py::test_web_content_taints_context_and_blocks_sensitive_tool -v
```

To check style:
- No em dashes or en dashes anywhere. Use commas, colons, periods, or
  parentheses. The accompanying paper and all docs follow this rule.
- No emojis in code, commits, docs, or output.
- Type annotations on all public APIs.
- `from __future__ import annotations` at the top of every module.
- Minimal comments. Explain the non-obvious "why", not the "what".
- Docstrings on public classes and functions. Docstrings on `WorkerReport`
  and `strict_worker` are part of the security contract and must not be
  weakened.

## What to never change without explicit discussion

- The `WorkerReport` default schema (see invariant #2 above).
- The `Context.min_trust` computation (invariant #1).
- The HMAC signing format in `tessera.labels` (would break any deployment
  with labels in flight or stored at rest).
- The JWT claim format in `tessera.signing._claims_for` (would break
  interop with any existing verifier).
- The `TrustLevel` enum values (`UNTRUSTED=0, TOOL=50, USER=100,
  SYSTEM=200`). Reordering or adding levels between existing ones would
  reshuffle the ordering semantics.
- The `_default_extract` binary-content-marker format in `tessera.mcp`.
  Production deployments may be grepping for the `[binary content: ...]`
  string.

## Working with the paper

The paper in `papers/two-primitives-for-agent-security-meshes.md` is the
authoritative specification of the primitives. When the code and the
paper disagree, the paper is the target and the code must be fixed to
match, unless there is a documented reason to update the paper.

If you add a new invariant to the code, add the test that pins it, then
update Appendix A of the paper with the test name. The paper's Appendix
A is the primary way external readers verify our claims.

## Where things live

```
src/tessera/           Python primitives library (98 implementation modules
                       under hooks/, xds/, scanners/, risk/, adapters/)
rust/tessera-gateway/  Rust reference data plane
tests/                 pytest suite (1409 passing)
benchmarks/            microbenchmark suite (python -m benchmarks)
examples/              runnable demos (offline + real-API)
deployment/spire/      SPIRE docker-compose reference (not end-to-end tested)
papers/                position paper, authoritative spec for the two invariants
docs/                  architecture, roadmap, changelog, mesh specs
CLAUDE.md              this file
SECURITY.md            threat model and disclosure policy
CONTRIBUTING.md        contribution standards
README.md              public-facing entry point
LICENSE                AGPL-3.0-or-later
```

## Memory discipline for AI assistants

- Tessera is the primitives library. AgentMesh is the deployed mesh
  built from it. Do not conflate them. When someone asks "what is
  Tessera," say it is a Python library of composable security primitives
  for LLM agent systems with two load-bearing invariants (signed trust
  labels with taint tracking, schema-enforced dual-LLM execution) and a
  growing set of supporting primitives. When someone asks "what is
  AgentMesh," say it is a FastAPI proxy and SDK adapter layer that wires
  Tessera into a single deployable service.
- Do not overclaim Tessera's scope. It has grown well beyond the original
  two primitives (now includes audit, replay, policy synthesis, SSRF and
  URL gating, delegation, provenance, identity, A2A, policy backends,
  evidence), but the two original invariants remain the load-bearing
  security properties; the rest are supporting primitives that compose
  with them. Pitch Tessera as composable with any existing mesh
  (agentgateway, Bedrock AgentCore, Microsoft Agent Governance Toolkit).
- The Rust gateway (`rust/tessera-gateway/`) is a reference implementation
  proving the primitives port to a production data plane. It is not a
  competitor to agentgateway. The goal is to contribute these primitives
  upstream. Say this when asked.
- The control plane (`tessera.control_plane`) is a reference integration
  surface, not a production control plane. Production deployments should
  use an existing control plane. Say this when asked.
- Do not guess at numbers. If a user asks for CaMeL latency comparisons,
  say we do not have them yet and point to Section 4.5 of the paper.
- Do not fabricate SPIRE deployment experience. The `deployment/spire/`
  reference has not been stood up end-to-end in CI. Say so when asked.
- Do not add emojis.
- Do not use em dashes or en dashes in any output, including code
  comments and git commit messages.
