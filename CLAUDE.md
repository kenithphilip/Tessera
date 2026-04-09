# CLAUDE.md

Context file for AI assistants working in the Tessera repository.

## What this project is

Tessera is a reference implementation of two security primitives for LLM
agent systems. The primitives are specified in
[`papers/two-primitives-for-agent-security-meshes.md`](papers/two-primitives-for-agent-security-meshes.md).
That paper is the authoritative specification. This codebase exists to
prove the primitives are tractable, not to be the production
implementation of them.

The two primitives are:

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

## Project state as of the initial public release

- **Version:** v0.0.1, published April 2026
- **Source:** ~1,556 lines of Python across 12 modules in `src/tessera/`
- **Tests:** 1,187 lines, 65 passing, runtime under 2 seconds
- **Python:** 3.12+ only
- **Dependencies:** FastAPI, Pydantic, PyJWT with cryptography, the `mcp`
  Python package, optional OpenTelemetry SDK

Stable APIs:

- `tessera.labels.TrustLabel`
- `tessera.context.make_segment`, `Context`
- `tessera.policy.Policy`, `Decision`
- `tessera.quarantine.QuarantinedExecutor`, `strict_worker`, `WorkerReport`
- `tessera.signing.HMACSigner`, `HMACVerifier`, `JWTSigner`, `JWTVerifier`, `JWKSVerifier`
- `tessera.events.SecurityEvent`, `register_sink`

Less stable, expected to change:

- `tessera.proxy` (FastAPI reference, meant to be ported into a Rust data plane)
- `tessera.mcp` interceptor interface (will change when MCP SEP-1913 lands)
- Security event sink API (will grow as more SIEM integrations land)

## Development workflow

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

All tests must pass before any change is committed. The suite is fast
(~2 seconds); there is no excuse to skip it.

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
src/tessera/           source modules
tests/                 pytest suite
examples/              runnable demos (offline + real-API)
deployment/spire/      SPIRE docker-compose reference (not end-to-end tested)
papers/                position paper, authoritative spec
docs/                  additional documentation (architecture, roadmap, etc.)
CLAUDE.md              this file
SECURITY.md            threat model and disclosure policy
CONTRIBUTING.md        contribution standards
README.md              public-facing entry point
LICENSE                Apache 2.0
```

## Memory discipline for AI assistants

- Do not overclaim Tessera's scope. It is two primitives, not "an agent
  security mesh." Pitch it as a composable library that slots into any
  existing mesh (agentgateway, Bedrock AgentCore, Microsoft Agent
  Governance Toolkit).
- Do not guess at numbers. If a user asks for CaMeL latency comparisons,
  say we do not have them yet and point to Section 4.5 of the paper.
- Do not fabricate SPIRE deployment experience. The `deployment/spire/`
  reference has not been stood up end-to-end in CI. Say so when asked.
- Do not add emojis.
- Do not use em dashes or en dashes in any output, including code
  comments and git commit messages.
