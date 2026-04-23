# tessera-gateway

Rust reference data plane for Tessera primitives. The terminal crate
in the workspace: it owns the axum app, the native TLS listener,
SPIFFE workload identity, the control-plane sync loop, and the
`/v1/*` REST surface. Everything else
(`tessera_core`, `tessera_audit`, `tessera_policy`,
`tessera_runtime`) is library code that this crate composes into a
running service.

This crate proves the Tessera primitives port cleanly to a Rust data
plane suitable for production traffic. It is not a competing proxy.
The long-term goal is to contribute the load-bearing pieces upstream
to [agentgateway](https://agentgateway.dev/) (Linux Foundation),
aligning with Tessera's design principle of composing with existing
infrastructure rather than replacing it.

## Status (v0.8.0-alpha.1)

176 tests passing across the workspace; the gateway crate's lib
ships 54 of those plus the legacy chat / A2A integration tests.
Phase 1 of the multi-phase Rust port plan landed as this release:
workspace split into 7 crates, mimalloc as the global allocator,
`arc-swap` on the policy / URL-rules hot path, HTTP/2 ALPN on the
TLS listener.

| Module                             | Crate                | Status     | Mirrors Python                          |
|------------------------------------|----------------------|------------|------------------------------------------|
| `labels`                           | `tessera-core`       | complete   | `tessera.labels`                         |
| `context`                          | `tessera-core`       | complete   | `tessera.context`                        |
| `policy`                           | `tessera-policy`     | complete   | `tessera.policy` (taint-floor only)      |
| `ssrf_guard`                       | `tessera-policy`     | complete   | `tessera.ssrf_guard`                     |
| `url_rules`                        | `tessera-policy`     | complete   | `tessera.url_rules`                      |
| `audit_log`                        | `tessera-audit`      | complete   | `tessera.audit_log` (interop verified)   |
| `session_context`                  | `tessera-runtime`    | complete   | `tessera.session_context`                |
| `endpoints`                        | `tessera-gateway`    | complete   | subset of `agentmesh.proxy`              |
| chat / A2A / SPIFFE / TLS (legacy) | `tessera-gateway`    | complete   | n/a (gateway-specific)                   |

The on-disk audit log format stays byte-for-byte interoperable with
the Python reference: a chain written by Rust verifies in
`tessera.audit_log.verify_chain` and vice versa, including the
optional HMAC seal. Cross-language interop is exercised by
`tests/python_audit_interop.rs`.

`tessera_gateway::*` re-exports every former path
(`tessera_gateway::labels::TrustLabel`, etc.) from the new crate
locations, so embedders that pinned to the v0.7.x flat module
layout keep building unchanged.

## Endpoint surface

| Endpoint                       | Method | Purpose                                   |
|--------------------------------|--------|-------------------------------------------|
| `/healthz`                     | GET    | proxy health, primitive feature flags     |
| `/v1/sessions`                 | GET    | active session ids and eviction stats     |
| `/v1/context?session_id=...`   | GET    | one session's Context state               |
| `/v1/context/split?...`        | GET    | trusted / untrusted halves                |
| `/v1/reset?session_id=...`     | POST   | drop one session                          |
| `/v1/evaluate`                 | POST   | full taint-tracking policy decision       |
| `/v1/label`                    | POST   | sign and add a tool output to context     |
| `/v1/audit/verify`             | GET    | walk the JSONL hash chain                 |
| `/v1/ssrf/check`               | POST   | SSRF guard verdict on a URL               |
| `/v1/url-rules/check`          | POST   | static URL rules verdict                  |

The legacy chat / A2A endpoints (`/.well-known/agent.json`,
`/v1/chat/completions`, `/a2a/jsonrpc`, `/v1/tessera/status`) coexist
on the same listener via `Router::merge`.

## What's deliberately NOT ported (yet)

These live in the Python reference and are scheduled for later
phases or compose better as out-of-process services:

- `tessera.guardrail` LLM judge: Phase 4. Calls an LLM behind a
  circuit breaker. The Rust port keeps a `LlmClient` trait so the
  underlying call can route to either a Rust HTTP client or via PyO3
  callback to a Python implementation.
- `tessera.replay` / `tessera.policy_builder` /
  `policy_builder_llm`: Phase 3. Operator-time tooling that consumes
  the audit log this crate writes.
- Hard scanners (`promptguard`, `perplexity`, `pdf_inspector`,
  `image_inspector`, `codeshield`): Phase 4 ships a PyO3 callback
  bridge so the Python ML / PIL implementations stay authoritative;
  no functionality loss, no ONNX rewrite gating the release.
- The 14 framework adapters (LangChain, OpenAI Agents, etc.) stay
  application-side; not gateway-side.
- Sensitivity HWM, ratelimit, evidence, provenance, mcp_baseline,
  delegation, compliance: Phase 2 ports these to `tessera-policy`.

These are intentional gaps with shipping dates, not unknowns. The
plan is at `~/.claude/plans/buzzing-baking-waterfall.md`.

## Performance

Microbench numbers from `cargo bench -p tessera-bench --bench
policy_eval -- --warm-up-time 1 --measurement-time 3` on Apple M3
Pro (rustc 1.94, release profile + lto = "thin", mimalloc allocator,
ArcSwap on hot-path state):

| Operation                                       | Rust per-op | Python per-op | Speedup |
|-------------------------------------------------|-------------|---------------|---------|
| `Policy.evaluate` (allow path)                  | 110 ns      | ~50,000 ns    | ~450x   |
| `Policy.evaluate` (deny path)                   | 127 ns      | ~50,000 ns    | ~390x   |
| `Policy.evaluate` (10-segment context)          | 136 ns      | ~50,000 ns    | ~370x   |
| `url_rules.evaluate` (allow / deny / no_match)  | 51-78 ns    | n/a           | n/a     |
| `ssrf_guard.check_url` (literal IP)             | 977 ns      | n/a           | n/a     |
| `audit_log.append` (no fsync)                   | 34,085 ns   | n/a           | n/a     |
| `SessionContextStore.get` (warm)                | 73 ns       | n/a           | n/a     |
| `label_sign` (HMAC-SHA256, 32-byte body)        | 764 ns      | n/a           | n/a     |
| `label_verify`                                  | 698 ns      | n/a           | n/a     |

Full baseline at `rust/bench/baseline.md`. The headline allow path
shaved ~10 ns versus v0.7.x's `121 ns` from the mimalloc + ArcSwap
swap-ins; future phases will re-run this same suite to keep numbers
honest.

## Configuration (carried forward from v0.7.x, unchanged)

The primitives router reads:

- `TESSERA_PRINCIPAL` (default: `tessera-gateway`): principal field
  on signed labels and audit records this gateway emits.
- `TESSERA_HMAC_KEY`: 32+ byte symmetric key for label signing /
  verification on the new endpoints. Defaults to a placeholder, set
  in production.
- `TESSERA_AUDIT_LOG_PATH`: path to the JSONL audit log. Empty =
  in-memory only (no `/v1/audit/verify` data).
- `TESSERA_AUDIT_LOG_FSYNC_EVERY` (default: `1`): batch this many
  appends before fsync. Higher = more throughput, more loss on
  crash.
- `TESSERA_AUDIT_LOG_SEAL_KEY`: optional HMAC key for the truncation
  seal. When set, a `<path>.seal` file is updated on every append.

## Legacy surface (chat mediation, A2A, SPIFFE, TLS)

What exists:
- `/.well-known/agent.json`
- `/v1/chat/completions` with HMAC label verification, optional
  prompt provenance verification, spotlighted upstream payload
  rendering, optional upstream forwarding, signed workload identity
  on `ASM-Agent-Identity`, proof-of-possession on `ASM-Agent-Proof`,
  signed delegation on `ASM-Agent-Delegation`, replay protection for
  proofs, mTLS transport identity from a native TLS listener, direct
  request extensions, or trusted `X-Forwarded-Client-Cert`, and
  min-trust tool-call gating against the caller-declared tool
  surface
- `/a2a/jsonrpc` with JSON-RPC `tasks.send`, shared workload
  identity and mTLS enforcement, verified
  `tessera_security_context` provenance and delegation, intent
  trust-floor gating, and optional upstream forwarding
- security event emission for label, identity, proof, delegation,
  provenance, and policy denial paths via registerable sinks

Runtime knobs: see the previous v0.7.x README; same set still
applies. New in v0.8.0-alpha.1: HTTP/2 multiplexing now negotiates
automatically on the native TLS listener via ALPN; no env knob, no
opt-in.

What does not exist yet in the legacy surface:
- production control plane, policy distribution, and fleet
  management
- richer sink surface like the Python reference implementation's
  webhook and evidence helpers

This crate is intentionally honest. The coverage matrix above lists
exactly which Python primitives have been ported and which are still
Python-only; the phase plan tells you when each remaining gap
closes.
