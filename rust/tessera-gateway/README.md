# tessera-gateway

Rust reference data plane for Tessera primitives.

This crate proves the Tessera primitives (trust labels, taint-floor
policy, delegation, provenance, workload identity, evidence bundles)
port cleanly to a Rust data plane suitable for production traffic. It
is not a competing proxy. The long-term goal is to contribute these
primitives upstream to [agentgateway](https://agentgateway.dev/) (Linux
Foundation) as a middleware plugin, aligning with Tessera's design
principle of composing with existing infrastructure rather than
replacing it.

## Status (v0.7.x)

~12,100 lines of Rust across 8 modules; 172 unit tests + 3 cross-language
interop tests pass. The crate ports the load-bearing security primitives
from the Python reference and exposes them through a 10-endpoint REST
surface that mirrors the AgentMesh proxy for the same primitives.

| Module                             | Status     | Tests | Mirrors Python                          |
|------------------------------------|------------|-------|------------------------------------------|
| `labels`                           | complete   | 16    | `tessera.labels`                         |
| `context`                          | complete   | 9     | `tessera.context`                        |
| `policy`                           | complete   | 8     | `tessera.policy` (taint-floor only)      |
| `session_context`                  | complete   | 18    | `tessera.session_context`                |
| `audit_log`                        | complete   | 19    | `tessera.audit_log` (interop verified)   |
| `ssrf_guard`                       | complete   | 31    | `tessera.ssrf_guard`                     |
| `url_rules`                        | complete   | 14    | `tessera.url_rules`                      |
| `endpoints`                        | complete   | 13    | subset of `agentmesh.proxy`              |
| chat / A2A / SPIFFE / TLS (legacy) | complete   | 44    | n/a (gateway-specific)                   |

The on-disk audit log format is byte-for-byte interoperable with the
Python reference: a chain written by Rust verifies in
`tessera.audit_log.verify_chain` and vice versa, including the optional
HMAC seal. Cross-language interop is exercised by
`tests/python_audit_interop.rs`.

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

## What's deliberately NOT ported

These live in the Python admin / data plane and either compose with
existing tooling or aren't load-bearing at the data path:

- `tessera.guardrail` LLM judge: this calls an LLM and lives behind
  a circuit breaker; runs better as an out-of-band Python service.
- `tessera.replay` / `tessera.policy_builder` / `policy_builder_llm`:
  operator-time tools that consume the audit log this crate writes.
- `tessera.scanners.*`: heuristic / directive / intent / canary /
  promptguard / yara / supply_chain. These compose well with the
  existing chat-mediation path; not ported here.
- The 14 framework adapters (LangChain, OpenAI Agents, etc.). Those
  are application-side, not gateway-side.
- Sensitivity HWM / IFC: belongs adjacent to the policy engine if
  ported; the existing chat-mediation path handles this case for
  chat traffic today.

These are intentional gaps. Production gateways need the security
primitives at line speed; the operator UX runs on Python where it
already works.

## Performance

Microbench numbers from `cargo bench --bench policy_eval` on a recent
Apple M-series:

| Operation                                | Rust per-op | Python per-op | Speedup |
|------------------------------------------|-------------|---------------|---------|
| `Policy.evaluate` (allow path)           | 121 ns      | ~50,000 ns    | ~410x   |
| `Policy.evaluate` (deny path)            | 133 ns      | ~50,000 ns    | ~380x   |
| `Policy.evaluate` (10-segment context)   | 132 ns      | ~50,000 ns    | ~380x   |
| `url_rules.evaluate` (allow / deny / no_match) | 57-86 ns | n/a       | n/a     |
| `ssrf_guard.check_url` (literal IP)      | 1,044 ns    | n/a           | n/a     |
| `audit_log.append` (no fsync)            | 36,200 ns   | n/a           | n/a     |
| `SessionContextStore.get` (warm)         | 40,069 ns   | n/a           | n/a     |
| `label_sign` (HMAC-SHA256, 32-byte body) | 863 ns      | n/a           | n/a     |
| `label_verify`                           | 725 ns      | n/a           | n/a     |

Reproduce with `cargo bench --bench policy_eval`.

## Configuration (new in v0.7.x)

In addition to the existing `TESSERA_*` env vars (preserved unchanged
for the legacy chat / A2A paths), the primitives router reads:

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
- `/v1/chat/completions` with HMAC label verification, optional prompt provenance
  verification, spotlighted upstream payload rendering, optional upstream
  forwarding, signed workload identity on `ASM-Agent-Identity`,
  proof-of-possession on `ASM-Agent-Proof`, signed delegation on
  `ASM-Agent-Delegation`, replay protection for proofs, mTLS transport
  identity from a native TLS listener, direct request extensions, or trusted
  `X-Forwarded-Client-Cert`,
  and min-trust tool-call gating against the caller-declared tool surface
- `/a2a/jsonrpc` with JSON-RPC `tasks.send`, shared workload identity and mTLS
  enforcement, verified `tessera_security_context` provenance and delegation,
  intent trust-floor gating, and optional upstream forwarding
- security event emission for label, identity, proof, delegation, provenance,
  and policy denial paths via registerable sinks

Runtime knobs:
- `TESSERA_HMAC_KEY` enables HMAC label verification
- `TESSERA_PROVENANCE_HMAC_KEY` optionally separates prompt provenance signing
  from label signing
- `TESSERA_UPSTREAM_URL` turns chat handling from echo mode into proxy mode
- `TESSERA_A2A_UPSTREAM_URL` turns A2A handling on and forwards verified
  `tasks.send` payloads upstream
- `TESSERA_A2A_REQUIRED_TRUST_JSON` optionally pins per-intent trust
  requirements as a JSON object, defaults to `USER` trust when omitted
- `TESSERA_POLICY_OPA_URL` enables an external deny-only OPA backend for chat
  tool calls and A2A intents after local trust and delegation checks pass
- `TESSERA_POLICY_OPA_PATH` overrides the OPA Data API decision path, defaults
  to `/v1/data/tessera/authz/allow`
- `TESSERA_POLICY_OPA_TOKEN` adds bearer auth on OPA requests
- `TESSERA_POLICY_FAIL_CLOSED_BACKEND_ERRORS` defaults to fail closed, set it
  false only if you want backend faults to degrade open
- `TESSERA_POLICY_INCLUDE_PROVENANCE` defaults to true and asks OPA for
  decision provenance plus bundle revisions
- `TESSERA_IDENTITY_HS256_KEY` enables HS256 workload identity verification
- `TESSERA_IDENTITY_ISSUER` optionally pins the workload identity issuer
- `TESSERA_IDENTITY_AUDIENCE` overrides the default identity audience
- `TESSERA_TLS_CERT_PATH` enables the native Rust TLS listener with this server
  certificate chain
- `TESSERA_TLS_KEY_PATH` points at the matching server private key
- `TESSERA_TLS_CLIENT_CA_PATH` loads client trust anchors for native client
  certificate validation
- `TESSERA_REQUIRE_MTLS` requires transport identity on every request
- `TESSERA_TRUST_XFCC` allows trusted `X-Forwarded-Client-Cert` handoff
- `TESSERA_TRUSTED_PROXY_HOSTS` lists immediate proxy hosts allowed to supply
  `X-Forwarded-Client-Cert`
- `TESSERA_MTLS_TRUST_DOMAINS` pins acceptable SPIFFE trust domains for
  transport identity
- `TESSERA_DELEGATION_KEY` optionally separates delegation signing from label
  signing
- `TESSERA_DELEGATION_AUDIENCE` overrides the default delegation audience

What does not exist yet in the legacy surface:
- production control plane, policy distribution, and fleet management
- richer sink surface like the Python reference implementation's webhook and
  evidence helpers

What external policy parity means here:
- the Rust gateway sends a redacted normalized policy input, not raw prompt
  content
- local trust-floor and delegation denies stay authoritative, the backend only
  refines already-local-allowed actions
- backend faults fail closed by default
- deny responses surface backend metadata so callers can correlate decisions

This crate is intentionally honest. The coverage matrix above lists
exactly which Python primitives have been ported and which are still
Python-only. We do not claim parity for anything we have not shipped.
