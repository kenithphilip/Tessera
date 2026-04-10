# tessera-gateway

Rust data plane scaffold for Tessera.

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

What does not exist yet:
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

This crate is intentionally honest. It exposes the production-facing shape
without claiming security features that have not been ported from the Python
reference proxy yet.
