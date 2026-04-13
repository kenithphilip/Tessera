# Proposal: Trust-Label-Aware Security Middleware for agentgateway

**Author:** Kenith Philip

**Status:** Draft, April 2026

**Target:** agentgateway maintainers (Linux Foundation)

---

## 1. Problem Statement

Agent traffic through proxies today lacks content-level provenance.
Existing proxies, including agentgateway, enforce transport-level security
(mTLS, OAuth, API key validation) but cannot distinguish user instructions
from attacker-controlled content within the LLM context window. This is
the root cause of indirect prompt injection succeeding even in "secured"
agent deployments.

The threat model is specific. An attacker controls some segment of data
entering the agent's context (a scraped web page, a retrieved document, a
tool output from a third-party MCP server, a memory entry from a previous
session). The attacker's goal is to cause the agent to take a privileged
action that the delegating user did not authorize. Transport-layer
defenses do not help here because the malicious content arrives over an
authenticated, authorized channel. The security gap is inside the request,
not around it.

This proposal describes a middleware for agentgateway that closes that gap
by verifying cryptographically signed trust labels on each segment of the
context window and enforcing taint-tracking policy at the tool-call
boundary.

---

## 2. Proposed Middleware: `TesseraTrustMiddleware`

A middleware that plugs into agentgateway's request pipeline and performs
four operations in sequence:

### 2.1 Label Verification

Each message in a chat completion request (or each input segment in an A2A
task payload) carries a `TrustLabel` in its metadata. The middleware
verifies the cryptographic signature on each label before the request
proceeds. Two signing modes are supported:

- **HMAC-SHA256**: Symmetric key verification. The signature covers
  `origin | principal | trust_level | nonce | sha256(content)`. Suitable
  for single-trust-domain deployments where the signer and verifier share
  a key.

- **JWT-SVID**: Asymmetric verification. The label's signature field
  carries a compact JWS. The verifier resolves the public key via a JWKS
  endpoint (typically a SPIRE trust bundle endpoint). Suitable for
  multi-workload meshes. A configurable clock-skew leeway (default 30
  seconds) accommodates NTP drift with short-lived SPIRE SVIDs.

Requests with invalid or missing signatures are rejected with HTTP 401.
Each rejection emits a `SecurityEvent` with kind `label_verify_failure`
before the response is sent.

### 2.2 Taint-Floor Computation

The middleware computes `min(trust_level)` across all labeled segments in
the request. This is the taint floor. A single segment with
`trust_level = 0` (UNTRUSTED) drags the entire context to 0, regardless
of how many high-trust segments are present.

This is the load-bearing invariant. It must be enforced via `min`, not
`max` or `mean`. The use of `min` provides indirect prompt injection
defense by construction: if attacker-controlled content is present in the
context, the agent cannot trigger a tool call that requires user-level
authorization because the taint floor is already at UNTRUSTED.

### 2.3 Tool-Call Policy Evaluation

When the upstream LLM responds with proposed tool calls, the middleware
evaluates each call against the taint floor:

```
allow(tool, ctx) iff required_trust(tool) <= min(segment.trust_level for all segments in ctx)
```

Tools declare a minimum required trust level. Tools without an explicit
declaration inherit a default of `USER` (100). Deny-by-default.

Both ALLOW and DENY decisions are deterministic. They do not depend on the
LLM's output, the model provider, or any textual content. The check
happens outside the model.

DENY decisions emit a `SecurityEvent` with kind `policy_deny`. ALLOW
decisions do not emit events (keeps SIEM volume proportional to risk, not
to traffic).

### 2.4 Optional: External Policy Backend Callout

After the taint-floor check passes, the middleware can optionally call an
external policy backend (OPA or Cedar) for attribute-based decisions. The
taint check runs first because it is local, fast, and deterministic. The
backend callout runs second because it requires a network round-trip.

The policy input sent to the backend includes:

```rust
pub struct PolicyInput {
    pub action_kind: String,        // "tool_call" or "a2a_intent"
    pub tool: String,               // tool name or A2A intent
    pub args: Option<Value>,        // tool arguments (for arg-level rules)
    pub principal: Option<String>,  // delegating user principal
    pub required_trust: i64,        // tool's declared minimum
    pub observed_trust: i64,        // taint floor
    pub min_trust_passed: bool,     // true (taint check already passed)
    pub origin_counts: HashMap<String, usize>,  // {user: 2, web: 1, tool: 3}
    pub segment_summary: Vec<PolicySegmentSummary>,
    pub delegation: Option<PolicyDelegationSummary>,
}
```

Backend errors are fail-closed by default (configurable).

### 2.5 Passthrough on Allow

When all checks pass, the middleware passes the request to the upstream
without modifying it. The only request modification is optional
Spotlighting: wrapping segments below `TOOL` trust in
`<<<TESSERA-UNTRUSTED>>>` delimiters as defense-in-depth for the model.

---

## 3. Primitives to Extract: `tessera-primitives` Crate

The middleware depends on a small set of data structures and functions that
should be packaged as an independent `tessera-primitives` Rust crate. This
crate has no web framework dependency and can be consumed by any Rust
proxy, not only agentgateway.

### 3.1 TrustLabel

```rust
pub struct TrustLabel {
    pub origin: Origin,       // User, System, Tool, Memory, Web
    pub principal: String,    // identity string (e.g., "alice", SPIFFE ID)
    pub trust_level: i64,     // 0 (UNTRUSTED), 50 (TOOL), 100 (USER), 200 (SYSTEM)
    pub nonce: String,        // 128-bit random value, hex-encoded
    pub signature: String,    // hex-encoded HMAC or compact JWS
}

pub enum Origin {
    User,
    System,
    Tool,
    Memory,
    Web,
}
```

The trust level ordering is: `UNTRUSTED(0) < TOOL(50) < USER(100) <
SYSTEM(200)`. These values are stable and must not be reordered.

### 3.2 HMAC Signing and Verification

```rust
/// Sign a trust label over content using HMAC-SHA256.
/// Canonical payload: "{origin}|{principal}|{trust_level}|{nonce}|{sha256(content)}"
pub fn sign_label(label: &TrustLabel, content: &str, key: &[u8]) -> String;

/// Verify a trust label signature in constant time.
pub fn verify_label(label: &TrustLabel, content: &str, key: &[u8]) -> bool;
```

The canonical serialization is pipe-delimited. The content is not included
directly; its SHA-256 digest is used. This means label verification does
not require holding the full content in memory if the digest was computed
during streaming.

### 3.3 JWT-SVID Signing and Verification

```rust
pub struct JwtLabelSigner {
    pub encoding_key: EncodingKey,
    pub algorithm: Algorithm,
    pub issuer: String,
    pub audience: String,
}

pub struct JwtLabelVerifier {
    pub decoding_key: DecodingKey,
    pub algorithms: Vec<Algorithm>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub leeway: u64,  // clock-skew tolerance in seconds, default 30
}

pub struct JwksLabelVerifier {
    pub jwks_url: String,
    pub algorithms: Vec<Algorithm>,
    pub leeway: u64,
}
```

The JWT claims set includes `sub` (principal), `aud` (audience), `iss`
(issuer), `exp`, `nbf`, `iat`, and custom claims for `origin`,
`trust_level`, `nonce`, and `content_sha256`.

### 3.4 SecurityEvent

```rust
pub struct SecurityEvent {
    pub kind: EventKind,
    pub principal: String,
    pub detail: Value,       // structured JSON, schema varies by kind
    pub timestamp: String,   // ISO-8601 UTC
}

pub enum EventKind {
    PolicyDeny,
    LabelVerifyFailure,
    IdentityVerifyFailure,
    ProofVerifyFailure,
    ProvenanceVerifyFailure,
    DelegationVerifyFailure,
}
```

Sink system:

```rust
pub type EventSink = Arc<dyn Fn(SecurityEvent) + Send + Sync>;

pub fn register_sink(sink: impl Fn(SecurityEvent) + Send + Sync + 'static);
pub fn emit_event(event: SecurityEvent);
```

Sinks are called in registration order. A panicking sink is caught and
swallowed. The security path must not fail because of an observability
bug.

### 3.5 Taint-Floor Policy Evaluation

```rust
/// Compute the minimum trust level across all segments.
pub fn min_trust(segments: &[impl HasTrustLevel]) -> i64;

/// Evaluate a tool call against the taint floor.
/// Returns Allow iff required_trust(tool) <= min_trust(segments).
pub fn evaluate_tool_call(
    tool_name: &str,
    required_trust: i64,
    observed_trust: i64,
) -> Decision;

pub enum Decision {
    Allow,
    Deny {
        reason: String,
        required_trust: i64,
        observed_trust: i64,
    },
}
```

### 3.6 EvidenceBundle

```rust
pub struct EvidenceBundle {
    pub schema_version: String,   // "tessera.evidence.v1"
    pub generated_at: String,     // ISO-8601 UTC
    pub event_count: usize,
    pub dropped_events: usize,
    pub counts_by_kind: BTreeMap<String, usize>,
    pub events: Vec<Value>,
}

pub struct SignedEvidenceBundle {
    pub bundle: EvidenceBundle,
    pub algorithm: String,
    pub signature: String,
    pub issuer: Option<String>,
    pub key_id: Option<String>,
}
```

Evidence bundles use deterministic canonical JSON serialization (sorted
keys, no whitespace) for reproducible digests and signatures.

---

## 4. Integration Points

### 4.1 Request Interception

The middleware parses `TrustLabel` metadata from each message in OpenAI
chat completion payloads and from each input segment in A2A `tasks.send`
JSON-RPC payloads. The label is expected as a `label` object on each
message:

```json
{
  "role": "user",
  "content": "...",
  "label": {
    "origin": "user",
    "principal": "alice",
    "trust_level": 100,
    "nonce": "a1b2c3...",
    "signature": "deadbeef..."
  }
}
```

For A2A, the security context (including delegation and provenance) is
carried in the `metadata.tessera_security_context` field of the
`tasks.send` params.

### 4.2 Response Interception

After the upstream LLM responds, the middleware inspects the response for
proposed tool calls (in `choices[].message.tool_calls[]`). Each proposed
call is evaluated against the taint floor computed during request
interception. The middleware annotates the response with the evaluation
results:

```json
{
  "tessera": {
    "allowed": [{"name": "read_file", "arguments": {...}}],
    "denied": [
      {
        "tool": "send_email",
        "denied": true,
        "reason": "context contains a segment at trust_level=0, below required 100",
        "required_trust": 100,
        "observed_trust": 0
      }
    ]
  }
}
```

### 4.3 Configuration

Per-tool trust requirements via agentgateway configuration (static) or OPA
policy bundles (dynamic). Example static configuration:

```yaml
tessera:
  label_hmac_key: ${TESSERA_LABEL_HMAC_KEY}
  default_required_trust: 100  # USER
  tool_requirements:
    send_email: 100     # USER
    read_file: 50       # TOOL
    web_search: 50      # TOOL
    delete_data: 200    # SYSTEM
  opa:
    url: http://opa:8181
    path: /v1/data/tessera/authz/allow
```

Dynamic policy updates via control plane (pull-based polling with HMAC
signature verification on policy documents).

### 4.4 Observability

`SecurityEvent` records are exported alongside agentgateway's existing
telemetry. Three built-in sinks:

1. **Structured JSON to stdout**: one line per event, for `kubectl logs`
   and log aggregator ingestion.
2. **Async webhook**: bounded queue with background worker, for SIEM
   webhook endpoints.
3. **Evidence buffer**: ring buffer of recent events, exportable as a
   signed `EvidenceBundle` for audit.

The event schema is the same across the Python library (`tessera`), the
Rust reference gateway (`tessera-gateway`), and the proposed agentgateway
middleware. SIEM queries and detection rules work across all deployment
modes without modification.

---

## 5. What This Enables for agentgateway Users

1. **Deterministic defense against indirect prompt injection at the proxy
   layer.** The taint-floor invariant is a mathematical property of the
   `min` function over trust levels. It does not depend on model behavior,
   prompt phrasing, or probabilistic defenses.

2. **Content-level provenance without agent code changes.** Agent
   frameworks and application code do not need modification. The
   middleware operates on labeled metadata attached to messages at the
   point of origin (SDK, MCP server, memory layer). The proxy verifies
   and enforces.

3. **Compatible with existing SPIFFE/SPIRE infrastructure.** JWT-SVID
   label verification uses the same trust bundles and JWKS endpoints that
   agentgateway already supports for workload identity. No new PKI.

4. **Composable with OPA/Cedar.** The taint-floor check is the first
   stage. OPA or Cedar is the second stage. The two are complementary:
   taint tracking answers "is the context contaminated," attribute-based
   policy answers "is this principal authorized for this action on this
   resource." Neither replaces the other.

5. **Audit-grade evidence.** Signed evidence bundles provide
   tamper-evident records of all deny decisions. Evidence bundles use
   deterministic canonical JSON serialization, so their SHA-256 digests
   are reproducible.

---

## 6. Compatibility

### 6.1 SecurityEvent Schema

The `SecurityEvent` schema is identical across:

- `tessera` (Python library): `tessera.events.SecurityEvent`
- `tessera-gateway` (Rust reference): `SecurityEvent` in `lib.rs`
- This proposed agentgateway middleware

Fields: `kind` (enum string), `principal` (string), `detail` (JSON
object), `timestamp` (ISO-8601 UTC string). SIEM queries and Sigma
detection rules work across all three without modification.

### 6.2 Label Format

The trust label format and canonical serialization are the same across
Python and Rust. Labels signed by the Python library verify correctly
in the Rust gateway and vice versa. This has been tested.

### 6.3 A2A Interop

The A2A security context schema (delegation, provenance envelopes,
labeled input segments) is consistent across the Python reference proxy
and the Rust gateway. The proposed middleware uses the same schema.

---

## 7. Prior Art and References

- **Microsoft Spotlighting** (Hines et al., 2024): Datamarking reduces
  indirect prompt injection success from over 50% to under 2% in their
  measurements. Tessera uses Spotlighting delimiters as defense-in-depth
  alongside deterministic taint tracking.

- **CaMeL** (Debenedetti et al., Google DeepMind, 2025): Capability-based
  data provenance enforced through a custom interpreter. Reported 6.6x
  latency cost. Tessera's taint-tracking approach operates at a measured
  approximately 32 microseconds per request end-to-end, relying on
  structural enforcement rather than interpreter-based data flow
  tracking.

- **MCP SEP-1913**: Proposed trust and sensitivity annotations for MCP
  tool outputs. When SEP-1913 lands, the middleware should ingest
  `trust_level` annotations from MCP tool responses directly, reducing
  reliance on per-deployment external-tool registries.

- **Tessera paper**: "Two Primitives for Agent Security Meshes" (Philip,
  2026). Specifies the two primitives with test-verified invariants and
  a narrow threat model.

---

## 8. What This Proposal Does Not Cover

To be precise about scope:

- **Direct prompt injection by the authenticated user.** If the user is
  hostile, trust labels do not help. The primitives defend the user from
  third-party content, not the system from the user.

- **Semantic poisoning of the agent's output.** The defense is at the
  tool-call boundary, not at the generation boundary. If the agent's text
  response is the final artifact, an attacker who poisoned the context can
  still poison the response.

- **Compromised MCP servers or tool implementations.** If the MCP server
  itself is compromised, the tool output is attacker-controlled from the
  start. Labels can correctly classify that output as untrusted only if the
  deployment has declared the tool as an external fetcher.

- **Model-level attacks.** Backdoors, data poisoning, weight extraction,
  and adversarial examples against model weights are out of scope.

---

## 9. Open Questions for the agentgateway Team

These are decisions that depend on agentgateway's architecture and
roadmap. This proposal does not presume answers.

### 9.1 Plugin Model

agentgateway uses Envoy-style middleware chains. Questions:

- What is the preferred interface for a middleware that needs to inspect
  both the request (to verify labels and compute the taint floor) and the
  response (to evaluate proposed tool calls)? Is this a single middleware
  with pre/post hooks, or two separate middleware instances?
- Is there a trait or interface contract for request/response middleware
  that this should implement?
- How does middleware state (the taint floor computed during request
  interception) flow from the request phase to the response phase?

### 9.2 Streaming Inspection

Chat completion APIs support streaming responses (`stream: true`). Tool
calls in streaming responses arrive incrementally across multiple SSE
chunks. Questions:

- Does agentgateway currently buffer streaming responses for middleware
  inspection, or does it pass them through unbuffered?
- If unbuffered, is the middleware responsible for its own buffering to
  reassemble tool calls from incremental chunks before policy evaluation?
- What is the acceptable latency budget for response-side middleware in
  the streaming case?

### 9.3 Configuration Surface

The middleware needs per-tool trust requirements and signing key material.
Questions:

- Does agentgateway have an existing configuration surface for per-route
  or per-tool metadata that this should use?
- Is there a preferred secret management integration (Kubernetes secrets,
  Vault, environment variables) for key material?
- Should the middleware support dynamic policy updates (pull-based from a
  control plane), or is static configuration sufficient for the initial
  contribution?

### 9.4 Crate Packaging

The `tessera-primitives` crate is independent of any web framework.
Questions:

- Would the agentgateway team prefer this as an external crate dependency,
  or vendored into the agentgateway repository?
- If external, is there a preferred registry or hosting model for
  dependencies?
- What is the MSRV (minimum supported Rust version) for agentgateway
  dependencies?

### 9.5 Testing and CI

The Tessera Rust gateway has 40 tests covering label verification, policy
evaluation, A2A mediation, mTLS identity, delegation, provenance,
evidence bundles, and OPA callout. Questions:

- Does agentgateway have integration test infrastructure that this
  middleware should plug into?
- Are there performance benchmarks or regression tests that new middleware
  must pass?

---

## 10. Proposed Next Steps

1. Open an issue on the agentgateway repository describing the middleware
   and linking this proposal.
2. Get feedback from agentgateway maintainers on the plugin model, config
   surface, and streaming questions.
3. Extract `tessera-primitives` as a standalone Rust crate with no web
   framework dependencies.
4. Implement `TesseraTrustMiddleware` against agentgateway's middleware
   interface based on maintainer feedback.
5. Contribute the middleware and crate as a pull request with tests and
   documentation.

---

## Appendix A: Existing Implementation

A complete Rust implementation of the primitives described in this
proposal exists in the Tessera repository at `rust/tessera-gateway/`
(approximately 7,400 lines, 40 tests). The implementation covers:

- HMAC-SHA256 label signing and verification with constant-time comparison
- Taint-floor policy evaluation (`min_trust` across context segments)
- OPA policy backend callout with structured `PolicyInput`
- A2A JSON-RPC mediation with per-intent trust requirements
- mTLS with SPIFFE SAN extraction from DER-encoded client certificates
- Signed evidence bundles with canonical JSON serialization
- Security event emission with pluggable sinks (including async webhook)
- DPoP-style proof-of-possession with replay cache
- Delegation token verification
- Prompt provenance envelope and manifest verification
- Spotlighting delimiters for defense-in-depth
- Agent Card discovery document (`.well-known/agent.json`)

The dependencies are: `axum`, `tokio`, `reqwest`, `jsonwebtoken`, `hmac`,
`sha2`, `rustls`, `spiffe`, `serde`, `serde_json`, `chrono`, `uuid`,
`hex`, `base64`, `tower`, `tower-http`, `tokio-rustls`.

The `tessera-primitives` crate extraction would factor out the core types
and verification functions, leaving the HTTP layer as a thin adapter that
any proxy (including agentgateway) can implement against its own framework.
