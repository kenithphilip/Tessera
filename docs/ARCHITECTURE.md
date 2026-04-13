# Architecture

This document expands on the architecture section of the README with
module-level detail, data flow diagrams, and the rationale behind the
key design decisions. The authoritative specification of the security
invariants is in
[`../papers/two-primitives-for-agent-security-meshes.md`](../papers/two-primitives-for-agent-security-meshes.md).
This document explains the code, not the security claims.

## Module map

```
src/tessera/
├── __init__.py         public API surface
├── a2a.py              A2A security carriage and verification helpers
├── labels.py           TrustLabel + HMAC-SHA256 primitives
├── signing.py          LabelSigner protocol, JWT-SVID and HMAC implementations
├── context.py          LabeledSegment, Context, Spotlighting renderer
├── delegation.py       signed user-to-agent delegation tokens
├── provenance.py       signed prompt provenance envelopes and manifests
├── identity.py         workload identity tokens, proof-of-possession, replay protection
├── mtls.py             SPIFFE-aware transport identity from ASGI TLS and XFCC
├── spire.py            live SPIRE Workload API adapters for SVIDs and trust bundles
├── policy.py           taint-tracking policy engine with delegation constraints
├── policy_backends.py  external deny-only policy backends (OPA, Cedar)
├── quarantine.py       QuarantinedExecutor, strict_worker, WorkerReport
├── mcp.py              MCPInterceptor auto-labeling tool outputs
├── registry.py         org-level external-tool registry
├── events.py           SecurityEvent with pluggable sinks and evidence buffering
├── evidence.py         signed evidence bundles for audit export
├── telemetry.py        optional OpenTelemetry instrumentation
├── proxy.py            FastAPI reference proxy (chat, A2A, discovery)
├── redaction.py        SecretRegistry for credential isolation at the proxy
├── control_plane.py    reference control plane for policy and registry distribution
└── cli.py              `tessera serve` entrypoint
```

## Module responsibilities

### `labels.py`

Defines `TrustLabel`, the `Origin` enum (USER, SYSTEM, TOOL, MEMORY, WEB),
and the `TrustLevel` int enum (UNTRUSTED=0, TOOL=50, USER=100, SYSTEM=200).
Provides the HMAC-SHA256 `sign_label` and `verify_label` functions that
bind a label to content via a canonical serialization.

Why HMAC is still here when `signing.py` exists: `labels.py` is the core
primitive, pure Python standard library, no external dependencies. It
must be importable even when PyJWT is not installed. `signing.py` builds
on `labels.py` for HMAC and adds JWT.

### `signing.py`

Introduces the `LabelSigner` and `LabelVerifier` protocols. Provides
`HMACSigner`/`HMACVerifier` (thin wrappers over `labels.py` primitives)
and `JWTSigner`/`JWTVerifier`/`JWKSVerifier` (asymmetric signing via
PyJWT). Depends on PyJWT only when the JWT path is used; raises
`SigningNotAvailable` at construction if PyJWT is missing.

The JWT verifiers carry a 30-second clock-skew `leeway` by default. This
is not optional paranoia, SPIRE mints short-lived SVIDs and NTP drift
between workloads produces flakes without leeway.

### `context.py`

Defines `LabeledSegment` (content + label) and `Context` (ordered list of
segments). The `Context` class exposes:

- `min_trust`: the taint ceiling, used by the policy engine
- `max_trust`: rarely useful, mostly for debugging
- `principal`: the first USER segment's principal, used for attributing
  security events without threading principal through every call site
- `render()`: assembles segments for the LLM, wrapping any segment below
  `TrustLevel.TOOL` in `<<<TESSERA-UNTRUSTED>>>` delimiters (Spotlighting)

`make_segment()` accepts either an HMAC key (bytes) or a `LabelSigner`,
with exactly-one validation. This is the unified API that lets HMAC and
JWT signing flow through the same happy path.

### `delegation.py`

Defines `DelegationToken` plus symmetric signing and verification for
bounded user-to-agent authority. The token binds subject, delegate,
audience, authorized actions, constraints, session identifier, and
expiry to a deterministic canonical serialization.

This is intentionally a small primitive. It gives the policy and proxy
surfaces something portable and fail-closed to consume before a richer
OAuth or proof-of-possession profile lands.

### `provenance.py`

Defines `ContextSegmentEnvelope` and `PromptProvenanceManifest`, the
content-bound provenance structures used to carry signed prompt
lineage. Envelopes bind one content segment to origin, issuer, trust
level, and optional lineage metadata. Manifests bind ordered prompt
assembly across multiple envelopes.

These are stronger than simple spotlighting markers because signatures
cover both metadata and the exact content digests the proxy and A2A
surfaces rely on.

### `identity.py`

Workload identity and proof-of-possession for inbound agent traffic.
Defines `AgentIdentity` (a JWT with a SPIFFE subject and optional
`cnf.jkt` proof key binding), `AgentProofVerifier` (validates a
DPoP-style proof JWT binding the credential to one HTTP request), and
`AgentProofReplayCache` (thread-safe `jti` replay detection with
configurable window).

Supports HS256 (symmetric, single-process) and RS256/ES256 (asymmetric,
multi-workload) verification. The proof verifier is strict: method, URI,
and access token hash must all match. Replay protection uses a bounded
time window rather than an unbounded set.

### `mtls.py`

Validates caller identity from the transport session rather than from
application tokens. Two sources are supported:

- The ASGI TLS extension, when the server exposes a verified client
  certificate chain in the request scope. SPIFFE URIs are extracted from
  the SAN extension.
- Envoy-style `X-Forwarded-Client-Cert` headers, but only when the
  request arrived from an explicitly trusted proxy host.

The module refuses to trust XFCC headers unless the immediate peer is
on the `trusted_proxy_hosts` allowlist, and optionally pins acceptable
SPIFFE trust domains.

### `spire.py`

Adapters for the SPIRE Workload API. Keeps SPIRE-specific plumbing out
of the core modules. Supports two runtime capabilities:

1. Fetch a live JWT-SVID for outbound `ASM-Agent-Identity` carriage.
2. Fetch JWT bundles and expose them as a JWKS-backed verifier for
   inbound identity checks.

Uses duck typing so it works with both the modern `spiffe` Python
package and the older `pyspiffe.workloadapi` API. Intentionally
defensive: malformed SVIDs or bundle responses raise
`SpireProtocolError` rather than silently degrading.

### `policy.py`

The taint-tracking engine. Per-tool trust requirements are declared
statically via `Policy.require(tool, level)`. `Policy.evaluate(ctx, tool)`
returns a `Decision` (allow or deny) based on:

```
allow iff required_trust(tool) <= ctx.min_trust
```

Denies emit a `SecurityEvent` through the event sink system before
returning. Allows do not. The `emit_decision` call also fires an OTel
span with the decision attributes when telemetry is enabled.

Delegation constraints are enforced here too. The policy layer now
consumes bounded delegated authority, including per-tool authorization,
delegate binding, per-action cost caps, delegated human-approval
requirements, and delegated domain allowlists for common network
destination arguments.

### `policy_backends.py`

External deny-only policy backends that compose with the local taint
floor. The local trust check and delegation checks remain authoritative.
External backends (OPA, Cedar, or any HTTP policy endpoint) can only add
denies after the local checks have already allowed. This preserves the
taint floor invariant while enabling attribute-based policy decisions
that are too organization-specific for the local engine.

`PolicySegmentSummary` sends content hashes and metadata to the backend,
never raw prompt content. This is a deliberate privacy boundary: the
external policy engine evaluates policy over metadata, not over the
text the agent saw. Backend failures fail closed by default.

### `quarantine.py`

The dual-LLM executor. `QuarantinedExecutor.run(ctx)` splits the context
by trust level, invokes the Worker on the untrusted partition, validates
the Worker's output against a Pydantic schema via `strict_worker`, and
then invokes the Planner on the trusted partition plus the validated
report.

`WorkerReport` is the default schema. It contains no free-form string
fields. This is intentional and load-bearing for the security claim. See
the docstring on `WorkerReport` for the rationale.

`strict_worker(schema, inner)` wraps a raw callable with Pydantic
validation. Invalid outputs raise `WorkerSchemaViolation` and emit a
security event. The Planner is never invoked if validation fails.

### `a2a.py`

Defines `A2APromptSegment`, `A2ASecurityContext`, and `A2ATaskRequest`
for carrying Tessera delegation and provenance metadata across
agent-to-agent task payloads. The helpers parse and verify signed
delegation and prompt provenance fail-closed before a task is treated
as trusted input.

This is not a full A2A transport implementation. It is the security
carriage layer that the proxy and any future data-plane component can
reuse.

### `mcp.py`

Wraps an MCP `ClientSession` (or any object satisfying the `MCPClient`
protocol) and auto-labels tool outputs. Tools listed in `external_tools`
or flagged by the registry are labeled `Origin.WEB` at
`TrustLevel.UNTRUSTED`. Everything else is labeled `Origin.TOOL` at
`TrustLevel.TOOL`.

`_default_extract` handles the various shapes MCP tool results come in,
with special handling for binary content: image and audio results are
replaced with `[binary content: mime=..., bytes=N]` markers rather than
passed through as base64. This prevents both token-budget blowup and
data smuggling through the model's vision inputs.

### `registry.py`

Org-level `ToolRegistry` for classifying which MCP tools are external
fetchers. The registry's external tool set is the union of the org-level
declaration and any per-agent additions. Agents can ADD to the set but
cannot REMOVE from it. This prevents the "agent forgot to mark
`fetch_url` as external" footgun.

### `events.py`

`SecurityEvent` is a structured record with kind, principal, detail,
and timestamp. The `register_sink` / `emit` API fans events out to any
number of sinks. Built-in sinks:

- `stdout_sink`: JSON lines to stdout, for log collectors
- `otel_log_sink`: attaches to the current OTel span as a span event
- `webhook_sink(url)`: factory returning a sink that POSTs to a SIEM

Sink exceptions are swallowed so a broken observability path cannot
take down the security path.

### `evidence.py`

Signed evidence bundles for audit and incident workflows. An
`EvidenceBundle` packages a set of security events into a portable
structure with schema version, event counts, per-kind tallies, and
optional dropped-event accounting. Bundles can be HMAC-signed or
JWT-signed for tamper evidence.

The Rust gateway implements the same bundle schema, so Python and Rust
components produce interoperable evidence artifacts.

### `telemetry.py`

Optional OpenTelemetry instrumentation. Every function is a no-op if
OTel is not installed. When it is installed, the module emits spans for:

- `tessera.proxy.request` (parent span for one proxy request)
- `tessera.proxy.upstream` (child, around the upstream LLM API call)
- `tessera.policy.evaluate` (child, one per proposed tool call)
- `tessera.mcp.tool_call` (child, one per MCP call)
- `tessera.quarantine.run` (parent span for a dual-LLM execution)
- `tessera.quarantine.worker` (child, around the Worker LLM call)
- `tessera.quarantine.planner` (child, around the Planner LLM call)

Child spans nest automatically via OTel's context propagation.

### `proxy.py`

FastAPI reference proxy that exposes:

- OpenAI-compatible `/v1/chat/completions`
- discovery at `/.well-known/agent.json`
- A2A JSON-RPC ingress at `/a2a/jsonrpc` when an A2A handler is wired

The proxy verifies every incoming label, prompt provenance header, and
delegation header, binds delegated authority to the local `agent_id`,
builds a `Context`, forwards to the configured upstream LLM, and gates
proposed tool calls through the policy engine. For A2A ingress, it
requires verified `tessera_security_context` metadata, rebuilds a policy
context from the verified envelopes, and evaluates the task intent
before calling the handler.

When a `SecretRegistry` (see `redaction.py`) is configured, the proxy
also redacts registered secrets on both directions: outbound messages
are scrubbed before the upstream LLM sees them, and inbound responses
are walked with `redact_nested` before being handed back to the caller.
A `SECRET_REDACTED` security event fires whenever a hit occurs, so
incident response sees the near-miss.

This module is still meant to be treated as a specification, not a
production artifact. Production deployments should port the primitives
into a Rust data-plane proxy such as agentgateway.

### `redaction.py`

Credential isolation at the proxy boundary. `SecretRegistry` holds a
set of named secrets that must never cross the proxy boundary.
`registry.redact(text)` replaces every registered value with a
`<REDACTED:NAME>` marker. `redact_nested(obj, registry)` walks a JSON
shaped payload and rewrites string leaves in place. The registry
refuses to register secrets shorter than 8 characters to avoid
false-positive matches on benign substrings.

The pattern is the GitHub Agent Workflow Firewall approach: the proxy
holds the real credentials, and any attempt to move them into an LLM
prompt or back out through an LLM response is rewritten to the opaque
marker. This is defense-in-depth for agents that still hold real
credentials in process; the right long-term answer is to give the
agent process placeholder tokens and substitute on egress to
downstream services.

### `control_plane.py`

Reference control plane for signed policy and registry distribution.
Exposes FastAPI endpoints that agents poll for policy bundles, tool
registries, and OPA configuration. Documents are content-addressed
(SHA-256 revision hashes), ETag-gated, and optionally JWT-signed so
agents can verify that the policy they received came from the
control plane and was not modified in transit.

Includes heartbeat ingress with workload identity verification, so
the control plane knows which agents are alive and authenticated.

This module exists because the primitives need a reference integration
surface, not because Tessera is building a production control plane.
Production deployments should use an existing control plane (Istiod,
agentgateway's management API, Microsoft AGT) and adapt the Tessera
distribution format to it.

### `cli.py`

Minimal `tessera serve` command that wires the proxy to an OpenAI
upstream using environment variables. Not load-bearing, mostly for
demo convenience.

## Data flow: one chat proxy request

```
HTTP POST /v1/chat/completions
         |
         v
+--------------------+
| proxy.chat_...     |
| wraps in           |
| proxy_request_span |
+---------+----------+
          |
          v
+--------------------+
| verify every label |  401 on first failure
| build Context      |
+---------+----------+
          |
          v
+--------------------+
| call upstream LLM  |  wrapped in upstream_span
+---------+----------+
          |
          v
+--------------------+
| extract proposed   |
| tool calls         |
+---------+----------+
          |
          v
+--------------------+
| policy.evaluate()  |  one per tool call
| taint tracking     |  emits policy span + SecurityEvent on deny
+---------+----------+
          |
          v
+--------------------+
| return response    |
| with tessera field |
| listing allow/deny |
+--------------------+
```

## Data flow: A2A ingress

```text
HTTP POST /a2a/jsonrpc (tasks.send)
         |
         v
+----------------------------+
| validate JSON-RPC envelope |
+-------------+--------------+
              |
              v
+----------------------------+
| extract and verify         |
| tessera_security_context   |
| - delegation               |
| - prompt provenance        |
+-------------+--------------+
              |
              v
+----------------------------+
| rebuild Context from       |
| verified prompt segments   |
+-------------+--------------+
              |
              v
+----------------------------+
| policy.evaluate(intent)    |
| against verified context   |
+------+------+--------------+
       |      |
    deny      allow
       |      |
       v      v
  JSON-RPC  call configured
   error    A2A handler
```

## Data flow: dual-LLM quarantine

```
full Context (trusted + untrusted)
         |
         v
+--------------------+
| split_by_trust()   |
+----+---------+-----+
     |         |
     |         |
trusted    untrusted
     |         |
     |         v
     |  +--------------------+
     |  | quarantine_worker  |
     |  | span               |
     |  +---------+----------+
     |            |
     |            v
     |  +--------------------+
     |  | WORKER LLM call    |  no tool access
     |  +---------+----------+
     |            |
     |            v
     |  +--------------------+
     |  | strict_worker      |
     |  | Pydantic validate  |
     |  +----+----------+----+
     |       |          |
     |    valid     invalid
     |       |          |
     |       |          v
     |       |    SecurityEvent
     |       |    WORKER_SCHEMA_VIOLATION
     |       |          |
     |       |          v
     |       |    raise WorkerSchemaViolation
     |       |
     |       v
     |  +--------------------+
     |  | WorkerReport       |
     |  | (schema instance)  |
     |  +---------+----------+
     |            |
     +------------+
                  |
                  v
         +--------------------+
         | quarantine_planner |
         | span               |
         +---------+----------+
                   |
                   v
         +--------------------+
         | PLANNER LLM call   |  has tool access
         | sees: trusted only |
         | + WorkerReport     |
         +--------------------+
```

## Design decisions worth knowing

### Why HMAC is the v0 default and not JWT

HMAC has zero new dependencies (Python standard library only), zero
setup, and zero operational complexity. For single-process agent
runtimes it is the right choice. JWT is the right choice for multi-
workload deployments, but we did not want to force PyJWT and cryptography
on every user for the common case.

The trade-off is explicit: HMAC cannot survive workload compromise.
Anyone with the key can forge any label. The moment you have two
workloads that produce labels, switch to JWT-SVID.

### Why `Context.principal` returns "first USER segment" instead of a set

Multi-principal contexts are not a supported use case yet. If a single
context carries segments from two different users, the mesh is already
in an ambiguous state and needs explicit handling. For the current
release we take the first USER segment's principal and document the
limitation. Multi-principal support is a v0.5+ item.

### Why policy denies emit security events but allows do not

SIEM volume. A busy agent platform does thousands of allowed tool calls
per minute. Emitting one event per call would drown the signal. Denies
are rare and every one matters. Allows are visible via OTel spans if you
want them there.

### Why `strict_worker` fans out the security event before raising

Caller code may wrap the executor in try/except for flow control. If we
emit the event after the raise, a caller that catches the exception to
fall back to a simpler path swallows the security signal along with the
exception. Emitting before the raise guarantees the SIEM sees the
failed attempt regardless of caller behavior.

### Why the MCP interceptor replaces binary content with markers

Two reasons. First, dumping a base64 blob of an image into the context
window wastes tokens (often thousands per image). Second, vision-capable
models process base64-encoded images in the text channel, and an
attacker who gets an MCP tool to return an image can smuggle instructions
into the context via that image. Replacing with a `[binary content: ...]`
marker closes both issues at once.

If a deployment actually wants to pass images to a vision model, it
should do so through a dedicated image tool with its own label and its
own policy, not through a general text-tool extraction path.

### Why the SPIRE reference deployment is docker-compose and not Helm

We wanted something a reader could stand up in five minutes on a
laptop. A Helm chart would be more production-ready but would also
require a Kubernetes cluster and would obscure the SPIFFE concepts
behind a layer of chart values. The docker-compose is explicit about
every component and every config file.

The trade-off is that the compose reference has not been stood up in
CI. See `deployment/spire/STATUS.md` for the caveat.

## Testing philosophy

Tests are the primary specification of the invariants. The prose in the
paper and this document is secondary. If the prose and the tests
disagree, the tests are right and the prose is out of date.

Every security-relevant change must come with a test that pins the
specific invariant the change affects. The test should fail on the old
behavior and pass on the new. This is enforced informally in code review.

The test suite is fast (~6 seconds for 216 tests) and should stay fast.
Slow tests get less love and are more likely to be skipped under time
pressure. If a test is slow because it is doing too much, split it.

## When to update this document

- Adding a new module under `src/tessera/`: add a module responsibility
  entry.
- Changing a core data flow: update the relevant diagram.
- Making a design decision worth remembering: add it to "Design decisions
  worth knowing."
- Renaming a public API: update every mention.

Do not update this document for internal refactors that do not change
observable behavior. This is architecture, not implementation detail.
