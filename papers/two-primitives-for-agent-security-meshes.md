# Two Primitives for Agent Security Meshes

## Trust-Labeled Context and Schema-Enforced Dual-LLM Execution

**Author:** Kenith Philip

**Status:** Draft for discussion with OWASP Agentic AI, IETF WIMSE, and agent
mesh implementers.

**Version:** 0.1, April 2026

**License:** This paper is licensed under CC BY 4.0. The reference
implementation referenced herein is licensed under Apache 2.0.

---

## Abstract

Recent surveys of agent security infrastructure consistently identify two
primitives as "proposed but not implemented in any production system":
trust-label injection at the proxy level (following Microsoft's Spotlighting,
2024), and structurally enforced dual-LLM execution (following Willison,
2023, and CaMeL, 2025). Both are load-bearing for any mesh architecture that
claims to defend against indirect prompt injection, and neither exists in
production open-source form.

This paper presents reference implementations of both, with a narrow threat
model, test-verified invariants, and a proposal for how the primitives slot
into existing agent mesh architectures. The core claims are: (1) signed
trust labels on context segments, combined with taint tracking on the
minimum trust level observed, provide deterministic control-flow guarantees
at the tool-call boundary; (2) schema-enforced dual-LLM execution, where
the worker model is structurally prevented from returning free-form text,
closes the convention-based hole in Willison's dual-LLM pattern at a
fraction of the cost of custom interpreter approaches. Neither primitive
requires model modification, new hardware, or changes to existing mesh
infrastructure.

The reference implementation is open-source and available as a Python
library of approximately 1,500 lines, with approximately 1,200 lines of
test coverage and 65 passing tests validating the stated invariants.

---

## 1. Introduction

Recent comprehensive surveys of agent security infrastructure have mapped
the space with admirable precision. They identify five enforcement layers
(identity, data-plane proxy, observability, policy, runtime sandbox),
catalogue the existing components for each layer (SPIFFE/SPIRE for
identity, Envoy and agentgateway for the proxy, OpenTelemetry for
observability, OPA and Cedar for policy, Firecracker and Tetragon for
sandboxing), and reach a consistent conclusion: the components exist, the
integration layer does not.

We do not dispute this conclusion. We observe a narrower one. Across these
surveys, two specific primitives are flagged as "proposed but not
implemented" or "experimental":

1. **Trust-label injection at the proxy level.** The Spotlighting technique
   (Hines et al., 2024) wraps untrusted content in delimiters so that the
   model can learn to treat it as data. Every survey we have reviewed
   cites Spotlighting as the reference for this defense and then states
   that no production agent mesh implements trust-label injection.

2. **Schema-enforced dual-LLM execution.** The dual-LLM pattern (Willison,
   2023) separates planning from execution across two models so the
   planner never sees untrusted content. CaMeL (Debenedetti et al., 2025)
   strengthens this with a custom interpreter that enforces capability-based
   data flow at a reported 6.6x latency cost. Neither reference
   implementation is available as a composable primitive that drops into
   an existing mesh.

Both primitives are necessary for any claim of defense against indirect
prompt injection. Both can be implemented in approximately 200 lines of
production code each. This paper presents such implementations, with a
deliberately narrow threat model and an honest scoping of what the
primitives guarantee and what they do not.

The reference implementation is a Python library named Tessera. This paper
is not a pitch for the library. The library is an existence proof. The
claims are about the primitives, not about the code.

---

## 2. Threat model

We defend against indirect prompt injection, narrowly defined. Specifically:

- An attacker controls the content of some segment of data that enters an
  LLM agent's context window. Typical vectors include scraped web pages,
  retrieved documents from a RAG index, tool outputs from third-party MCP
  servers, memory entries from previous sessions, and results from
  federated agent-to-agent calls.
- The attacker's goal is to cause the agent to take a privileged action
  that the delegating human user did not authorize. Typical targets
  include exfiltrating credentials, sending email, executing financial
  transactions, modifying persistent state, or pivoting to a broader
  compromise via the agent's tool access.

We do NOT defend against the following, and any reader of this paper
should treat the defense as incomplete with respect to them:

- **Direct prompt injection by the authenticated user.** If the delegating
  user is hostile, no amount of trust-label machinery helps. The primitives
  defend the user from third-party content, not the system from the user.
- **Attacks on the model itself.** Backdoors introduced during training,
  data poisoning of the base model, weight extraction, and adversarial
  examples against the model's weights are out of scope.
- **Network-layer compromise of tool servers.** If an attacker compromises
  the underlying MCP server, the tool output is attacker-controlled from
  the start. Our labels can correctly classify that output as untrusted
  only if the mesh operator has declared the tool as an external fetcher.
- **Supply-chain attacks on agent software artifacts.** Compromised model
  weights, compromised system prompts, compromised tool manifests, and
  compromised mesh software itself are out of scope. SLSA-based provenance
  verification belongs in a different layer of the mesh.
- **Attacks on code the agent generates.** If the agent writes and
  executes code, the code must be sandboxed (Firecracker, gVisor, or
  equivalent). Our primitives do not replace sandboxing.
- **Semantic attacks on the agent's output.** If the agent's natural
  language response to the user is the final artifact, an attacker who
  poisoned the context can still poison the response. Our defense is at
  the tool-call boundary, not at the generation boundary.

This threat model is narrow by design. Within this scope, we claim that
the two primitives described below are sufficient to provide deterministic
control-flow guarantees at the tool-call boundary. Guarantees on the
actual semantics of what an LLM decides remain outside the reach of any
defense mechanism that does not modify the model, and we do not claim
them.

---

## 3. Primitive 1: Signed Trust Labels on Context Segments

### 3.1 Data structure

Every chunk of text that enters an agent's context window carries an
unforgeable provenance label. The label has the following structure:

```
TrustLabel(
    origin:       {USER, SYSTEM, TOOL, MEMORY, WEB},
    principal:    identity string (e.g. "alice" or "spiffe://example.org/retrieval"),
    trust_level:  ordered integer in {UNTRUSTED=0, TOOL=50, USER=100, SYSTEM=200},
    nonce:        128-bit random value,
    signature:    cryptographic signature over origin | principal | trust_level | nonce | sha256(content)
)
```

The signature binds the label to the exact bytes of the content. Tampering
with the content or any metadata field invalidates the signature. Two
signing modes are supported and are interchangeable at the API level
through a `LabelSigner` protocol:

(a) **HMAC-SHA256 with a symmetric key.** Appropriate for single-workload
    deployments where all segments are produced and verified in the same
    process or by workloads that can share a key. This is the default for
    local development and for single-process agent runtimes.

(b) **JWT-SVID with asymmetric keys.** The signing workload holds a JWT
    Verifiable Identity Document minted by SPIRE. The label's signature
    field carries a compact JWS over the canonical claims set. Downstream
    verifiers resolve the public key via a JWKS fetched from the trust
    domain bundle endpoint. This is the deployment mode for multi-workload
    meshes, and it is the only mode that survives compromise of any single
    workload without allowing label forgery across the rest of the mesh.

The JWT verifier applies a default clock-skew tolerance of 30 seconds to
the `nbf` and `exp` claims. SPIRE mints short-lived SVIDs (5 minutes by
default), and zero leeway produces flakes under normal NTP drift.

### 3.2 The core invariant

A tool call may execute only if every segment of context that could have
influenced the decision has a trust level at or above the tool's required
level. Formally:

```
allow(tool, ctx) iff required_trust(tool) <= min_{s in ctx.segments} s.trust_level
```

The taint-tracking primitive is the use of `min`, not `max`. A single
segment with `trust_level = 0` drags the entire context to 0, regardless
of how many high-trust segments are also present. This is indirect prompt
injection defense by construction: if an attacker-controlled web page is
present in the context, the agent cannot be manipulated via that page into
triggering a tool call that requires user-level authorization, because the
`min_trust` of the context has already been pulled to the floor.

This differs from attribute-based policy engines like Cedar and OPA, which
operate on static attributes of the principal and action. Those engines
are richer for expressing rules. They do not natively model data-flow
taint. The two approaches are complementary: evaluate taint first, then
evaluate attribute-based rules over the surviving set.

Figure 1 illustrates the flow. A user ask, a scraped web page, and a
vetted tool output all enter the context, each carrying a signed label.
The context reports `min_trust = 0` because the scraped page pulls the
floor down. A policy evaluation for `send_email` (which requires USER
trust, or 100) produces a deterministic DENY, regardless of any textual
content in the scraped page that tries to impersonate a user
instruction.

```
Figure 1: Primitive 1, taint tracking at the tool-call boundary.

   USER ask             WEB page              TOOL output
   (trust=100)          (trust=0)             (trust=50)
       |                    |                     |
       v                    v                     v
   +-------+            +-------+             +-------+
   | label |            | label |             | label |
   |  sig  |            |  sig  |             |  sig  |
   +---+---+            +---+---+             +---+---+
       |                    |                     |
       +--------------------+---------------------+
                            |
                            v
                 +---------------------+
                 |      Context        |
                 |                     |
                 |  min_trust = 0      |
                 |  (WEB segment       |
                 |   dominates)        |
                 +----------+----------+
                            |
                            v
                 +---------------------+
                 |   Policy engine     |
                 |  taint tracking     |
                 +----------+----------+
                            |
                            v
       tool = send_email, required_trust = 100 (USER)
                observed_trust       = 0   (UNTRUSTED)
                          ||
                          vv
                  +---------------+
                  |     DENY      |
                  | SecurityEvent |
                  +---------------+
```

The DENY is a deterministic function of `(tool, required_trust,
min_trust(ctx))`. It does not depend on what the LLM was instructed to
do, what the web page said, or which model provider is in use. The
invariant holds regardless of the model's probabilistic behavior
because the check happens outside the model.

### 3.3 Tool-call evaluation

The policy engine evaluates every proposed tool call against the current
context. Tools declare a minimum required trust level. Deny-by-default is
the operating mode: tools without an explicit declaration inherit a
default required trust of USER.

Both decisions are deterministic. Both are testable without invoking an
LLM. Both can be audited offline from a recorded context and tool set.

### 3.4 Spotlighting delimiters as defense-in-depth

Untrusted segments are additionally wrapped in visible delimiters when the
context is rendered for the model:

```
<<<TESSERA-UNTRUSTED>>> origin=web
{content}
<<<END-TESSERA-UNTRUSTED>>>
```

This is the Spotlighting datamarking defense from Hines et al. (2024),
which reduces indirect prompt injection success empirically in their
measurements. We emphasize that the delimiters are defense-in-depth, not
load-bearing. The enforcement happens in deterministic code at the
tool-call boundary. If the model ignores the delimiters entirely, the
taint-tracking invariant still holds. The delimiters exist only so the
model has structural information it may choose to respect.

### 3.5 What this does not defend against

This invariant does not prevent an attacker from influencing the LLM's
*output* via the untrusted segment. It only prevents that output from
triggering a privileged tool call. If the agent's output is itself the
final artifact (a summary returned to the user), the attacker may still
poison that output. The defense is at the tool boundary, not at the
generation boundary.

This is an important clarification. Many readers of survey literature come
away with the impression that indirect prompt injection is "prevented" by
trust labels. It is not. What is prevented is the escalation from "attacker
influenced the model's output" to "attacker caused a privileged action."
The former is a reputational and informational harm; the latter is an
operational and financial harm. The primitive addresses the second class.

### 3.6 Test-verified invariants

The reference implementation validates the stated invariant through the
following tests (all passing at the time of writing):

- `test_web_content_taints_context_and_blocks_sensitive_tool`: a context
  containing a USER segment and a WEB segment, asked to evaluate
  `send_email` (required trust USER), returns DENY with
  `observed_trust=0`.
- `test_proxy_denies_send_email_when_web_content_is_present`: the same
  invariant, enforced at the proxy level with a stub upstream LLM that
  always proposes the tool call.
- `test_proxy_rejects_tampered_signature`: a request whose label
  signature does not match the content returns HTTP 401 at the proxy,
  before policy evaluation.
- `test_real_mcp_image_content_does_not_leak_base64`: a real MCP tool
  returning an `ImageContent` object does not have its base64 data field
  passed through as text. Binary content is replaced with a structured
  marker. This closes a vision-channel smuggling path that naive
  implementations leave open.

---

## 4. Primitive 2: Schema-Enforced Dual-LLM Execution

### 4.1 Background

Willison's 2023 dual-LLM pattern proposes splitting agent execution into
two models:

1. A **Planner** that sees the user's instructions, the system prompt, and
   the tool set. The Planner emits the plan, including which tool calls
   to make and with what arguments.
2. A **Worker** that sees untrusted content and returns extracted data.
   The Worker has no tool access.

The Planner never sees the untrusted content directly. The Worker cannot
trigger tool calls because it does not have access to them. Therefore, the
argument goes, the Worker cannot be manipulated into triggering a tool
call (it cannot trigger anything), and the Planner cannot be manipulated
via untrusted content (it cannot see it).

This pattern is sound as stated. It has a subtle, previously unaddressed
hole: the Worker's output flows back to the Planner as text, and the
Planner reads that text. If the Worker's output is free-form prose, a
compromised Worker model (one that fell for the injection in the untrusted
content) can embed instructions in its prose that the Planner then reads
as part of its context. The injection channel is merely relocated from the
raw untrusted content to the Worker's output.

CaMeL (Debenedetti et al., 2025) addresses this by running the Planner's
output through a custom interpreter that enforces capability-based data
flow, providing strong guarantees at a reported 6.6x latency cost. That
approach is valid and well-specified. It is also operationally expensive,
and the custom interpreter is a large piece of novel code that must be
audited and maintained.

### 4.2 The primitive: constrain the Worker's output space

We propose a lighter alternative that does not require a custom
interpreter. The Worker is wrapped with a Pydantic schema validator. The
Worker must return an instance of, or something coercible into, a declared
`BaseModel` subclass. Any output that does not validate against the schema
raises `WorkerSchemaViolation`, and the Planner is never invoked.

Two properties make this a security primitive rather than a data-shape
convention:

**Property 1: The schema contains no free-form string fields.** The
default schema provided by the reference implementation is:

```python
class WorkerReport(BaseModel):
    entities: list[str]
    urls: list[str]
    numbers: dict[str, float]
    flags: dict[str, bool]
```

There is no `summary: str`, no `notes: str`, no `description: str`. If the
Worker attempts to return prose, the validator fails and the Planner is
never invoked. A compromised Worker cannot smuggle instructions in
free-form text because the output surface does not contain free-form
text.

This is a deliberate design decision. Earlier versions of the reference
implementation included a `summary: str` field in the default schema. We
removed it, because any free-form string field in the default re-opens
the injection channel the pattern was supposed to close. Users who
genuinely need a summary must define their own schema and document how
the Planner treats that field. The default is safe by default, not
convenient by default.

Figure 2 shows the execution flow. The context is split by trust level
before either model is invoked. The Planner sees only trusted segments
and a validated `WorkerReport`. The Worker sees only untrusted segments
and has zero access to tools. The Worker's output flows through
`strict_worker`, which validates against the Pydantic schema before the
Planner is allowed to run.

```
Figure 2: Primitive 2, schema-enforced dual-LLM execution.

                    Full context
                 (trusted + untrusted)
                          |
                          v
                +---------------------+
                |   split_by_trust    |
                +---------+-----------+
                          |
              +-----------+-----------+
              |                       |
       trusted only            untrusted only
              |                       |
              v                       v
    +-------------------+    +-------------------+
    |    PLANNER LLM    |    |    WORKER LLM     |
    |                   |    |                   |
    |  sees: user ask + |    |  sees: scraped    |
    |  WorkerReport     |    |  content          |
    |                   |    |                   |
    |  tools: YES       |    |  tools: NO        |
    +-------+-----------+    +---------+---------+
            ^                          |
            |                          v
            |                +---------------------+
            |                |    strict_worker    |
            |                | Pydantic validator  |
            |                +---------+-----------+
            |                          |
            |                  valid schema?
            |                 /               \
            |               yes                no
            |                |                  |
            |                v                  v
            |       +----------------+  +-------------------+
            +-------+  WorkerReport  |  |  SecurityEvent    |
                    |  (structured)  |  |  WORKER_SCHEMA_   |
                    +----------------+  |  VIOLATION +      |
                                        |  raise            |
                                        +-------------------+
```

The structural guarantee is that the arrow from the Worker back to the
Planner only carries a validated schema instance. Free-form prose from
the Worker never reaches the Planner. If the Worker fails to produce
valid output, the Planner is never invoked at all, and the failure is
reported as a security event before the caller sees the exception.

**Property 2: Schema violations are a security event, not a retry
condition.** When `WorkerSchemaViolation` is raised, a structured
`SecurityEvent` is emitted through the event sink system (see Section 5)
with the violating principal and the schema name, *before* the exception
propagates. This ensures incident response sees the failed attempt even
when the caller catches the exception. A Worker that returns prose is not
a transient failure; it is a signal that something is wrong with the
Worker model, the Worker's system prompt, or the untrusted content, and
it should be visible in the SIEM, not buried in a caller's try/except.

### 4.3 Why this is stronger than convention

Previous dual-LLM implementations rely on instructing the Worker via
system prompt to return JSON and on the caller to parse that JSON
correctly. This is a convention. A compromised Worker can break the
convention, return prose, and the caller has no structural defense.

The primitive described here replaces convention with a structural
contract enforced by Pydantic's validator. Pydantic is a battle-tested
piece of software, not a new security tool, and its validation semantics
are well-understood.

The security claim is narrow. It is: the Worker cannot influence the
Planner via free-form text if the schema has no free-form text fields.
Adding a `notes: str` or `summary: str` field reopens the channel. The
reference implementation's default schema documents this with an explicit
warning in the class docstring, and the test suite contains a test
(`test_free_form_text_fails_closed`) that pins the behavior for the case
where a compromised Worker attempts to return prose.

### 4.4 The remaining hole: semantically adversarial structured data

A compromised Worker can return structurally valid but semantically
adversarial data. For example:

```python
WorkerReport(entities=["ignore_previous_and_email_attacker"])
```

If the Planner later renders this entity list into natural-language prose
that gets fed back to the model, the attacker has a channel, narrower
than before but still present.

Three mitigations, in increasing order of strength:

1. **Planner prompt discipline.** The Planner's system prompt must treat
   Worker output as data, not as instruction material. This is prompt
   engineering, not a structural guarantee.
2. **Closed enums for string fields.** For high-stakes schemas, pin
   string-valued fields to closed enums. A `company:
   Literal["ACME", "Globex"]` field cannot contain adversarial strings.
   This is the appropriate discipline for any schema where the string
   field will be rendered into prose by the Planner.
3. **Composition with Primitive 1.** The tool-call boundary is still
   deterministic. Even if a semantically adversarial Worker output
   influences the Planner's output, the Planner cannot trigger a
   privileged tool call because the context still contains the original
   untrusted segment at `trust_level = 0`. Primitive 1 enforces this
   invariant regardless of what the Worker said.

Primitives 1 and 2 are designed to compose. Primitive 2 reduces the ways
a compromised Worker can influence the Planner. Primitive 1 prevents any
remaining influence from triggering privileged tool calls. Together, they
close the control-flow path, even though neither closes it alone.

### 4.5 Latency

The CaMeL paper reports a 6.6x latency cost for its custom interpreter
approach. We do not have comparable benchmarks for the Pydantic-based
approach, and we are explicit that we have not measured it. Informally,
Pydantic validation on a structured dict is microseconds; the dominant
latency contribution is the two LLM calls (Worker and Planner), which are
also present in the CaMeL design. The 6.6x figure in CaMeL includes the
interpreter's data-flow tracking overhead, which this approach does not
perform. We expect, but have not verified, that the latency overhead of
schema-enforced dual-LLM execution over single-LLM execution is
dominated by the extra LLM call rather than by validation.

Future work should include a controlled benchmark comparing the Pydantic
approach against the CaMeL interpreter on the same workload.

---

## 5. Security events as a first-class channel

A brief design note, because we observe that existing surveys conflate
this with observability.

Policy denies and schema violations are incident-response events, not
telemetry traces. They should land in an SIEM, not in a tracing backend.
The distinction matters because:

- Tracing backends optimize for high-volume, low-signal data (every
  request, every span). Security events are low-volume, high-signal
  (one per denied tool call, one per schema violation).
- Tracing backends do not typically feed alerting pipelines, or do so
  poorly. SIEMs do.
- The on-call rotation that responds to a `POLICY_DENY` event is rarely
  the same team that responds to a trace latency regression.

The reference implementation separates these channels. `tessera.telemetry`
emits OTel spans for observability. `tessera.events` emits `SecurityEvent`
records through a pluggable sink system with built-in sinks for stdout
(JSON lines), OTel span events (for inline correlation), and HTTP
webhooks (for SIEM delivery). Sink exceptions are swallowed so a broken
observability path cannot take down the security path.

We do not claim this is novel. We do claim that surveys of the space
should draw the distinction explicitly, because conflating the two leads
to deployments where security events end up in the same backend as
latency histograms and nobody alerts on them.

---

## 6. Composition with existing mesh architectures

These primitives do not replace SPIFFE, OPA, Cedar, Envoy, agentgateway,
Firecracker, Tetragon, or OpenTelemetry. They are narrowly scoped and
designed to slot into any of them.

- **Identity layer.** The `JWTSigner` and `JWKSVerifier` components
  accept SPIFFE JWT-SVIDs as signing keys. A retrieval workload that
  holds a JWT-SVID can mint labeled segments that downstream workloads
  verify via the SPIRE trust bundle. The reference deployment includes
  a SPIRE docker-compose configuration and an example showing the
  end-to-end path from SVID issuance to label verification.
- **Policy layer.** The `Decision` object returned by the taint-tracking
  engine carries `required_trust` and `observed_trust` as first-class
  fields. A Cedar or OPA policy evaluator can be chained after the
  taint-tracking engine for richer attribute-based rules, without losing
  the min-trust guarantee. The composition order matters: evaluate taint
  first (fast, deterministic), then evaluate attribute-based rules over
  the surviving set.
- **Data-plane proxy.** The reference implementation is a FastAPI
  sidecar at approximately 160 lines. Production deployments should
  port the primitives into a Rust data-plane proxy such as agentgateway
  rather than run FastAPI at production scale. The FastAPI
  implementation is a specification, not a production artifact. We
  recommend reading it as pseudocode with imports.
- **Observability.** Every policy decision, MCP tool call, and
  quarantine execution emits OTel spans with provenance attributes.
  Integration with existing OTel collectors and GenAI semantic
  convention processors is straightforward.
- **Sandbox layer.** The primitives are orthogonal to Firecracker, gVisor,
  and Tetragon. A deployment that runs agent code under a sandbox layer
  still benefits from trust labels and schema-enforced dual-LLM execution
  at the layer above. The primitives are application-layer, not
  kernel-layer.

We do not propose a new control plane. The primitives work under any
control plane, from none (single-process) to Istiod-style distributed.

---

## 7. What we do not claim

This paper makes a deliberately narrow set of claims. We do not claim:

- **That these primitives prevent all indirect prompt injection.** They
  prevent privileged tool calls from being triggered by tainted context,
  and they close the free-form-text channel between Worker and Planner.
  They do not prevent the model from saying untrue or harmful things in
  its response to the user.
- **That these primitives constitute a complete agent security
  architecture.** They are two primitives. Any real deployment also
  needs identity, policy, observability, sandboxing, supply-chain
  verification, and credential isolation. The survey literature is
  correct to scope the problem at five layers; this paper addresses
  specific gaps within that scope, not the whole.
- **That Pydantic validation is unforgeable.** If a bug in Pydantic
  allows malformed data to pass validation, the primitive breaks. We
  recommend that deployments running high-stakes schemas pin their
  Pydantic version and track CVEs.
- **Deterministic guarantees on model semantics.** LLMs are probabilistic.
  We provide deterministic guarantees on control flow (a tool call either
  fires or it does not, depending on taint state) and on output schema
  (a Worker either returns a valid schema instance or raises an
  exception). We do not provide guarantees on what the model chooses to
  say.
- **That the primitives are conceptually novel.** They are not.
  Spotlighting, the dual-LLM pattern, and CaMeL's flow tracking predate
  this work. What is novel is the specific implementation that:
  (a) reduces the dual-LLM pattern to a small Pydantic wrapper instead
  of a custom interpreter,
  (b) makes trust labels cryptographically bound to content via HMAC or
  JWT-SVID,
  (c) exposes both as a composable library that can be dropped into any
  agent mesh,
  (d) provides test-verified invariants for the claimed guarantees.

---

## 8. Reference implementation

The reference implementation is Tessera, a Python library available at
<https://github.com/kenithphilip/Tessera>. As of the time of writing:

- **Source:** 1,556 lines of Python across 12 modules.
- **Tests:** 1,187 lines of tests, 65 passing, including integration
  tests against the real `mcp` Python package using in-memory transport.
- **Dependencies:** FastAPI and Pydantic (required), PyJWT with
  cryptography (required for JWT-SVID signing), OpenTelemetry SDK
  (optional for span emission), the `mcp` package (optional for MCP
  interceptor).

Key components:

| Module | Purpose |
|---|---|
| `tessera.labels` | Signed TrustLabel structure, HMAC-SHA256 primitives |
| `tessera.signing` | JWTSigner, JWKSVerifier, HMACSigner, LabelSigner protocol |
| `tessera.context` | LabeledSegment, Context, Spotlighting delimiter rendering |
| `tessera.policy` | Taint-tracking policy engine with per-tool trust requirements |
| `tessera.quarantine` | QuarantinedExecutor, strict_worker, safe-by-default WorkerReport |
| `tessera.mcp` | MCP interceptor auto-labeling tool outputs |
| `tessera.registry` | Org-level external-tool registry, registry-wins-on-inclusion |
| `tessera.events` | Structured SecurityEvent with pluggable sinks |
| `tessera.telemetry` | Optional OTel spans for proxy, MCP, policy, quarantine |
| `tessera.proxy` | FastAPI sidecar reference implementation |

The deployment reference includes a SPIRE server, SPIRE agent, and
example workload configuration demonstrating the JWT-SVID issuance and
verification path.

The test suite is the primary specification of the invariants claimed in
Sections 3 and 4. Readers who want to verify the claims should read the
tests, not the prose.

---

## 9. Standardization asks

We propose three small additions to existing standards work. Each is
scoped to be adoptable without disrupting the broader standards agenda.

1. **An IETF primitive for content-bound provenance labels.** The existing
   drafts in the WIMSE working group (draft-klrc-aiagent-auth,
   draft-ni-wimse-ai-agent-identity) establish agent identity but do not
   address content provenance inside the context window. A short draft
   specifying the TrustLabel structure, its canonical serialization, and
   its HMAC and JWT signing modes would give the agent mesh ecosystem a
   shared format. We are prepared to contribute such a draft if the
   working group is interested.

2. **An extension to MCP SEP-1913.** The existing SEP-1913 proposal adds
   per-item sensitivity and trust hint annotations to MCP tool results.
   We propose adding a `trust_level` field compatible with the structure
   described in Section 3.1. This would allow MCP servers to declare
   their tool outputs' trust level natively, rather than requiring each
   proxy to maintain its own external-tool registry, and it would provide
   an interop path between mesh implementations.

3. **An OWASP Agentic AI Top 10 entry for unconstrained worker output in
   dual-model architectures.** The attack class is documented implicitly
   in the CaMeL paper and in Willison's original post, but it is not
   called out as a named weakness in the current taxonomy. Giving it a
   name (provisional: ASI-DUAL-LLM-BYPASS) would help implementers of
   dual-model architectures recognize and mitigate the specific failure
   mode this paper addresses.

---

## 10. Related work

**Spotlighting** (Hines et al., 2024, Microsoft Research) introduces
datamarking of untrusted content in LLM contexts, with measurements
showing a significant reduction in indirect prompt injection success.
Our Primitive 1 implements Spotlighting delimiters as defense-in-depth,
layered on top of deterministic taint tracking at the tool-call boundary.

**Dual-LLM pattern** (Willison, 2023) proposes the architectural
separation of planner and worker models to prevent untrusted content
from reaching the model that emits tool calls. Our Primitive 2 is a
direct implementation of the pattern, with the schema-enforcement
addition to close the free-form-text channel.

**CaMeL** (Debenedetti et al., 2025) strengthens the dual-LLM pattern
with a custom interpreter enforcing capability-based data flow. The
reported latency cost is 6.6x. Our approach trades the strength of
interpreter-enforced data flow for the simplicity of Pydantic-enforced
output contracts.

**Design Patterns for Securing LLM Agents against Prompt Injections**
(2025) catalogs architectural patterns and their tradeoffs. Our
contribution is consistent with the pattern catalog.

**OWASP Agentic AI Top 10** (December 2025) enumerates agent-specific
threat categories. The invariants described in this paper address
ASI01 (goal hijacking), ASI02 (memory injection), and portions of
ASI04 (supply chain) and ASI08 (tool abuse).

**SPIFFE and SPIRE** (CNCF graduated) provide the identity substrate
for asymmetric label signing. Our JWT-SVID integration relies on
SPIRE's JWT issuance and JWKS bundle distribution primitives.

**MCP** (Model Context Protocol, Anthropic and Linux Foundation)
provides the protocol substrate for agent-to-tool communication. Our
MCP interceptor wraps the official `mcp` Python package's ClientSession
via a Protocol-based abstraction.

**IETF draft-klrc-aiagent-auth** and **draft-ni-wimse-ai-agent-identity**
(WIMSE working group, 2026) establish the identity layer. Our primitives
are complementary: identity establishes who is acting, trust labels
establish what content that actor is processing and where it came from.

---

## 11. Conclusion

Two primitives, each implementable in approximately 200 lines of
production code, close the two specific holes that recent agent security
surveys identify as unimplemented in production systems. Neither primitive
requires model modification, new hardware, or changes to control-plane
infrastructure. Both have reference implementations with test-verified
invariants and an Apache 2.0 license.

The remaining work is not research. It is standardization (Section 9),
adoption into production mesh data planes (Section 6), and the
accompanying composition with identity, policy, sandboxing, and
supply-chain verification at the other mesh layers. We expect that a
deployment combining these primitives with an existing mesh (agentgateway
or equivalent for the data plane, SPIRE for identity, Cedar or OPA for
attribute-based policy, Firecracker or gVisor for sandboxing, and a
standard OTel pipeline for observability) can provide defensible control-
flow guarantees against indirect prompt injection within six months of
focused integration work.

We are less interested in whether the reference implementation described
in this paper becomes the adopted implementation, and more interested in
whether the primitives themselves become widely understood as the minimum
bar for any agent security mesh that claims to defend against indirect
prompt injection. The survey literature is clear that the primitives are
necessary. This paper shows that they are tractable.

---

## Appendix A: Test names pinning the stated invariants

Readers interested in verifying the claims against the reference
implementation should start with the following tests:

**Primitive 1 (trust labels and taint tracking):**

- `tests/test_policy.py::test_web_content_taints_context_and_blocks_sensitive_tool`
- `tests/test_policy.py::test_user_only_context_allows_sensitive_tool`
- `tests/test_policy.py::test_tool_trust_is_below_user_so_blocks_sensitive_tool`
- `tests/test_proxy.py::test_proxy_denies_send_email_when_web_content_is_present`
- `tests/test_proxy.py::test_proxy_rejects_tampered_signature`
- `tests/test_labels.py::test_tampered_content_fails_verification`
- `tests/test_mcp_integration.py::test_real_mcp_image_content_does_not_leak_base64`

**Primitive 2 (schema-enforced dual-LLM execution):**

- `tests/test_strict_worker.py::test_free_form_text_fails_closed`
- `tests/test_strict_worker.py::test_extra_fields_rejected_by_strict_schema`
- `tests/test_strict_worker.py::test_custom_schema_flows_through_executor`
- `tests/test_quarantine.py::test_planner_only_sees_trusted_segments`
- `tests/test_events.py::test_worker_schema_violation_emits_event`

**SPIFFE JWT-SVID signing:**

- `tests/test_signing.py::test_jwt_round_trip`
- `tests/test_signing.py::test_jwt_tampered_content_rejected`
- `tests/test_signing.py::test_jwks_verifier_resolves_by_kid`
- `tests/test_signer_api.py::test_jwt_signer_via_make_segment_round_trips`

Total passing tests at the time of writing: 65.

---

## Appendix B: What a conformant mesh looks like

For implementers considering adoption of these primitives in a mesh
other than the reference implementation, a conformant deployment must
satisfy the following minimum requirements:

1. Every segment of content entering an agent's context window carries
   a TrustLabel with a cryptographically verifiable signature. Segments
   without valid labels are rejected at the proxy boundary.

2. The effective trust level of a context is `min` over the trust
   levels of its segments. Tool-call authorization uses this effective
   trust level, not any per-segment level in isolation.

3. Tool requirements are declared statically (per tool) or dynamically
   (per request), and unknown tools inherit a deny-by-default required
   trust equivalent to USER.

4. Any dual-LLM execution path constrains the Worker's output to a
   declared schema. Schema violations raise a terminal exception and
   emit a security event before propagating.

5. The default schema provided by the mesh for the dual-LLM path
   contains no free-form string fields. Deployments that need
   free-form output must opt in explicitly and document the risk.

6. Security events emitted by the mesh are structurally distinct from
   telemetry traces and can be routed to an SIEM via a pluggable sink.

7. MCP tool outputs are auto-labeled on ingress, with binary content
   replaced by a structured marker rather than passed through as base64.

Conformance with these requirements does not require using any specific
codebase. It requires only that the deployment can demonstrate, through
tests or audit, that each invariant holds.

---

*This paper is a draft for discussion. Feedback, corrections, and
implementation contributions are welcome. The reference implementation
is available as an open-source Python library. The authors intend to
contribute the TrustLabel format as an IETF draft and the dual-model
bypass category as an OWASP Agentic AI Top 10 entry, subject to
community interest.*
