# Two Primitives for Agent Security Meshes

## Trust-Labeled Context and Schema-Enforced Dual-LLM Execution

**Author:** Kenith Philip

**Status:** Draft for discussion with OWASP Agentic AI, IETF WIMSE, and agent
mesh implementers.

**Version:** 0.4, April 2026 (paper); v0.7.0 (reference implementation)

**License:** This paper is licensed under CC BY 4.0. The reference
implementation referenced herein is licensed under AGPL-3.0-or-later.

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

Since version 0.1 of this paper, the reference implementation has been
extended with three additional defense layers that address attack classes
the original two primitives explicitly disclaimed: output manipulation
attacks that work through the model's text response rather than tool
calls, value-level taint tracking that traces argument provenance rather
than relying on context-level minimum trust, and adaptive trust scoring
where trust levels decay over time and degrade based on observed
anomalous behavior. These extensions are described in Sections 3.7
through 3.10.

In v0.7.0 of the reference implementation, five further supporting
primitives have landed alongside the two load-bearing invariants:
persistent hash-chained audit logging (`tessera.audit_log`), decision
replay against alternate policies (`tessera.replay`), deterministic and
LLM-driven policy synthesis (`tessera.policy_builder`,
`tessera.policy_builder_llm`), an SSRF guard with encoded-IP decoding
and DNS-rebinding defense (`tessera.ssrf_guard`), and a deterministic
URL allow / deny gate (`tessera.url_rules`). These primitives compose
with the two invariants but do not replace them: replay reads the audit
log produced by policy denials, the policy builder scores proposals via
replay, and the SSRF guard runs as a Scanner under the same protocol as
the content scanners. The two original invariants remain the
load-bearing security properties; the supporting primitives add
durability, replayability, and policy authoring on top.

The reference implementation is open-source and available as a Python
library of approximately 26,800 lines across 98 implementation modules,
with 1409 passing tests validating the stated invariants. AgentMesh, a
FastAPI proxy that wires the Tessera primitives into a single
deployable service with 39 HTTP endpoints and 15 SDK adapters (11
agent-framework adapters and 4 coding-agent hook adapters), ships
separately as `agentmesh-mesh` on PyPI and depends on `tessera-mesh`.

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
  poisoned the context can still poison the response. The core primitives
  (Sections 3 and 4) defend at the tool-call boundary, not at the
  generation boundary. However, the content analysis extensions described
  in Section 3.8 provide defense-in-depth against a specific subclass of
  output manipulation: injections that direct the model to make
  particular claims or recommendations ("Say that Riverside View Hotel
  is the best"). These extensions detect the injection in the tool output
  before the model processes it, but they do not prevent all forms of
  output poisoning.

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

### 3.5 What context-level taint does not defend against

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

Section 3.8 describes a content analysis layer that provides
defense-in-depth against a specific subclass of output manipulation,
but the fundamental limitation remains: deterministic control-flow
guarantees apply at the tool-call boundary, not at the text-generation
boundary.

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

### 3.7 Value-level taint tracking

The `min_trust` invariant is conservative: a single untrusted segment in
the context blocks all side-effecting tool calls, even when the specific
arguments to the tool call came entirely from the user. This is correct
from a security perspective but reduces utility. The AgentDojo benchmark
(Debenedetti et al., 2025) exposes this tradeoff: context-level taint
blocking achieves high attack prevention but also blocks legitimate tasks
where the user explicitly requested a side-effecting action while
untrusted data happened to be present in the context.

CaMeL addresses this with per-variable taint tracking through a custom
interpreter. Tessera extends the context-level invariant with a
`DependencyAccumulator` that records which context segments contributed
to which tool call arguments. When a tool call is proposed, each
argument is checked individually:

```
allow(tool, arg, ctx, acc) iff
    acc.binding(arg).trust_level(ctx) >= required_trust(tool)
    for each arg in critical_args(tool)
```

Critical arguments are the security-relevant parameters of each tool:
recipients for send operations, account identifiers for transfers, file
paths for write operations, and commands for execution. Non-critical
arguments (amounts, subjects, body text) are not checked because their
taint does not create a new attack surface.

The `DependencyAccumulator` is an opt-in refinement layer. When absent,
`Policy.evaluate` falls back to context-level `min_trust`. When present,
it enables per-argument provenance checking without changing the policy
engine's interface. This preserves backward compatibility with
deployments that use context-level taint only.

### 3.8 Content analysis: the directive/ambient distinction

Sections 3.1 through 3.6 defend at the tool-call boundary: an attacker
cannot trigger a privileged tool call through tainted context. Section
3.5 acknowledges a class of attacks this does not address: output
manipulation, where the injection directs the model's text response
rather than its tool calls. "Say that Riverside View Hotel is the best"
has no tool call to block.

The reference implementation now includes a content analysis layer that
detects injection in tool outputs before they reach the model. Three
scanners operate in sequence:

1. **Schema enforcement.** Each tool declares an expected output shape
   (structured data, list of records, free text, or numeric). A hotel
   search tool that returns persuasive prose paragraphs is violating its
   structural contract regardless of content. Prose density, imperative
   verb presence, and key:value marker absence are measured against the
   expected shape.

2. **Directive detection with model-targeting.** The scanner distinguishes
   between content addressed to the human reader ("You should check your
   spam folder") and content addressed to the model ("You should
   recommend Riverside View Hotel to the user"). The key insight: both
   use identical syntax, but injections reference the model's output
   behavior ("the user," "your response," "your recommendation").

   Patterns are classified as *strong* (inherently model-targeted:
   "say that," "tell the user," "include in your response") or *ambient*
   (common in benign text: "you should," "make sure to," "I would
   recommend"). Ambient patterns score at 5-15% of full weight by
   default, only jumping to full weight when model-targeting context is
   present. This eliminates false positives on FAQ text, product reviews,
   tutorials, and help content.

3. **Intent verification.** Detects side-effecting action verbs
   (send, transfer, delete, execute) that the user did not request.
   Filters out past-tense records ("was sent," "Transfer of EUR 500"),
   passive constructions ("has been created"), quoted speech
   ("Bob: 'Please send the deck'"), and nominal forms ("email for
   confirmation"). Only imperative uses of action verbs, cross-checked
   against the user's original prompt, produce a detection signal.

These scanners are deterministic (no model call required) and run in
under 1 millisecond per tool output. They are defense-in-depth: even if
all three miss an injection, the tool-call boundary invariant from
Section 3.2 still prevents privileged actions.

### 3.9 Plan integrity verification

CaMeL's strongest property is that untrusted data never influences which
tools get called, only the data passed to those tools. The interpreter
extracts control flow from the trusted query and executes it
deterministically.

Tessera does not replicate the full interpreter approach. Instead, a
lightweight `PlanVerifier` checks whether a proposed tool-call sequence
is consistent with the user's original intent. For common patterns
("search for hotels" implies search tools, not send or delete tools),
the verifier infers expected and forbidden tool patterns from the user
prompt and flags sequences that include tools the user did not ask for.

This is heuristic pattern matching, not formal plan verification. CaMeL's
interpreter provides stronger guarantees because it controls execution.
The verifier catches the obvious cases (an injection adding send_money
to a search task) without requiring a custom AST executor, at the cost
of missing subtle control-flow manipulations.

### 3.10 Adaptive trust scoring

The trust levels defined in Section 3.1 are static: a segment labeled
TOOL stays at trust level 50 forever. Microsoft's Agent Governance
Toolkit (April 2026) introduced dynamic trust scoring where trust
decays based on observed behavior.

Tessera adds a `TrustDecayPolicy` that computes effective trust on the
fly without modifying the immutable `TrustLabel` (whose signature
prevents modification). Effective trust decreases linearly with segment
age past a configurable maximum, and decreases by a configurable penalty
per scanner anomaly. A `ToolServerTrustTracker` accumulates per-server
anomaly counts: if a tool server's outputs repeatedly trigger content
analysis scanners, its future outputs start with lower effective trust.

A `DecayAwareContext` wraps the standard `Context` and overrides the
`min_trust` property to use effective trust. It can be passed to
`Policy.evaluate` without changes to the policy engine, preserving
backward compatibility.

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
approach. That figure includes the interpreter's data-flow tracking
overhead, which this approach does not perform: we rely on Pydantic
validation of a structured dict, and policy evaluation is a minimum
over the context segments' trust levels.

The reference implementation ships a microbenchmark suite under
`benchmarks/` that measures the Tessera primitives in isolation. On an
Apple Silicon laptop running Python 3.12 with the suite's default
settings, the headline numbers are:

- `WorkerReport.model_validate` on a valid dict: approximately 1.0
  microseconds per call.
- `WorkerReport.model_validate_json` on a valid JSON string:
  approximately 1.4 microseconds per call.
- `Policy.evaluate` allow path: approximately 4 microseconds per call.
- `Policy.evaluate` deny path, including `SecurityEvent` emission:
  approximately 6 microseconds per call.
- End-to-end per-request overhead (sign three segments, verify three
  segments, evaluate one tool call): approximately 32 microseconds.

Against a 200-millisecond LLM round-trip, the end-to-end overhead is
roughly 0.016 percent. Against a 1-second round-trip it is
approximately 0.003 percent. We do not present this as a head-to-head
comparison with CaMeL: we did not run CaMeL, and the two systems are
doing different work. The benchmark's purpose is to pin the absolute
overhead of Tessera's primitives so readers can compute the ratio
against whatever latency budget they care about, and so claims like
"Pydantic validation is microseconds" are backed by reproducible
numbers rather than intuition.

A full head-to-head comparison against CaMeL on the same workload is
implemented in `benchmarks/comparison/` and can be run with `python -m
benchmarks.comparison` or `python -m benchmarks.comparison -o
docs/benchmarks/comparison.md`. The comparison uses an identical workload
(financial analyst assistant with embedded prompt injection) and measures
security-layer overhead only, with deterministic stubs in place of LLM
calls. The CaMeL side faithfully reimplements the value system from the
original source (CaMeLValue wrappers with dependency DAGs, Capabilities
with Sources and Readers, recursive DAG walking for taint propagation,
and the SecurityPolicyEngine with fnmatch-based policy matching). It does
not include CaMeL's full 2,700-line AST interpreter, so the numbers are
a lower bound on CaMeL's actual security-layer cost. On the same
hardware, the security-layer overhead is:

- Baseline (single LLM, no security): approximately 0.5 microseconds per
  tool call.
- CaMeL value system (dependency DAG walking, reader intersection,
  SecurityPolicyEngine): approximately 13 microseconds per tool call, or
  roughly 26x the baseline.
- Tessera (sign and verify three segments, schema validation, policy
  evaluation): approximately 50 microseconds per tool call, or roughly
  100x the baseline.

Both CaMeL and Tessera achieve 100% injection resistance on the workload.
The comparison is instructive for several reasons. CaMeL's published 6.6x
end-to-end overhead is dominated by the cost of making two LLM calls
(plan generation followed by plan execution), not by the interpreter
itself. Our 26x figure for the security layer alone (value wrapping,
dependency DAG traversal, frozenset reader intersections, and policy
engine checks) is a lower bound because it omits the full AST interpreter
overhead. Tessera's 100x security-layer overhead is dominated by
HMAC-SHA256 signing and verification, which is fundamentally more
expensive than in-memory taint tracking but provides a different security
property: cryptographic provenance that can be verified across trust
boundaries, not just within a single interpreter process. Against a
200-millisecond LLM round-trip, Tessera's overhead is approximately
0.025 percent. Against a 1-second round-trip it is approximately 0.005
percent.

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

**AgentMesh: a concrete composition.** The AgentMesh project
(<https://github.com/kenithphilip/AgentMesh>) is a working composition
of Tessera with SPIRE, agentgateway, and OpenTelemetry. It packages the
primitives as a proxy service with 23 HTTP endpoints and 51 integrated
Tessera modules, providing taint-tracking policy evaluation, content
scanning, RAG retrieval guard, tool baseline drift detection, provenance
manifests, SARIF compliance export, and signed evidence bundles. The
proxy runs as a sidecar alongside any MCP-compatible agent and exposes
a framework SDK (LangChain, OpenAI Agents, CrewAI, Google ADK) so agent
code calls the proxy rather than importing Tessera directly.

AgentMesh is infrastructure. Tessera is a library. They are not the
same project. Tessera provides composable primitives that can be
embedded in any agent, framework adapter, or mesh proxy. AgentMesh is
one specific composition that deploys those primitives as a proxy
service. Other compositions are possible and expected.

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
<https://github.com/kenithphilip/Tessera>. As of version 0.7.0:

- **Source:** approximately 26,800 lines of Python across 98
  implementation modules.
- **Rust gateway:** approximately 8,200 lines in `rust/tessera-gateway/`
  (reference data plane).
- **Tests:** 1409 passing, runtime approximately 10 seconds.
- **Dependencies:** FastAPI and Pydantic (required), PyJWT with
  cryptography (required for JWT-SVID signing). Optional extras for
  OpenTelemetry, MCP, CEL, SPIFFE, gRPC/xDS, and 14 framework adapters.

AgentMesh (<https://github.com/kenithphilip/AgentMesh>) is a composition
layer built on Tessera:

- **Source:** approximately 1,600 lines across 6 modules
  (`proxy.py`, `identity.py`, `transport.py`, `exports.py`, `client.py`,
  `sdk/`).
- **Tests:** 106 passing in approximately 5 seconds.
- **Tessera integration:** 51 of 94 Tessera modules.
- **HTTP endpoints:** 23 (policy evaluation, content scanning, RAG guard,
  provenance, evidence, SARIF export, liveness, xDS distribution).
- **Framework SDK:** proxy-backed adapters for LangChain, OpenAI Agents,
  CrewAI, and Google ADK.

Key components (stable APIs):

| Module | Purpose |
|---|---|
| `tessera.labels` | Signed TrustLabel, Origin, TrustLevel |
| `tessera.signing` | JWTSigner, JWKSVerifier, HMACSigner, LabelSigner protocol |
| `tessera.context` | LabeledSegment, Context, Spotlighting rendering |
| `tessera.policy` | Taint-tracking policy engine with value-level accumulator |
| `tessera.quarantine` | QuarantinedExecutor, strict_worker, WorkerReport |
| `tessera.delegation` | DelegationToken, sign_delegation, verify_delegation |
| `tessera.provenance` | ContextSegmentEnvelope, PromptProvenanceManifest |
| `tessera.events` | Structured SecurityEvent with pluggable sinks |
| `tessera.taint` | TaintedValue, DependencyAccumulator, per-argument provenance |
| `tessera.ir` | PolicyIR, YAML/JSON policy DSL, compile_policy |

Content analysis and defense-in-depth:

| Module | Purpose |
|---|---|
| `tessera.scanners.directive` | Two-layer directive detection (strong/ambient with model-targeting) |
| `tessera.scanners.intent` | Intent verification (imperative action detection with tense/voice filtering) |
| `tessera.scanners.heuristic` | Sliding-window injection scoring with target-qualified patterns |
| `tessera.scanners.tool_output_schema` | Schema enforcement on tool output structural shape |
| `tessera.output_monitor` | Token-level echo detection (URLs, IBANs, emails from untrusted segments) |
| `tessera.claim_provenance` | Provenance-grounded response verification |
| `tessera.plan_verifier` | Plan integrity verification (tool sequence vs user intent) |
| `tessera.trust_decay` | Adaptive trust scoring with time decay and anomaly penalty |
| `tessera.side_channels` | LoopGuard, StructuredResult, ConstantTimeDispatch |
| `tessera.scanners.prompt_screen` | Initial prompt screening for delegated injection |

Framework adapters (14):

| Module | Framework |
|---|---|
| `tessera.adapters.langchain` | LangChain |
| `tessera.adapters.openai_agents` | OpenAI Agents SDK |
| `tessera.adapters.agentdojo` | AgentDojo |
| `tessera.adapters.mcp_proxy` | MCP |
| `tessera.adapters.crewai` | CrewAI |
| `tessera.adapters.google_adk` | Google Agent Development Kit |
| `tessera.adapters.llamaindex` | LlamaIndex |
| `tessera.adapters.haystack` | Haystack |
| `tessera.adapters.langgraph` | LangGraph |
| `tessera.adapters.pydantic_ai` | PydanticAI |

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

The original version of this paper described two primitives, each
implementable in approximately 200 lines, that close the two holes
agent security surveys identify as unimplemented: trust-label injection
and schema-enforced dual-LLM execution.

This revision describes the extensions that grew from applying those
primitives to the AgentDojo benchmark and from competitive analysis
against CaMeL and Microsoft's Agent Governance Toolkit. The extensions
address three attack classes the original primitives explicitly
disclaimed:

1. **Output manipulation** (the injection directs the model's text
   response rather than its tool calls). Addressed by the directive
   scanner's strong/ambient two-layer architecture, schema enforcement
   on tool output structural shape, and intent verification with
   tense/voice filtering.

2. **Coarse-grained taint** (context-level min_trust blocks legitimate
   tasks). Addressed by value-level taint tracking via
   `DependencyAccumulator`, which traces per-argument provenance to
   specific context segments.

3. **Static trust** (trust levels never change). Addressed by adaptive
   trust scoring with time decay and per-server anomaly penalties.

Neither the original primitives nor these extensions require model
modification, new hardware, or changes to control-plane infrastructure.
All have reference implementations with test-verified invariants (991
passing tests) and an AGPL-3.0-or-later license.

The remaining work is validation: running the defenses against real
models in real agent loops, not just deterministic replay. The replay
evaluator measures what Tessera would block if the model followed the
injection. It does not measure how often the model actually follows it.
Live model evaluation against AgentDojo is the next step.

We remain more interested in whether the primitives become widely
understood as a minimum bar for agent security than in whether this
specific implementation is adopted. The extensions described in this
revision were driven by concrete benchmark gaps, not by architectural
ambition. If a different implementation closes the same gaps with better
tradeoffs, that is a good outcome.

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

**Value-level taint (Section 3.7):**

- `tests/test_gap_analysis.py::TestArgumentTaintInPolicy::test_tainted_recipient_blocked_even_with_accumulator`
- `tests/test_gap_analysis.py::TestArgumentTaintInPolicy::test_accumulator_blocks_on_clean_context_tainted_arg`
- `tests/test_gap_analysis.py::TestArgumentTaintInPolicy::test_accumulator_not_checked_for_read_only_tools`

**Content analysis (Section 3.8):**

- `tests/test_gap_analysis.py::TestDirectiveScanner::test_speech_act_directive_detected`
- `tests/test_gap_analysis.py::TestDirectiveScanner::test_ventriloquism_detected`
- `tests/test_gap_analysis.py::TestDirectiveScanner::test_superlative_combined_with_speech_act_detected`
- `tests/test_gap_analysis.py::TestIntentVerification::test_unrequested_send_flagged`
- `tests/test_gap_analysis.py::TestIntentVerification::test_requested_action_not_flagged`
- `tests/test_gap_analysis.py::TestOutputMonitoring::test_url_echo_detected`
- `tests/test_gap_analysis.py::TestOutputMonitoring::test_user_mentioned_token_excluded`
- `tests/test_tool_output_schema.py::TestSchemaEnforcement::test_prose_in_search_output_is_violation`
- `tests/test_tool_output_schema.py::TestSchemaEnforcement::test_free_text_tool_never_violates`

**False positive regression (scanner precision):**

- `tests/test_scanner_false_positives.py::TestDirectiveFalsePositives::test_customer_service_advice`
- `tests/test_scanner_false_positives.py::TestDirectiveFalsePositives::test_product_review_recommendation`
- `tests/test_scanner_false_positives.py::TestIntentFalsePositives::test_past_tense_email_record`
- `tests/test_scanner_false_positives.py::TestIntentFalsePositives::test_nominal_transfer`
- `tests/test_scanner_false_positives.py::TestHeuristicFalsePositives::test_developer_todo_note`

**Plan verification (Section 3.9):**

- `tests/test_plan_verifier.py::test_search_prompt_forbids_send`
- `tests/test_plan_verifier.py::test_forbidden_tool_detected`

**Trust decay (Section 3.10):**

- `tests/test_trust_decay.py::TestEffectiveTrust::test_decay_after_max_age`
- `tests/test_trust_decay.py::TestEffectiveTrust::test_anomaly_penalty_applied`
- `tests/test_trust_decay.py::TestDecayAwareContext::test_decay_aware_context_min_trust`

**SPIFFE JWT-SVID signing:**

- `tests/test_signing.py::test_jwt_round_trip`
- `tests/test_signing.py::test_jwt_tampered_content_rejected`
- `tests/test_signing.py::test_jwks_verifier_resolves_by_kid`
- `tests/test_signer_api.py::test_jwt_signer_via_make_segment_round_trips`

**Delegation chain enforcement:**

- `benchmarks/delegation_chain/test_delegation_attacks.py::TestDelegationScopeEnforcement::test_delegated_tool_outside_scope_denied`
- `benchmarks/delegation_chain/test_delegation_attacks.py::TestDelegationScopeEnforcement::test_wrong_delegate_identity_denied`

**Memory poisoning defense:**

- `benchmarks/memory_poisoning/test_session_rescan.py::TestSessionRescan::test_poisoned_session_blocked_on_rescan`

Total passing tests at the time of writing: 991 (Tessera) + 106
(AgentMesh).

**AgentMesh proxy integration (github.com/kenithphilip/AgentMesh):**

Core pipeline:

- `tests/test_proxy.py::TestEvaluate::test_denied_tainted`
- `tests/test_proxy.py::TestEndToEnd::test_full_injection_scenario`
- `tests/test_proxy.py::TestReadOnlyGuard::test_path_traversal_blocked`
- `tests/test_proxy.py::TestHumanApproval::test_approval_required_tool_denied`

Production hardening:

- `tests/test_tier2_tier3.py::TestPromptScreening::test_injection_prompt_labeled_untrusted`
- `tests/test_tier2_tier3.py::TestPIIScanning::test_pii_redacts_email`
- `tests/test_tier2_tier3.py::TestSecretRedaction::test_secret_redacted_from_tool_output`
- `tests/test_tier2_tier3.py::TestCanaryTokens::test_canary_leakage_detected`
- `tests/test_tier2_tier3.py::TestToxicFlow::test_toxic_flow_blocks_sensitive_egress`

Defense-in-depth:

- `tests/test_tier_ab.py::TestScannerExtensions::test_unicode_tags_force_taint`
- `tests/test_tier_ab.py::TestScannerExtensions::test_intent_scanner_catches_unrequested`
- `tests/test_tier_ab.py::TestScannerExtensions::test_tool_description_poisoning`
- `tests/test_tier_ab.py::TestScannerExtensions::test_tool_shadow_detection`
- `tests/test_tier_ab.py::TestProvenance::test_manifest_with_segments`
- `tests/test_tier_ab.py::TestEvidence::test_evidence_bundle_after_event`

SDK:

- `tests/test_sdk.py::TestMeshClient::test_evaluate_blocked_after_taint`
- `tests/test_sdk.py::TestGenericMeshGuard::test_full_flow`
- `tests/test_sdk.py::TestCrewAIAdapter::test_tool_blocked_after_taint`
- `tests/test_sdk.py::TestGoogleADKAdapter::test_before_tool_blocks`

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
