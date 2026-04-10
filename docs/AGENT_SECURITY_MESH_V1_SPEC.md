# Agent Security Mesh V1

**Status:** Draft v1 for discussion and iteration.

**Position:** This document defines a proposed provider-neutral security mesh for agentic workloads. Tessera is not this mesh. Tessera is a reference implementation of two load-bearing primitives that fit inside it: signed context provenance labels and schema-enforced dual-LLM execution.

## Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, and `MAY` in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

## Executive Summary

An agent security mesh is possible today, but not as a single finished product. The identity, transport, and policy building blocks already exist in production-grade form: [SPIFFE/SPIRE](https://spiffe.io/docs/latest/deploying/svids/) for workload identity, [MCP](https://github.com/modelcontextprotocol/modelcontextprotocol) and [A2A](https://a2a-protocol.org/) for agent interoperability, [OAuth-based agent auth guidance from IETF WIMSE work](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) for delegation and application authentication, and emerging agent-aware proxies such as [agentgateway](https://docs.solo.io/agentgateway/2.1.x/).

What does not exist yet is the integration layer. In particular, there is no widely adopted standard for signed prompt provenance that lets a system deterministically distinguish user instructions from untrusted instructions arriving from the web, tools, memory, or other agents. That is the main gap this specification addresses.

This specification proposes an ambient or gateway-deployed mesh with seven core capabilities:

1. workload identity for agents, tools, and control-plane services
2. user-to-agent delegation with transaction scoping
3. signed provenance on every context segment
4. deterministic policy enforcement outside the model
5. MCP, A2A, and LLM-aware data-plane mediation
6. runtime containment for dangerous actions
7. audit and observability with provenance-preserving event schemas

The central claim is simple: model behavior is probabilistic, so security boundaries must be enforced in deterministic code outside the model.

## Problem Statement

Traditional service meshes secure deterministic software components. Agentic systems break those assumptions. An LLM-based agent changes behavior with each prompt, dynamically selects tools, mixes trusted and untrusted text into a single context window, and often acts on behalf of a human principal without a standard delegation model.

The specific security problem this spec targets is indirect prompt injection. [Spotlighting](https://arxiv.org/abs/2403.14720) shows why the problem exists: the model cannot inherently distinguish which parts of a concatenated prompt come from the user and which parts come from attacker-controlled sources. [CaMeL](https://arxiv.org/abs/2503.18813) and [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837) show that the workable defenses rely on system architecture, not prompt wording.

The mesh goal is not to make models safe in the abstract. The goal is to make agent actions attributable, authorized, auditable, and resistant to untrusted context influencing privileged operations.

## Terminology

- **Agent**: a software system that uses an LLM or equivalent model to select or execute actions.
- **Tool**: an external capability exposed to an agent through MCP, HTTP, RPC, shell, or equivalent integration.
- **Control plane**: the system responsible for identity issuance, policy distribution, registry metadata, and fleet-level governance.
- **Data plane**: the system that mediates runtime requests among agents, tools, and model providers.
- **Prompt segment**: a single unit of content entering the context window, such as a user instruction, tool result, memory retrieval, or web document.
- **Provenance**: verifiable metadata describing where a prompt segment came from, who issued it, and how it relates to earlier segments.
- **Delegation**: authorization by which a human or organization permits an agent to act within a defined scope.
- **High-risk action**: any action that can exfiltrate data, mutate external state, spend money, invoke admin capabilities, or trigger regulated workflows.

## Design Principles

### 1. External Enforcement

Every security decision that matters must be made outside the model.

### 2. Provenance Before Policy

Authorization decisions are only meaningful if the system knows where each context segment came from and can verify that claim cryptographically.

### 3. Ambient Or Gateway Deployment

Like modern service meshes, the preferred operational model is node-level, gateway-level, or ambient interception. Per-agent sidecars should be optional, not the default.

### 4. Provider Neutrality

The mesh must compose with hosted APIs, self-hosted inference, open-weight models, and multiple tool and agent protocols.

### 5. Deterministic Minimum Guarantees

The baseline guarantee is control-flow protection: untrusted content must not cause privileged actions to occur without clearing explicit policy gates.

### 6. Honest Scope

This specification does not claim to solve model poisoning, prompt quality, hallucinations, or all semantic attacks. It defines system-level security and identity primitives for agent operations.

## Threat Model And Non-Goals

### In Scope

- indirect prompt injection from web content, RAG content, tool outputs, memory, or other agents
- unauthorized tool invocation
- confused-deputy behavior between users, agents, and tools
- replay or misuse of agent credentials
- lack of attribution and audit across agent-to-agent and agent-to-tool flows
- cross-tenant or cross-principal contamination in shared agent infrastructure

### Out Of Scope

- a malicious authenticated end user directly instructing the agent to do harm
- compromise of the model weights or hosting provider
- sandbox escape from arbitrary code execution environments
- all forms of semantic manipulation of natural-language outputs
- a claim that current transformer architectures natively enforce trust boundaries

## What Exists Today

The following components are real and usable as of April 10, 2026.

### Workload Identity

- [SPIFFE/SPIRE](https://spiffe.io/docs/latest/deploying/svids/) provides short-lived workload identities and mTLS-ready SVIDs.
- The March 2026 IETF draft [AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) explicitly says agents need unique identifiers, credentials, delegation, and authorization, and allows a SPIFFE ID to serve as the agent identifier model.

### Agent And Tool Protocols

- [Model Context Protocol](https://github.com/modelcontextprotocol/modelcontextprotocol) is the main open tool protocol surface.
- [A2A](https://a2a-protocol.org/) provides an open agent-to-agent interaction model and Agent Cards for discovery.

### Proxies And Runtime Governance

- [agentgateway](https://docs.solo.io/agentgateway/2.1.x/) is the closest current data-plane analog to Envoy for agents, with MCP-aware routing and operational mesh positioning.
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) provides deterministic runtime governance, identity, policy, and sandboxing around agent actions.

### Research Primitives

- [Spotlighting](https://arxiv.org/abs/2403.14720) shows provenance-marking of untrusted content can reduce indirect prompt-injection success from greater than 50 percent to below 2 percent in the reported experiments.
- [CaMeL](https://arxiv.org/abs/2503.18813) demonstrates that trusted control separation and capability-based execution can provide provable control-flow guarantees.
- [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837) organizes these defenses as reusable architectural patterns rather than isolated tricks.

### Emerging Trust Metadata

- The MCP security annotation proposal includes fields such as `privateHint`, `sensitiveHint`, and `maliciousActivityHint`, but this is still proposal-stage rather than a settled core standard: [proposal](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/711).

## What Is Missing

Four gaps prevent the current ecosystem from looking like Istio, Linkerd, or Cilium for agents.

### 1. Signed Prompt Provenance

There is no widely adopted standard that attaches a signed, content-bound provenance record to every prompt segment.

### 2. User-To-Agent Delegation

There is no common token profile that cleanly binds a human principal, an agent workload identity, a task scope, and transaction-specific authorization details.

### 3. Cross-Provider Federation

There is no adopted cross-provider model by which an agent running under one trust domain can securely authenticate, delegate, and exchange provenance-aware requests with another provider's agents, tools, or model endpoints.

### 4. Provider-Native Trust Separation

Hosted LLM APIs generally do not expose a hard, verifiable distinction between trusted instruction channels and untrusted data channels. Today this boundary must be emulated outside the model.

## Architecture

The proposed architecture has one control plane and seven main enforcement layers.

```text
┌────────────────────────────────────────────────────────────┐
│                      Control Plane                         │
│ identity │ delegation │ registry │ policy │ telemetry     │
└──────────┬────────────┬──────────┬────────┬───────────────┘
           │            │          │        │
┌──────────▼────────────────────────────────────────────────┐
│ L1 Identity                                               │
│ SPIFFE or equivalent workload identity for agents/tools   │
├───────────────────────────────────────────────────────────┤
│ L2 Delegation                                             │
│ user-to-agent, agent-to-agent, transaction-scoped auth    │
├───────────────────────────────────────────────────────────┤
│ L3 Provenance                                             │
│ signed context segments and lineage-preserving manifests   │
├───────────────────────────────────────────────────────────┤
│ L4 Policy                                                 │
│ deterministic authz on tool calls, agent hops, egress     │
├───────────────────────────────────────────────────────────┤
│ L5 Data Plane                                             │
│ MCP, A2A, and LLM-aware ambient or gateway proxy          │
├───────────────────────────────────────────────────────────┤
│ L6 Runtime                                                │
│ sandboxing, isolation, and kill-switches for execution    │
├───────────────────────────────────────────────────────────┤
│ L7 Observability                                          │
│ OTel, audit logs, provenance DAGs, policy decisions       │
└───────────────────────────────────────────────────────────┘
```

### Control Plane Responsibilities

- issue and rotate workload identities
- mint and validate delegation artifacts
- distribute policy bundles
- maintain agent and tool registry metadata
- publish trust mappings and provenance rules
- aggregate audit and observability outputs

### Data Plane Responsibilities

- terminate and re-establish authenticated protocol sessions
- inject or exchange credentials on outbound requests
- evaluate policy before tool or agent actions
- attach or verify provenance on content entering context
- enforce egress restrictions
- preserve event lineage for audit

## Core Primitives

### Agent Identity Document

The mesh requires a provider-neutral workload identity profile for agents.

Required fields:

- `agent_id`: stable workload identifier, ideally SPIFFE-compatible
- `trust_domain`
- `software_identity`: framework, version, image digest, or equivalent
- `key_binding`: proof that the workload controls the private key
- `issuer`
- `valid_from`
- `valid_until`

This document can be represented using existing workload identity systems. This specification does not require inventing a new PKI.

Normative requirements:

- an Agent Identity Document `MUST` be cryptographically bound to a workload-controlled key
- the `agent_id` `MUST` be stable for the lifetime of the credential
- the document `MUST` include validity bounds
- verifiers `MUST` reject expired or unverifiable identities

### Delegation Token

The mesh requires a portable delegation artifact from user or organization to agent.

Required fields:

- `subject`: delegating human or org principal
- `delegate`: target agent identity
- `audience`
- `authorized_actions`
- `constraints`
- `session_id`
- `transaction_id`, optional but recommended
- `issued_at`
- `expires_at`
- `proof_of_possession` binding

This should compose with OAuth, token exchange, and transaction-token work, not replace them. The [IETF agent auth draft](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) already points toward OAuth security best practices and transaction-scoped tokens.

Normative requirements:

- a Delegation Token `MUST` bind the delegating principal and the target agent identity
- a Delegation Token `MUST` be audience restricted
- a Delegation Token `MUST` include an expiration time
- high-risk actions `SHOULD` require transaction-scoped delegation rather than broad session-scoped delegation
- implementations `SHOULD` use proof-of-possession or equivalent token binding

### Context Segment Envelope

The **Context Segment Envelope** is the key new primitive. Every segment of text entering an agent context carries a signed, content-bound metadata envelope.

Required fields:

```json
{
  "segment_id": "seg_123",
  "origin": "user|system|tool|memory|web|agent",
  "issuer": "spiffe://acme.ai/ns/research/agent/summarizer/i/abcd",
  "delegating_user": "user:jane@acme.com",
  "trust_level": 100,
  "sensitivity": ["internal"],
  "content_sha256": "2c26b46b68ffc68ff99b453c1d304134...",
  "parent_ids": ["seg_101"],
  "created_at": "2026-04-10T12:00:00Z",
  "signature": "base64url(...)"
}
```

Rules:

- the signature must bind the envelope to the exact content bytes
- the issuer must be authenticated independently of the content itself
- `origin` is descriptive provenance, not permission by itself
- `trust_level` is policy input and must be derived by verified policy rules
- `parent_ids` preserve lineage across transformations and summaries

Normative requirements:

- every non-system context segment `MUST` carry a valid Context Segment Envelope in Silver and Gold deployments
- the `content_sha256` `MUST` match the exact bytes inserted into the prompt
- verifiers `MUST` reject a segment whose envelope signature, content hash, or issuer verification fails
- systems `MUST NOT` treat `origin=user` as sufficient authorization without separate identity and delegation validation
- systems `SHOULD` preserve `parent_ids` when summaries, extractions, or tool outputs derive from earlier segments

### Prompt Provenance Manifest

The **Prompt Provenance Manifest** is the ordered list of Context Segment Envelopes attached to one model request or one planner or worker invocation.

Required fields:

- `manifest_id`
- `session_id`
- `principal_set`
- `segments`, ordered
- `assembled_by`
- `assembled_at`
- `signature`

Rules:

- manifest ordering must match the actual prompt assembly order
- each segment entry must reference a valid Context Segment Envelope
- downstream components must reject manifests whose segment order or content hashes do not match the actual prompt payload

Recommended wire shape:

```json
{
  "manifest_id": "ppm_7f3a9b2c",
  "session_id": "ses_7f3a9b2c",
  "principal_set": ["user:jane@acme.com"],
  "segments": [
    {"segment_id": "seg_101", "position": 0, "content_sha256": "abc..."},
    {"segment_id": "seg_102", "position": 1, "content_sha256": "def..."}
  ],
  "assembled_by": "spiffe://acme.ai/ns/gateway/proxy/i/0f9d",
  "assembled_at": "2026-04-10T12:00:01Z",
  "signature": "base64url(...)"
}
```

Normative requirements:

- a Prompt Provenance Manifest `MUST` cover the entire ordered prompt presented to the model
- the manifest `MUST` be signed by the component that assembled the prompt
- downstream policy engines `MUST` reject a manifest whose ordering or segment hashes do not match the actual prompt
- model providers that do not evaluate manifests directly `MAY` treat them as opaque metadata, but they `SHOULD` preserve them across tool-calling and agent-handoff surfaces

### Tool Authorization Contract

The **Tool Authorization Contract** declares the security expectations of a tool call.

Required fields:

- `tool_name`
- `required_trust`
- `required_scopes`
- `allowed_callers`
- `egress_policy`
- `approval_mode`
- `output_handling`
- `audit_class`

This is where provider-independent policy meets tool-specific risk.

Recommended wire shape:

```json
{
  "tool_name": "send_email",
  "required_trust": 100,
  "required_scopes": ["mail.send"],
  "allowed_callers": ["spiffe://acme.ai/ns/assistants/agent/executive-assistant/*"],
  "egress_policy": {
    "allow": ["https://api.mail.example.com"],
    "deny": ["*"]
  },
  "approval_mode": "human_for_external_recipients",
  "output_handling": "tool_output",
  "audit_class": "high_risk"
}
```

Normative requirements:

- every privileged tool `MUST` have an explicit Tool Authorization Contract in Bronze, Silver, and Gold deployments
- the policy engine `MUST` evaluate required trust before executing the tool call
- egress destinations `MUST` be checked against the contract before network execution
- high-risk tools `SHOULD` declare approval requirements and audit class explicitly

### Security Event Schema

Every security-relevant action must emit a standard event.

Required fields:

- `event_id`
- `event_kind`
- `agent_id`
- `session_id`
- `policy_evaluation_id`
- `decision`
- `input_provenance_refs`
- `timestamp`
- `detail`

Examples:

- label verification failure
- delegation rejection
- denied tool call
- cross-agent authorization failure
- quarantined worker schema violation

Recommended wire shape:

```json
{
  "event_id": "evt_01jrm7r5v4",
  "event_kind": "policy_deny",
  "agent_id": "spiffe://acme.ai/ns/research/agent/summarizer/i/abcd",
  "session_id": "ses_7f3a9b2c",
  "policy_evaluation_id": "pol_12f0",
  "decision": "deny",
  "input_provenance_refs": ["seg_101", "seg_102"],
  "timestamp": "2026-04-10T12:00:02Z",
  "detail": {
    "tool_name": "send_email",
    "required_trust": 100,
    "observed_trust": 0
  }
}
```

Normative requirements:

- every deny path `MUST` emit a Security Event
- successful actions `SHOULD` emit auditable events where required by policy or regulation
- event consumers `MUST NOT` rely on natural-language model output as the sole audit artifact

## Transport Bindings

This section proposes wire bindings for the core primitives. These are proposal-level elements, not existing standards.

Implementations `MUST` treat the names in this section as provisional unless and until they are standardized. The main requirement is stable carriage of the objects, not these exact header strings.

### HTTP Binding

For HTTP-based MCP, A2A, and model-provider traffic, implementations `SHOULD` support the following headers:

- `ASM-Agent-Identity`: serialized Agent Identity Document reference or compact token
- `ASM-Agent-Delegation`: serialized Delegation Token
- `ASM-Prompt-Provenance`: serialized Prompt Provenance Manifest reference or compact token

Where headers are too large, implementations `MAY` place the full objects in the request body and send only stable references in headers.

Implementations `SHOULD` preserve these fields across internal retries, proxy hops, and tool-call dispatches. Intermediaries `MUST NOT` rewrite these values except when explicitly authorized to re-sign or replace them as the prompt-assembling authority.

### JSON-RPC Binding

For JSON-RPC traffic, implementations `SHOULD` support a `security_context` object attached to the request envelope:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "send_email",
    "arguments": {"to": "bob@example.com"},
    "security_context": {
      "agent_identity_ref": "aid_01",
      "delegation_ref": "dlg_01",
      "prompt_provenance_ref": "ppm_01"
    }
  },
  "id": "1"
}
```

### Provider API Binding

Hosted model APIs that cannot yet parse these objects `SHOULD` accept them as opaque metadata and `SHOULD` preserve them in downstream tool-call and trace surfaces. Provider-native trust-separated channels are a target for later standardization, not a current assumption.

## Versioning And Extensibility

All proposed protocol objects in this document `SHOULD` include an explicit version field once standardized. Until then, version negotiation may be carried by:

- media type parameters in HTTP
- protocol extension negotiation in MCP or A2A metadata
- object-level `schema_version` fields

Extensions `MUST NOT` silently change the meaning of existing fields. Unknown fields `MAY` be ignored unless local policy declares them mandatory.

## Trust Semantics

This specification recommends ordered trust levels similar to Tessera's current primitives:

- `UNTRUSTED = 0`
- `TOOL = 50`
- `USER = 100`
- `SYSTEM = 200`

Inference from current research and implementation practice: the important property is ordering, not the exact numeric values.

The default deterministic rule for privileged tool execution is:

```text
allow(tool, context) iff required_trust(tool) <= min_trust(context)
```

This is the strongest simple baseline because one untrusted segment drags the effective trust of the composed context to the floor. That mirrors the load-bearing invariant already implemented by Tessera.

## Deterministic Enforcement Points

The mesh enforces invariants at four places outside the model.

### Proxy

- verifies workload identity on inbound and outbound requests
- validates delegation artifacts
- verifies Context Segment Envelopes
- injects provenance or rejects unsigned content
- mediates MCP, A2A, and model-provider calls

### Policy Engine

- evaluates tool-call authorization
- evaluates agent-to-agent authorization
- enforces egress policy
- enforces approval and transaction constraints

### Runtime Sandbox

- contains code execution
- constrains filesystem, network, and subprocess access
- supports kill-switches and task termination

### Audit And Telemetry Path

- emits structured security events
- links policy decisions to provenance references
- preserves lineage across retries, sub-agents, and tool hops

## Deployment Profiles

### Ambient Or Gateway Mesh

Recommended default for enterprises and providers.

Properties:

- low operational overhead
- centralized enforcement
- easiest path to uniform audit and egress control

### Framework SDK Mode

Useful where full network mediation is not feasible.

Properties:

- faster adoption for application teams
- weaker guarantees if traffic bypasses the SDK
- still useful for provenance labeling and policy hooks

### High-Security Dual-LLM Mode

Use for workflows with sensitive tools, approvals, or regulated actions.

Properties:

- quarantined untrusted-data processing
- trusted planner that never sees raw untrusted content
- higher latency and complexity

This mode is directly aligned with the design direction of CaMeL and Tessera's `strict_worker` and `QuarantinedExecutor`.

## Standards Mapping

### Identity

- workload identity: [SPIFFE/SPIRE](https://spiffe.io/docs/latest/deploying/svids/)
- agent auth and delegation model: [IETF AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)

### Tool And Agent Interop

- tool protocol: [MCP](https://github.com/modelcontextprotocol/modelcontextprotocol)
- agent protocol: [A2A](https://a2a-protocol.org/)

### Research And Security Model

- provenance-marked untrusted input: [Spotlighting](https://arxiv.org/abs/2403.14720)
- trusted control and untrusted data separation: [CaMeL](https://arxiv.org/abs/2503.18813)
- architectural prompt-injection patterns: [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837)

### Proposed Standardization Targets

This specification proposes standardizing the following, because they do not yet exist as adopted cross-ecosystem primitives:

- Context Segment Envelope
- Prompt Provenance Manifest
- portable Delegation Token profile for agents
- Tool Authorization Contract schema
- Security Event Schema for agent operations

## Conformance

Conformance is intentionally progressive.

### Bronze

Required:

- workload identity for agents and tools
- authenticated MCP or A2A mediation
- deterministic tool authorization
- structured audit events

Normative profile:

- Bronze implementations `MUST` authenticate agents and tools
- Bronze implementations `MUST` authorize privileged tool calls before execution
- Bronze implementations `MUST` emit structured audit events for deny decisions
- Bronze implementations `SHOULD` centralize mediation through ambient or gateway deployment

Suitable for:

- early enterprise adoption
- provider-hosted gateways
- internal tool mediation

### Silver

Required:

- all Bronze requirements
- signed prompt provenance on all non-system context segments
- egress control
- delegation-aware policy evaluation

Normative profile:

- Silver implementations `MUST` satisfy all Bronze requirements
- Silver implementations `MUST` require valid Context Segment Envelopes on all non-system prompt segments
- Silver implementations `MUST` verify Prompt Provenance Manifests before high-risk actions
- Silver implementations `MUST` enforce egress policy
- Silver implementations `MUST` incorporate Delegation Token constraints into policy evaluation

Suitable for:

- regulated enterprise agents
- multi-agent internal platforms
- tool marketplaces and registries

### Gold

Required:

- all Silver requirements
- quarantined execution mode for untrusted data paths
- transaction-scoped delegation for sensitive actions
- lineage-preserving audit across sub-agents and tool chains

Normative profile:

- Gold implementations `MUST` satisfy all Silver requirements
- Gold implementations `MUST` isolate untrusted-data handling from privileged planning or execution paths
- Gold implementations `MUST` require transaction-scoped delegation for high-risk actions
- Gold implementations `MUST` preserve lineage across sub-agent, tool, and retry boundaries

Suitable for:

- high-risk financial, healthcare, and enterprise admin workflows
- provider-native governed agent offerings

## Adoption Matrix

### Enterprises

Need:

- auditability
- policy control
- identity and egress containment

Best first move:

- ambient or gateway deployment with Bronze or Silver conformance

### Model Providers

Need:

- portable governance layer
- provider-native trust-separated channels
- standardized provenance handoff to tools and agents

Best first move:

- accept Prompt Provenance Manifest inputs and preserve provenance in tool-call surfaces

### Tool Providers

Need:

- strong caller identity
- scoped delegation
- standard trust metadata in requests

Best first move:

- require authenticated callers and publish Tool Authorization Contracts

### Framework Maintainers

Need:

- simple integration hooks
- no forced infrastructure rewrite

Best first move:

- SDK support for Context Segment Envelope generation and policy callbacks

## Deployment Examples

These examples are illustrative deployment profiles, not claims about current native support from any provider.

### Hosted OpenAI-Style Deployment

- enterprise gateway assembles the prompt
- gateway signs Context Segment Envelopes and the Prompt Provenance Manifest
- gateway forwards the request to the hosted model API with provenance metadata attached
- tool calls return through the same gateway, which enforces Tool Authorization Contracts before execution

Properties:

- no provider changes required for baseline adoption
- strongest guarantees remain at the enterprise gateway
- provider-native trust separation is not assumed

### Hosted Anthropic-Style Deployment

- orchestration layer or gateway mediates MCP and model requests
- provenance and delegation validation happen before the model call
- tool use is authorized and audited by the external mesh layer

Properties:

- works even when the provider acts as a pure inference endpoint
- preserves portability across hosted providers

### Self-Hosted Or Open-Weight Deployment

- ambient proxy or node gateway mediates all model, tool, and agent traffic
- provenance manifests are available to the local runtime, planner, and policy engine
- Gold conformance is easiest here because the operator controls the full path

Properties:

- highest control
- strongest enforcement options
- highest operator responsibility

## Relationship To Tessera

Tessera already implements two primitives that belong inside this architecture:

- content-bound signed labels on context segments with taint-tracking policy
- schema-enforced dual-LLM execution for trusted control and untrusted data separation

Tessera should remain a portable primitive layer. It should not become a competing mesh control plane. That is already consistent with the current [roadmap](./ROADMAP.md), which explicitly says Tessera should not build a new control plane.

## Adoption Roadmap

### Phase 1: Practical Interop

- deploy gateway or ambient mediation
- bind agent workloads to SPIFFE or equivalent identities
- add deterministic policy for tool calls
- emit structured audit events

### Phase 2: Signed Provenance

- standardize Context Segment Envelope and Prompt Provenance Manifest
- integrate provenance verification in proxies and SDKs
- require trust metadata on tool and agent responses

### Phase 3: Delegation And Federation

- standardize user-to-agent delegation profiles
- support transaction-scoped high-risk actions
- enable cross-domain and cross-provider identity federation

### Phase 4: Provider-Native Trust Channels

- expose separate trusted and untrusted input channels in model APIs
- preserve provenance into tool-calling and agent-handoff surfaces
- support provider-verified policy hooks

## Security Considerations

This specification exists because prompt provenance and delegation are security boundaries, not convenience metadata.

- implementations `MUST` verify workload identity, delegation, and provenance signatures before privileged actions
- implementations `MUST` fail closed on invalid signatures, expired delegation, or manifest mismatch for protected workflows
- implementations `MUST NOT` treat a natural-language prompt as sufficient authority for a privileged tool call
- implementations `MUST` bind sensitive actions to explicit policy evaluation and auditable decisions
- implementations `SHOULD` use short-lived credentials and proof-of-possession token binding to reduce replay risk
- implementations `SHOULD` prevent provenance stripping by requiring either end-to-end carriage or trusted re-signing at authorized boundaries
- implementations `SHOULD` isolate untrusted-data processing from privileged execution where the impact of compromise is high
- implementations `MUST NOT` rely on model compliance with provenance markers as the sole enforcement mechanism

Residual risks remain:

- a compromised trusted workload can still issue malicious but validly signed provenance
- semantic attacks on final natural-language output remain possible even when tool control flow is protected
- policy quality still matters, a cryptographically perfect mesh can enforce a bad rule perfectly

## Privacy Considerations

Prompt provenance and delegation carry identity and behavioral metadata. Mishandling them creates a privacy problem even if the cryptography is correct.

- implementations `MUST` minimize personally identifiable information carried in prompt provenance and delegation artifacts
- implementations `SHOULD` prefer opaque references over rich identity claims when the receiving service does not need the full identity details
- downstream tools `MUST` receive only the minimum provenance and delegation information required for authorization and audit
- audit systems `MUST NOT` log full bearer tokens or unredacted sensitive delegation payloads
- cross-domain federation `SHOULD` use derived or down-scoped credentials so one provider does not learn unnecessary user context from another
- provenance lineage `SHOULD` preserve traceability without replicating raw user data unless policy explicitly requires it

Operationally, privacy review is not optional. A deployment that preserves every principal identifier and prompt lineage forever will become a surveillance system with nicer JSON.

## Open Questions

These are real questions, not placeholders.

- Should Prompt Provenance Manifest signing happen only at the proxy, or can framework SDKs legitimately assemble and sign manifests too.
- How much provenance detail can be preserved without over-disclosing user identity to downstream tools.
- Whether the eventual standard should encode trust levels directly or only encode provenance facts and let local policy derive trust.
- How much of the Delegation Token profile should be pure OAuth profiling versus a distinct agent-specific profile layered on top.

## Summary

The mesh can be built. The main missing piece is not another guardrail library. It is a standard, verifiable provenance and delegation layer that sits between models, agents, tools, and users.

The short version:

- identity exists
- protocols exist
- policy engines exist
- proxies exist
- sandboxing exists
- signed prompt provenance does not yet exist as an adopted standard

That missing standard is where the ecosystem should focus.
