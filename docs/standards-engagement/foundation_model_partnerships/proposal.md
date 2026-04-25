---
status: Ready for vendor review
date: 2026-04-25
owner: Kenith Philip
---

# Proposal: HMAC-Signed Provenance Label Transport Through Foundation Model APIs

## Problem Statement

Tessera implements signed trust labels on context segments, binding provenance metadata to the exact bytes of text entering LLM agent contexts. These labels are cryptographically verified at policy evaluation time and drive deterministic control-flow decisions at the tool-call boundary.

Today, this defense stops at the foundation-model API boundary. When an agent sends a labeled context to Claude, ChatGPT, or Gemini, the API strips the provenance metadata from the request envelope. If the foundation model's response includes data that flows back into the agent, that data lacks attribution. An attacker who controls an earlier context segment can influence the response without leaving a cryptographic trace of the contamination.

The gap is narrow (foundation-model APIs are not the primary injection vector) but real: it covers scenarios where an attacker can shape a model response that later gets fed back into the agent's context with higher trust than it deserves.

## Proposed Solution

Transport HMAC-signed provenance labels as a structured sidecar in request and response envelopes. The sidecar travels alongside the main payload but is not part of the model's input. On the Tessera side, we verify and lift the labels back onto the response data, restoring the attribution chain.

Wire format: request and response messages include an optional `__tessera_labels__` sidecar field at the top level, keyed by field name:

```json
{
  "messages": [...],
  "__tessera_labels__": {
    "messages": {
      "src": ["user://session/123"],
      "i": 1,
      "s": 0,
      "cap": 3
    }
  }
}
```

A signature header `X-Tessera-Provenance-Sig` (HMAC-SHA256) proves the sidecar was not tampered with after leaving the API client.

## Compatibility

Backward-compatible in both directions:

- Clients without a sidecar implementation see no change; their requests and responses work exactly as today.
- Providers who do not support the sidecar simply echo back requests without `__tessera_labels__` fields, and clients gracefully downgrade to unsigned transport.
- Existing agent code needs zero changes; the sidecar is transparent to the model.

## Implementation Outline

### Provider side (approximately 50 lines of code)

1. Deserialize the request, extract `__tessera_labels__` if present.
2. Verify the signature header against the sidecar and the request body.
3. Store the sidecar in a secure context variable (not visible to the model).
4. When constructing the response, attach the same sidecar (or an updated one reflecting new outputs).
5. Sign the response sidecar with the same HMAC key.
6. Return both the response payload and the `X-Tessera-Provenance-Sig` header.

### Tessera side (already implemented)

`tessera.labels.HMACVerifier` and `tessera.signing.HMACVerifier` already support sidecar verification. Tessera's HTTP client wrapper will:

1. Construct the `__tessera_labels__` sidecar from the request context.
2. Sign it before sending.
3. Verify the response sidecar and signature.
4. Lift labels back onto response fields using `tessera.taint.json_encoder.decode`.

## Threat Model

### What This Defends Against

- An attacker controlling client-side context attempts to inject a malicious instruction.
- The instruction passes through the foundation model's processing.
- The response flows back into the agent's context with artificially high trust.
- The signature header lets the agent verify that the response provenance is authentic and unchanged.

### What This Does NOT Defend Against

- Model-level attacks (backdoors, weight poisoning, adversarial prompts).
- Compromised provider infrastructure.
- An attacker who controls the symmetric HMAC key (credential compromise).
- Semantic poisoning: an attacker crafting a response that is cryptographically valid but semantically malicious.

These are explicitly out of scope per Tessera's threat model in the paper.

## Operational Asks

1. **SLA:** Providers commit to preserving `__tessera_labels__` and `X-Tessera-Provenance-Sig` across all request/response paths for the lifetime of an API version. No silent stripping.

2. **Deprecation policy:** If a provider decides to deprecate the feature, they announce it with 12 months' notice and maintain support for two stable API versions post-announcement.

3. **Key rotation:** Providers supply a key rotation endpoint (similar to JWKS providers) so Tessera clients can refresh HMAC keys without human intervention. Key ID in the signature header.

4. **Staging environment:** Initial support can land in staging only; production adoption follows if testing shows zero performance impact.

## Reference Implementation

- `tessera.labels.TrustLabel`, `sign_label`, `verify_label`: core label and HMAC signing (110 lines, stable API).
- `tessera.taint.json_encoder.SIDECAR_KEY`, `encode`, `decode`: sidecar serialization (140 lines, stable API).
- `tessera.signing.HMACVerifier`: verifier for this sidecar format (80 lines, stable API).

All three modules are frozen for v1.0. Tests cover round-trip serialization and verification against real HMAC keys.

## Next Steps

1. Provider technical team reviews this proposal and the wire_format.md examples.
2. Provider staging environment implements sidecar support.
3. Tessera integration tests run against staging, validating signature round-trip.
4. Decision: partner, decline, or revisit in 12 months.

See decision_log.md for tracking decisions per vendor and contingency_plan.md for actions on all/partial/no adoption.
