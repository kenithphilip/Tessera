---
status: Ready to send
date: 2026-04-25
owner: Kenith Philip
---

# Outreach Letter: Google

**To:** security@google.com, Google DeepMind Security and Gemini Teams

**From:** Kenith Philip, Tessera Maintainer

**Date:** 2026-Q3 (planned outreach window)

---

## Subject: Partnership proposal for HMAC-signed provenance label transport

Dear Google Security and Gemini Teams,

Tessera is an open-source Python library of composable security primitives for LLM agent systems, maintained at https://github.com/kenithphilip/Tessera. We implement signed trust labels on context segments, binding cryptographically-verified provenance metadata to data entering agent contexts.

Currently, when agents call the Google Gemini API (the `generateContent` endpoint), Tessera labels travel in the request but are not echoed back in the response. This creates an attribution gap: response data flowing back into the agent's context lacks the provenance chain, allowing an attacker who shaped the response to evade detection.

We are reaching out to propose an optional HMAC-signed provenance sidecar in the request/response envelope. The proposal is fully backward-compatible, requires minimal implementation overhead, and has zero impact on model latency or accuracy.

### The Ask

Implement optional sidecar transport for request and response messages:

1. Accept an optional `__tessera_labels__` field in the request body (JSON object keyed by field name).
2. Verify the sidecar against the `X-Tessera-Provenance-Sig` header (HMAC-SHA256).
3. Echo the same sidecar back in the response, re-signed with the same key.
4. Do not include the sidecar in the model's input (it is transparent to Gemini).

Concrete JSON examples are available in foundation_model_partnerships/wire_format.md in the Tessera repository.

### Why This Matters for Google

Google's enterprise customers (particularly in financial services, healthcare, and government) demand verifiable audit trails and supply-chain integrity. A documented, cryptographic provenance signal positions Gemini API as the foundation model with the strongest provenance guarantees. Early adoption creates a moat against competitors who would need significant engineering to match the feature.

The implementation is approximately 50 lines of code in the API gateway. Testing can happen entirely in Google Cloud's staging environment with zero production risk.

### Next Step

We propose a small first ask: Can Google's Gemini API team test the sidecar format in the staging environment? We will:

1. Provide complete request/response examples (ready now; see wire_format.md).
2. Implement Tessera client-side verification (already done).
3. Run integration tests against staging, reporting any issues or format ambiguities.

Success means the Gemini API staging environment supports sidecar round-trip with no latency regression. From there, you decide on production deployment and feature announcement.

### Contact

We are available for technical discussion via:

- Tessera GitHub issues: https://github.com/kenithphilip/Tessera/issues
- Google's security reporting: https://security.google.com
- This maintainer: kenith.philip@fivetran.com

### Timeline

Please reply by 2026-09-30 with your decision. We will document the outcome (yes, no, or conditional) in Tessera's public decision_log.md so users know which providers support provenance signing.

Thank you for considering this partnership.

Best regards,

Kenith Philip
Tessera Maintainer
