---
status: Outreach package in preparation
date: 2026-04-25
owner: Kenith Philip
---

# Foundation Model Provenance Signing Partnerships

Tessera maintains signed provenance labels on context segments that enter LLM agent contexts. These labels travel through Tessera's data plane and policy engine, but currently stop at the foundation-model API boundary. This package proposes a partnership model with major model providers (Anthropic, OpenAI, Google) to transport HMAC-signed provenance labels through their APIs, preserving attribution downstream.

## Deliverables

- `proposal.md`: Full technical proposal, backward-compatible wire format, threat model, and implementation outline.
- `letter_anthropic.md`: Vendor-specific outreach letter with API-specific problem statement.
- `letter_openai.md`: Vendor-specific outreach letter with API-specific problem statement.
- `letter_google.md`: Vendor-specific outreach letter with API-specific problem statement.
- `wire_format.md`: Concrete JSON examples of request/response envelopes with sidecar transport.
- `decision_log.md`: Status tracking table and decision rationale per provider.
- `contingency_plan.md`: Action paths for all/partial/no provider adoption.

## Partnership Status

| Provider | Outreach Planned | Contact Channel | Status | Decision Deadline |
|----------|------------------|-----------------|--------|-------------------|
| Anthropic | 2026-Q3 | security@anthropic.com | Pending | 2026-09-30 |
| OpenAI | 2026-Q3 | security@openai.com | Pending | 2026-09-30 |
| Google | 2026-Q3 | security@google.com | Pending | 2026-09-30 |

## Why This Matters

Tessera's provenance labels defend against indirect prompt injection by binding trust metadata to content segments. When labels cannot survive API boundaries, agents lose attribution coverage once data enters a foundation model. This package asks providers to echo HMAC-signed labels back through request/response envelopes, preserving the security boundary.

The ask is backward-compatible: clients without the sidecar see no change. Providers who ship this support early will have a documented, testable security primitive their customers can rely on.

## Next Steps

1. Technical review of proposal.md and wire_format.md (internal).
2. File outreach letters in 2026-Q3 with accompanying contact path.
3. Track responses in decision_log.md.
4. Activate contingency_plan.md paths based on provider decisions.
