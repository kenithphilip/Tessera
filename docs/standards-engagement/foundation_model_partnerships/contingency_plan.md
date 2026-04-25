---
status: Contingency action plan
date: 2026-04-25
owner: Kenith Philip
---

# Contingency Plan: Provider Adoption Outcomes

When providers respond to the outreach letters, their decisions will fall into three aggregate scenarios. This document specifies the action path for each.

## Scenario 1: All Three Say No

**Trigger:** Anthropic, OpenAI, and Google all decline to support provenance sidecars by the decision deadline (2026-09-30).

**Engineering Impact:**

HMAC-signed transport works within Tessera's data plane (agent-to-proxy and proxy-to-scanner paths remain fully signed). The gap persists only at the foundation-model API boundary: labels are stripped on the way in and cannot be verified on the way out.

**Mitigation:**

1. Document the limitation in user-facing docs: "Foundation-model APIs currently do not preserve provenance labels. Tessera defends against indirect prompt injection within your infrastructure; once data enters Claude/ChatGPT/Gemini, attribution coverage halts."

2. Ship a detection scanner (in `tessera.scanners`) that identifies label-strip behavior:
   - Infer from shape: if the response payload has the same structure as the request sidecar, we can detect whether it was preserved.
   - Emit `SecurityEvent` with type `PROVENANCE_LABELS_STRIPPED` when detected.
   - Allow policy to downgrade trust for all downstream context segments derived from the API response.

3. Mark this as a known limitation in v1.0 release notes with specific language: "Provenance labels do not survive foundation-model API boundaries. Deploy Tessera at the agent level, not the model level, for end-to-end coverage."

**Timeline:** Document limitation and ship scanner in v0.13 (Phase 5). Re-evaluate in 2027-Q1 if provider landscape shifts.

**Responsibility:** Kenith Philip updates docs/architecture/threat-model-limitations.md and contributes tessera.scanners.ProvenceLabelDetector.

---

## Scenario 2: One Says Yes

**Trigger:** Exactly one provider (e.g., Anthropic) commits to sidecar support; the other two decline.

**Engineering Impact:**

Early adopters (agents using only the partner model) get full end-to-end provenance coverage. Mixed deployments (agents that call multiple models) get partial coverage.

**Action Path:**

1. Ship a Tessera extra: `tessera-signing-anthropic` (or equivalent) on PyPI. Include:
   - `tessera.signing.anthropic`: HTTP wrapper that injects/verifies sidecars on all Claude API calls.
   - Integration tests against Claude staging and production.
   - User guide: "If you use Claude, install tessera-signing-anthropic for end-to-end provenance tracking."

2. For non-partner models, apply Scenario 1 mitigation (detection scanner, label-strip events).

3. Update decision_log.md to show single "yes" decision and the contingency activated.

4. In public messaging, frame as: "Anthropic has pioneered provenance label support. We invite other providers to follow."

**Timeline:** Extra ships in v0.14 (Phase 6). Maintain parity with core Tessera release schedule.

**Responsibility:** Kenith Philip develops and maintains the extra. Community contributions welcome via GitHub.

---

## Scenario 3: Two or More Say Yes

**Trigger:** Two or more providers (e.g., Anthropic and OpenAI, or all three) commit to sidecar support.

**Engineering Impact:**

Majority of deployed agents get end-to-end provenance coverage. The sidecar becomes a de facto standard for foundation-model provenance.

**Action Path:**

1. Convene a working group: Tessera maintainers, the "yes" providers, and interested parties from the security research community. Scope: standardize the sidecar format and integrate it with existing standards efforts (IETF WIMSE, OpenTelemetry, SEP-1913).

2. File an IETF Internet-Draft (I-D) under the WIMSE (Workload Identity in Multi-System Environments) charter. Title: "HMAC-Signed Provenance Labels for LLM API Boundaries" or similar.

3. Tessera becomes the reference implementation for the draft. Update the spec in papers/two-primitives-for-agent-security-meshes.md to cite the I-D.

4. Coordinate a joint announcement with the "yes" providers: "Foundation models now preserve provenance labels for supply-chain integrity. This standard is open for other providers to adopt."

5. Ship core support in v0.14 (Phase 6) and mark the sidecar as stable for v1.0.

**Timeline:** Working group convenes 2026-10. I-D filed 2026-11. Core support ships v0.14.

**Responsibility:** Kenith Philip leads Tessera side. Providers handle their own implementation and public messaging.

**Risk:** If the I-D process stalls or providers diverge on implementation details, revert to Scenario 2 (one-off extras) and revisit standardization in 2027.

---

## Mixed Scenario: One Yes, One No, One Defers

**Trigger:** Providers give inconsistent responses (e.g., Anthropic yes, OpenAI no, Google "we will reconsider in 2027").

**Action Path:**

1. Activate Scenario 2 for the "yes" provider (ship tessera-signing-anthropic).
2. Activate Scenario 1 mitigation for the "no" provider (detection scanner, documentation).
3. For the "defer" provider, set a 12-month follow-up task in decision_log.md. No contingency activation until they respond.

**Timeline:** Same as Scenario 2.

---

## How to Activate Contingencies

1. Monitor decision_log.md for provider responses.
2. Compute the aggregate outcome (all-yes, one-yes, all-no, mixed).
3. File a GitHub issue in kenithphilip/Tessera with title: "Wave 4H contingency: [Outcome]".
4. In the issue, cite which sections of this file apply and what action is required.
5. Assign tasks to Kenith Philip (primary owner) and open contributions if applicable.

---

## Key Invariants

- If no provider says yes by 2026-09-30, Tessera ships v1.0 with documented limitations and a scanner that detects label-strip.
- If any provider says yes, Tessera ships that vendor's integration and invites others.
- If a majority says yes, standardization via IETF WIMSE is the primary goal for v1.x.
- All contingency activations are transparent: decision_log.md and GitHub issues document the outcome for the community.

---

## See Also

- decision_log.md: current provider decision status.
- proposal.md: technical details of the ask.
- letter_anthropic.md, letter_openai.md, letter_google.md: outreach templates.
