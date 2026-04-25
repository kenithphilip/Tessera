# Migration guide

Tessera releases follow SemVer; the v0.x line allows minor versions
to introduce new structural surfaces while preserving every existing
import path through shims. This document records the migrations
landed per release so callers can plan the upgrade.

## v0.12 to v0.13

### Removed

- ``tessera.claim_provenance`` (Wave 2L). The module's
  ``verify_response_provenance`` + ``ClaimGrounding`` +
  ``ProvenanceVerificationResult`` were absorbed into
  ``tessera.worker.recovery`` with unchanged behavior. The
  ``tessera.worker.recovery.from_claim_provenance`` shim lives at
  the new address as a stable alias (no DeprecationWarning).

  ```diff
  -from tessera.claim_provenance import verify_response_provenance
  +from tessera.worker.recovery import verify_response_provenance
  ```

### Added (no caller change required)

- ``tessera.delegation.DelegationToken`` gained three optional
  fields: ``mcp_audiences``, ``allowed_tools``,
  ``sensitivity_ceiling``. Default values keep the canonical
  signing form bit-identical for v0.12 tokens, so v0.13 verifies
  v0.12 tokens unchanged.
- ``tessera.action_critic.ActionReview`` and ``ArgShape`` are now
  ``extra="forbid"`` (Pydantic config). Pre-v0.13 callers that
  passed unknown fields silently had them dropped; v0.13 raises a
  ``ValidationError``. This is the structural enforcement that
  Wave 2A's adversarial suite pins.
- ``tessera.action_critic.RiskSignals`` gained
  ``action_impact: ActionImpact``. Defaults to
  ``ActionImpact.SIDE_EFFECT`` so existing callers keep working;
  the breaker fallback path uses the new field to choose between
  DENY (DESTRUCTIVE) and REQUIRE_APPROVAL (everything else).

### Adapter naming

- All five framework adapters added a ``Mesh*`` alias alongside the
  pre-existing ``Tessera*`` class name. Both names point to the
  same class:

  | Tessera name | Mesh alias (Wave 2H spec) |
  | --- | --- |
  | ``TesseraCallbackHandler`` | ``MeshCallbackHandler`` |
  | ``TesseraLangGraphGuard`` | ``MeshLangGraphGuard`` |
  | ``TesseraCrewCallback`` | ``MeshCrewCallback`` |
  | ``TesseraLlamaIndexHandler`` | ``MeshLlamaIndexHandler`` |
  | ``TesseraPydanticAIGuard`` | ``MeshPydanticAIGuard`` |

  Existing imports continue to work; new code should prefer the
  ``Mesh*`` names for compatibility with the framework upstream PRs
  (Wave 2H).

### New env vars (v0.13)

| Env var | Default | Purpose |
| --- | --- | --- |
| ``TESSERA_CRITIC`` | ``off`` | Critic mode: off / stub / on |
| ``TESSERA_CRITIC_LOCAL_MODEL`` | (auto) | Override LocalSmallCritic model |
| ``TOGETHER_API_KEY`` | (none) | LocalSmallCritic provider key |
| ``GROQ_API_KEY`` | (none) | LocalSmallCritic provider key |
| ``TESSERA_ALLOW_SHARED_CRITIC`` | (unset) | Opt-in for SamePlannerCritic |
| ``TESSERA_MCP_MIN_TIER`` | ``community`` | Minimum MCP trust tier |
| ``TESSERA_MCP_HMAC_KEY`` | (none) | HMAC key (hex) for HMAC-signed manifests |
| ``TESSERA_DEFENSE_TRUST_KEY`` | (32 zero bytes) | Default trust key for the AgentDojo defense adapter |
| ``TESSERA_EMBEDDER`` | (auto) | Override the embedder factory choice |

### New CLIs (v0.13)

- ``tessera mcp fetch <registry_url> [--min-tier=community|verified|attested] [--hmac-key=hex] [--out=path] [--allow-unverified]``
- ``tessera bench emit-scorecard --out=foo.intoto.jsonl --sign=hmac|sigstore [--audit-log=...] [--scanner-report=...] [--benchmark-run=...]``

### Behavioral changes

- The Action Critic top-level ``review()`` now runs a deterministic
  pre-check BEFORE any backend dispatch. Calls that violate
  origin_consistency, untrusted_arg_reasonable, or no_exfiltration
  are denied without paying any model latency. To bypass the
  pre-check (tests, integration code), invoke a backend directly
  via ``backend.review(action)``.
- ``ArgShape``, ``ActionReview``, ``LabelSummary``, ``RiskSignals``,
  ``CriticDecision`` all set ``extra="forbid"``. Unknown fields now
  raise.
- ``MCPTrustProxy`` gained ``upstream_resource_indicator`` and
  ``inbound_token_audience`` fields plus three helper methods
  (``enforce_inbound_audience``, ``upstream_token_request``,
  ``reject_passthrough``). All optional; deployments that don't set
  them keep the v0.12 behavior.

## Earlier releases

| From | To | Notes |
| --- | --- | --- |
| v0.11 | v0.12 | New `tessera.taint`, `tessera.action_critic`, `tessera.worker` packages. Phase 0 SARIF + OTel additions are additive. See `docs/CHANGELOG.md`. |
| v0.10 | v0.11 | Linux wheels + rate limiter binding + PyScanner registry + deeper auto-swap. |
