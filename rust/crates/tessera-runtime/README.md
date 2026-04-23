# tessera-runtime

Async runtime surfaces. Per-session context store, approval gate,
session encryption, LLM guardrail, SARIF event sink, LLM-driven
policy proposer.

## What lives here

Core surfaces:

- `session_context`: per-session `Context` store with TTL + LRU
  eviction. Backed by `dashmap` for sharded concurrent reads.
- `sessions`: encrypted in-memory pending-approval store.
  AES-256-GCM with HKDF-SHA256 key derivation.
- `approval`: tokio oneshot per pending approval keyed by request
  id, plus an HMAC-SHA256 webhook signer.
- `sarif_sink`: thread-safe SARIF 2.1.0 emitter for SecurityEvents.
  Suitable for upload to GitHub Code Scanning.

LLM-touching surfaces:

- `llm_client`: `LlmClient` async trait + `CannedLlmClient` for
  tests. Provider-agnostic; transports plug in via a Rust impl
  (`ReqwestLlmClient` ships in `guardrail`) or via PyO3 callback
  to a Python SDK.
- `guardrail`: optional LLM-based fallback classifier. Cache,
  circuit breaker, structured `GuardrailDecision` output.
- `builder_llm`: LLM-driven proposer. Constrained template set
  (tighten / loosen / mark_read_only / register_tool); wraps a
  breaker; returns a `Vec<tessera_policy::builder::Proposal>` so
  callers score with the existing deterministic machinery.

Telemetry:

- See `tessera-gateway::telemetry` for the OTel + tracing-subscriber
  wire-up. The runtime crate stays transport-free.

## Tests

101 unit tests across all modules. Sessions has wire-format tests
for the AES-256-GCM ciphertext (different from Python Fernet;
cross-runtime sessions are not supported in 0.8.0).

## Performance notes

- `session_context` uses DashMap with the default 32-shard layout
  (ncpus * 4); concurrent reads scale linearly.
- `ReqwestLlmClient::with_defaults` builds a `reqwest::Client`
  with `pool_max_idle_per_host=1000`, 30s connect, 60s request,
  HTTP/2 over ALPN.
