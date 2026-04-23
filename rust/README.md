# Tessera Rust workspace

Cargo workspace that hosts the Rust data-plane implementation of the
Tessera primitives. The workspace lands in v0.8.0-alpha.1 as the
foundation for the multi-phase Rust port plan; v0.7.x shipped a
single `tessera-gateway` crate with all primitives inlined.

The long-term goal is the same as v0.7.x: prove the Tessera
primitives port cleanly to a production-grade Rust data plane, then
contribute the load-bearing pieces upstream to
[agentgateway](https://agentgateway.dev/). The workspace split makes
that contribution path easier (smaller, focused crates) and unlocks
the `tessera_rs` PyO3 wheel so Python adapter authors get a fast
path without reimplementing primitives.

## Workspace layout

```
rust/
  Cargo.toml                  workspace root, shared release profile and lints
  Cargo.lock
  bench/                      baseline microbench numbers and spike notes
  crates/
    tessera-core/             labels, context, no I/O, no async
    tessera-scanners/         (Phase 2) regex / Aho-Corasick scanners + Scanner trait
    tessera-audit/            hash-chained audit log, sinks, verifier
    tessera-policy/           taint-floor policy, SSRF guard, URL rules
                              (Phase 2 adds sensitivity, ratelimit, evidence,
                              provenance, mcp_baseline, delegation, compliance)
    tessera-runtime/          session_context (Phase 4 adds sessions, approval,
                              guardrail)
    tessera-gateway/          axum app, TLS, SPIFFE, control plane, endpoints
    tessera-bench/            criterion microbenches, (Phase 5) load harness binary
    tessera-py/               (Phase 3) PyO3 bindings, single wheel `tessera-rs`
                              (added in Phase 3)
```

Dependency direction is one-way:

```
tessera-gateway -> tessera-runtime -> tessera-policy -> tessera-core
                                  +-> tessera-audit  -+
                                  +-> tessera-scanners +
tessera-py     -> tessera-runtime (re-exports core / policy / audit / scanners)
tessera-bench  -> tessera-policy / tessera-audit / tessera-runtime (microbench)
                  + reqwest (Phase 5 load harness, out-of-process)
```

`tessera_gateway::*` re-exports every former path (`labels`,
`context`, `policy`, `session_context`, `audit_log`, `ssrf_guard`,
`url_rules`) so existing embedders keep building unchanged. See
`crates/tessera-gateway/src/lib.rs`.

## v0.8.0-rc.1 (Phase 5 complete)

Phase 5 ships the load test harness. Every perf claim now has a
measured number behind it, reproducible from any operator's host.

New in `tessera-bench`:

- `tessera-bench` binary with subcommands `evaluate`, `label`,
  `audit-verify`, `mixed`, `sustained`, `compare`. Built on
  `tokio + reqwest + hdrhistogram` (custom, not `wrk`, so we get
  correlated p50 / p95 / p99 / p99.9 across endpoint mixes
  without Lua).
- 5 workloads in `crates/tessera-bench/src/workloads/`:
  `evaluate`, `label`, `audit-verify`, `mixed` (60/30/10 split),
  `sustained` (long-duration soak).
- `compare` subcommand drives the same workload against two
  targets and emits a side-by-side report. Designed for the
  Python AgentMesh proxy vs Rust gateway comparison.
- Markdown summary to stdout; optional append to a results file
  (`--report-file`); optional CSV drop for Grafana ingestion
  (`--csv-dir`, filename `<git-sha>-<rfc3339>.csv`).
- `crates/tessera-bench/examples/spawn_primitives.rs` binds the
  primitives router on `127.0.0.1:18081` so the harness can be
  driven against a real tokio listener without standing up the
  full `tessera-gateway` binary.

Initial baseline (Apple M3 Pro, single-host loopback, in-process
primitives router):

| Workload     | Concurrency | RPS     | p50 ms | p95 ms | p99 ms |
|--------------|-------------|---------|--------|--------|--------|
| evaluate     | 100         | 160,736 | 0.65   | 1.20   | 1.51   |
| audit-verify | 100         | 199,145 | 0.52   | 0.90   | 1.16   |
| mixed        | 100         | 5,170   | 28.59  | 59.84  | 73.47  |

Full methodology, reproduce recipe, and CSV column spec at
`rust/bench/results.md`.

Test status: 750 passing across the workspace (Phase 4: 734,
Phase 5: +16). All 8 runner / report unit tests plus 3 in-process
smoke tests against the gateway router; the smoke tests fail
loudly if the harness ever loses the ability to drive a real
listener.

## v0.8.0-beta.1 (Phase 4 complete)

Phase 4 closes the data-path coverage. Hot-path code that
previously required Python on the request now runs entirely in
Rust. The four hard-tier modules and the PyO3 callback bridge for
ML scanners ship together with three medium perf wins.

New modules in `tessera-runtime`:

| Module        | Tests | Notes                                                                   |
|---------------|-------|-------------------------------------------------------------------------|
| `llm_client`  | 5     | `LlmClient` trait + `CannedLlmClient` for tests                         |
| `guardrail`   | 20    | LLM-based fallback classifier with cache, breaker, ReqwestLlmClient     |
| `approval`    | 18    | tokio oneshot per pending request + WebhookSigner (HMAC-SHA256)         |
| `sessions`    | 16    | AES-256-GCM with HKDF key derivation; new wire format                   |
| `builder_llm` | 14    | LLM-driven policy proposer (constrained templates only)                 |

Plan deviation worth flagging: the plan put `builder_llm` in
`tessera-policy`, but that creates a `policy -> runtime` cycle (it
needs `LlmClient` and the breaker, both async-leaning). It moved to
`tessera-runtime` instead, which preserves the one-way dep
direction. The deterministic `tessera_policy::builder` is unchanged
and still the foundation; `builder_llm` layers on top.

PyO3 callback bridge (`tessera-scanners`):

- `PyScanner` trait wraps a host-supplied callable. Scanner names
  (`promptguard`, `perplexity`, `pdf_inspector`, `image_inspector`,
  `codeshield`) are exported as `KNOWN_SCANNERS`. The Rust crate
  ships `NoOpScanner` as the default; the gateway can register
  Python implementations from a host process via the `pyo3-bridge`
  feature.
- The `pyo3-bridge` feature is OFF by default so plain
  `cargo build` / `cargo test` continue to work without the Python
  toolchain. Enable with `--features pyo3-bridge` to compile the
  `PyCallbackScanner` adapter.

Medium perf wins:

- `JsonlHashchainSink` now uses a `crossbeam_channel::bounded(4096)`
  SPSC channel between `append` (fast path) and a dedicated writer
  thread that batches `fsync`. Chain-hash computation stays serial
  under a tiny `Mutex<ChainState>` (only `last_seq + last_hash`).
  `Drop` sends a shutdown sentinel and joins the writer so every
  in-flight record is on disk. New `flush()` method blocks until
  enqueued records are written, useful for tests and write-then-read
  callers.
- `SessionContextStore` now uses `DashMap` instead of
  `parking_lot::Mutex<HashMap>`. Concurrent reads scale across the
  default 32-shard layout (ncpus * 4); LRU and TTL paths are O(n)
  but no longer take a global lock.
- `ReqwestLlmClient::with_defaults` builds a tuned `reqwest::Client`
  with `pool_max_idle_per_host = 1000`, 30s connect timeout, 60s
  request timeout, HTTP/2 over ALPN.

Total test count: **734 passing across the workspace** (Phase 3:
646, Phase 4: +88). Cross-language interop tests from Phase 2
continue to pass; the SPSC change to the audit log preserves
byte-for-byte format compatibility (verified by
`python_audit_interop`).

## v0.8.0-alpha.3 (Phase 3 complete)

Phase 3 lands the moderate-tier primitives, the four moderate
scanners, and the first PyO3 wheel.

New in `tessera-policy`:

| Module     | Tests | Notes                                                                     |
|------------|-------|---------------------------------------------------------------------------|
| `replay`   | 19    | replays audit history against a candidate `PolicyFn` callable             |
| `builder`  | 11    | analyzes audit history, proposes ToolRequirement edits, scores via replay |
| `sarif`    | 10    | Agent Audit SARIF correlation against runtime events                      |

`ReplayEnvelope` was added to `tessera-audit` so audit consumers
have one canonical type for the `detail["replay"]` payload.

New in `tessera-runtime`:

| Module       | Tests | Notes                                                |
|--------------|-------|------------------------------------------------------|
| `sarif_sink` | 10    | thread-safe `SecurityEvent` collector that emits SARIF 2.1.0 |

New in `tessera-scanners`:

| Module           | Tests | Notes                                                 |
|------------------|-------|-------------------------------------------------------|
| `pii`            | 16    | regex-only PII detector (Presidio backend deferred)   |
| `binary_content` | 23    | magic-byte + encoding pattern detection (9 categories)|
| `rag`            | 18    | RAG retrieval guard, pattern tracker, anomaly checker |
| `supply_chain`   | 25    | typosquat + confusables + lockfile + install patterns |

Shared types added to `tessera-scanners` for the structured
scanners: `Severity`, `ScanFinding`, `ScanResult`, `combine`.

First PyO3 wheel (`tessera-py`):

- Distribution name `tessera-rs` on PyPI.
- Import name `tessera_rs` (underscore keeps it disjoint from the
  existing `tessera` Python package).
- Surface in alpha.3: `tessera_rs.policy.Policy`,
  `tessera_rs.context.Context`, `tessera_rs.scanners.injection_score`,
  `tessera_rs.scanners.scan_unicode_tags`,
  `tessera_rs.audit.canonical_json`, `JsonlHashchainSink`,
  `make_replay_detail`, `tessera_rs.ssrf.SsrfGuard`,
  `tessera_rs.url_rules.UrlRulesEngine`.
- Build: `maturin develop` from `crates/tessera-py/`. The crate is
  a workspace member but excluded from `default-members` because
  the cdylib needs Python at link time; `cargo build` and
  `cargo test --workspace` continue to work without the Python
  toolchain.
- CI: `.github/workflows/wheels.yml` builds wheels for cp310 /
  cp311 / cp312 across manylinux2014 (x86_64, aarch64), macOS
  (x86_64, aarch64), and Windows (x64). TestPyPI publishes on
  every merge to main; PyPI publishes on tag push (gated by the
  `pypi` GitHub Environment, which requires manual approval per
  the plan's release cadence).

Total test count: **646 passing across the workspace** (Phase 2:
514, Phase 3: +132). The Python interop tests from Phase 2 still
verify byte-for-byte wire-format compatibility for evidence,
provenance, delegation, and canary.

## v0.8.0-alpha.2 (Phase 2 complete)

Phase 2 ports the trivial-tier primitives and scanners. All eight
primitives in `tessera-policy` and all nine scanners in
`tessera-scanners` are now pure-Rust with byte-for-byte
cross-language interop on every wire-format primitive.

Primitives ported (`tessera-policy`):

| Module             | Tests | Mirrors Python                    | Wire format                           |
|--------------------|-------|-----------------------------------|---------------------------------------|
| `compliance`       | 24    | `tessera.compliance`              | NIST/CWE/OWASP tables + chained log   |
| `delegation_intent`| 12    | `tessera.delegation_intent`       | regex prompt detection                |
| `mcp_baseline`     | 14    | `tessera.mcp_baseline`            | SHA-256 tool snapshot, JSON I/O       |
| `sensitivity`      | 32    | `tessera.sensitivity`             | IFC HWM, classifier rules             |
| `ratelimit`        | 18    | `tessera.ratelimit`               | sliding-window TokenBudget + rate     |
| `evidence`         | 12    | `tessera.evidence`                | HMAC-SHA256 over canonical JSON       |
| `provenance`       | 14    | `tessera.provenance`              | HMAC-SHA256 over canonical JSON       |
| `delegation`       | 13    | `tessera.delegation`              | HMAC-SHA256 + scope narrowing         |

Scanners ported (`tessera-scanners`):

| Module               | Tests | Mirrors Python                      | Tech                          |
|----------------------|-------|-------------------------------------|-------------------------------|
| `unicode`            | 9     | `tessera.scanners.unicode`          | tag-block detection           |
| `tool_shadow`        | 14    | `tessera.scanners.tool_shadow`      | strsim Levenshtein            |
| `directive`          | 29    | `tessera.scanners.directive`        | regex (13 patterns)           |
| `heuristic`          | varies| `tessera.scanners.heuristic`        | aho-corasick + RegexSet       |
| `intent`             | 17    | `tessera.scanners.intent`           | regex + cross-check           |
| `tool_descriptions`  | 27    | `tessera.scanners.tool_descriptions`| regex categories              |
| `tool_output_schema` | 27    | `tessera.scanners.tool_output_schema`| globset                      |
| `prompt_screen`      | 10    | `tessera.scanners.prompt_screen`    | composes the above            |
| `canary`             | 14    | `tessera.scanners.canary`           | hex tokens (no HMAC binding)  |

Cross-language interop (Rust ↔ Python both ways):

- `tests/python_evidence_interop.rs` (3 tests): Rust signs, Python verifies; Python signs, Rust verifies; identical SHA-256 digest.
- `tests/python_provenance_interop.rs` (3 tests): same pattern for `ContextSegmentEnvelope` and `PromptProvenanceManifest`.
- `tests/python_delegation_interop.rs` (2 tests): same pattern for `DelegationToken`.
- `tests/python_canary_interop.rs` (4 tests): format compatibility (`[CANARY:hex]` and `[ref:hex]`).

Total test count: **514 passing across the workspace** (Phase 1: 176, Phase 2: +338). Cross-language audit-log interop from v0.7.x still passes unchanged.

Phase 1 deliverables that carry forward unchanged:
- 7-crate workspace with one-way deps
- mimalloc global allocator
- ArcSwap on hot-path policy / URL-rules state
- HTTP/2 ALPN on TLS listener
- criterion microbench harness with checked-in baseline

## Running the suite

```bash
cd /Users/kenith.philip/Tessera/rust
cargo test --workspace
cargo bench -p tessera-bench --bench policy_eval -- \
    --warm-up-time 1 --measurement-time 3
```

Numbers from a clean run on Apple M3 Pro (rustc 1.94, release
profile + lto = "thin"):

| Workload                          | Time      | Notes                                                |
|-----------------------------------|-----------|------------------------------------------------------|
| `policy_evaluate_clean_allow`     | 110 ns    | 1-segment context, allow path                        |
| `policy_evaluate_tainted_deny`    | 127 ns    | 2-segment context, web taint forces deny             |
| `policy_evaluate_10_segments`     | 136 ns    | realistic session shape                              |
| `label_sign`                      | 764 ns    | TrustLabel + HMAC-SHA256                             |
| `label_verify`                    | 698 ns    | constant-time compare                                |
| `make_segment`                    | 784 ns    | sign + LabeledSegment wrap                           |
| `session_store_get_warm`          | 73 ns     | hot-path lookup                                      |
| `session_store_get_new`           | 44 us     | format + alloc + LRU bookkeeping                     |
| `audit_append_no_fsync`           | 34 us     | canonical_json + sha256 + file write                 |
| `ssrf_loopback_literal`           | 977 ns    | `http://127.0.0.1/`                                  |
| `ssrf_encoded_loopback`           | 962 ns    | `http://0x7f000001/` (hex IP path)                   |
| `ssrf_cloud_metadata`             | 1057 ns   | `http://169.254.169.254/...`                         |
| `url_rules_allow_hit`             | 78 ns     | prefix match against single allow rule               |
| `url_rules_deny_hit`              | 78 ns     | prefix match where deny wins                         |
| `url_rules_no_match`              | 51 ns     | walk rules, fall through to default                  |

The headline `Policy.evaluate` workload is roughly 450x faster than
the Tessera Python reference (~50 us per call). Numbers carry over
from v0.7.x with mimalloc + ArcSwap shaving a few nanoseconds; the
workspace split is behavior-neutral.

## Plan and phases

The full plan lives at
`~/.claude/plans/buzzing-baking-waterfall.md`. Summary:

| Phase | Target window | Pre-release       | Scope                                                                |
|-------|---------------|-------------------|----------------------------------------------------------------------|
| 1     | week 1        | `0.8.0-alpha.1`   | workspace split + drop-in perf wins (this release)                   |
| 2     | weeks 2-3     | `0.8.0-alpha.2`   | trivial primitives + 9 trivial scanners                              |
| 3     | weeks 4-5     | `0.8.0-alpha.3`   | moderate tier + first PyO3 wheel to TestPyPI                         |
| 4     | week 6        | `0.8.0-beta.1`    | hard tier + medium perf wins + PyO3 callback for ML scanners         |
| 5     | week 7        | `0.8.0-rc.1`      | tessera-bench load harness, Rust vs Python comparison numbers        |
| 6     | week 8        | `0.8.0`           | PyO3 wheel to public PyPI + PGO build                                |
| 7     | weeks 9-10    | `0.9.0-alpha.1`   | OpenTelemetry-native + workspace housekeeping                        |

Each phase ends with green tests and a tagged pre-release, so the
work is shippable at any phase boundary.

## Per-crate documentation

`crates/tessera-gateway/README.md` carries the gateway-specific
endpoint surface, configuration knobs, and legacy chat / A2A surface
documentation; that crate is the only one with an HTTP listener and
an external configuration story. Other crates document themselves
through rustdoc; run `cargo doc --workspace --open` for the rendered
view.
