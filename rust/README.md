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
