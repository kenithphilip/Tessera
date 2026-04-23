# tessera-policy

Taint-tracking policy engine plus the operator-time tools that
consume the audit log it writes. All synchronous, no I/O beyond
file reads in the replay / builder paths.

## What lives here

Core policy:

- `policy`: `Policy`, `Decision`, `ResourceRequirement`. The
  `evaluate` hot path is now zero-alloc on the allow / deny path
  thanks to `Cow<'static, str>` reasons.
- `ssrf_guard`: SSRF guard with encoded-IP decoding (hex,
  decimal, octal, mixed).
- `url_rules`: deterministic URL rule engine (prefix / suffix /
  glob / regex), allow / deny verdicts.

Wire-format primitives (cross-language interop):

- `evidence`: HMAC-SHA256 signed evidence bundles.
- `provenance`: HMAC-SHA256 signed segment envelopes + assembled
  prompt manifests.
- `delegation`: HMAC-SHA256 delegation tokens with scope
  narrowing.
- `compliance`: NIST/CWE/OWASP enrichment + in-memory
  hash-chained audit log.

Other primitives:

- `sensitivity`: 4-level IFC lattice + classifier rules + HWM
  store + outbound policy.
- `ratelimit`: per-principal token budget + per-session tool
  call rate limit (window + burst + lifetime caps).
- `delegation_intent`: regex prompt detection (delegation phrase
  patterns).
- `mcp_baseline`: MCP server tool drift detection via SHA-256
  snapshots.

Operator-time tools:

- `replay`: `LabelStore`, `iter_replay_cases`, `run_replay`.
  Replays a candidate `PolicyFn` against a recorded audit log.
- `builder`: deterministic policy-edit proposer. Reads audit
  history + labels, emits proposals, scores via `replay`.
- `sarif`: Agent Audit SARIF correlation against runtime events.

## Cross-language interop

Four wire-format primitives have byte-for-byte interop tests
against the Python reference (lives in
`crates/tessera-policy/tests/`):

- `python_evidence_interop.rs`
- `python_provenance_interop.rs`
- `python_delegation_interop.rs`

(Canary interop lives in `tessera-scanners`.)

## Tests

245 unit tests + 8 cross-language interop tests.
