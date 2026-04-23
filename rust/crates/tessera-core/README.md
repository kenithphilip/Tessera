# tessera-core

Foundational types for the Tessera Rust workspace. Zero I/O, no
async, no transitive crates beyond `serde` + crypto primitives.

## What lives here

- `labels`: `TrustLabel`, `TrustLevel`, `Origin`, HMAC signer /
  verifier. Wire format byte-for-byte interoperable with
  `tessera.labels` in the Python reference.
- `context`: `LabeledSegment`, `Context`. The `min_trust`
  computation is the load-bearing security invariant: the policy
  engine evaluates tool calls against the minimum trust level
  across every segment.

Every other crate in the workspace depends on `tessera-core`. It
sits at the bottom of the one-way dependency graph:

```
tessera-gateway -> tessera-runtime -> tessera-policy -> tessera-core
                              +-> tessera-audit  -+
                              +-> tessera-scanners +
```

## Tests

24 unit tests covering label sign/verify round-trips,
constant-time comparison, byte-format pinning, and context
min_trust correctness on tainted segments.

## What this crate does NOT do

- No JSON I/O (that's `tessera-audit` for the audit-log path,
  `serde_json` for the rest).
- No network: this crate has no `tokio` or `reqwest` dep.
- No global state: every type is self-contained.
