# tessera-audit

Append-only, hash-chained audit log. Mirrors `tessera.audit_log`
from the Python reference; on-disk format is byte-for-byte
interoperable.

## What lives here

- `JsonlHashchainSink`: writer-thread-backed sink. Per-`append`
  hash computation runs on the caller under a tiny mutex; the
  formatted line is queued to a `crossbeam_channel::bounded(4096)`
  channel that a dedicated writer thread drains and `fsync`s.
- `verify_chain` / `verify_chain_mmap`: walk the JSONL file and
  validate the hash chain plus the optional truncation seal. Use
  the mmap variant for files larger than ~100 MB.
- `iter_records`: stream `ChainedRecord`s for offline analysis
  (replay, builder).
- `ReplayEnvelope`: shared shape for the `detail["replay"]`
  payload that drives `tessera-policy::replay` and `builder`.
- `canonical_json`: deterministic JSON serializer matching
  Python's `json.dumps(sort_keys=True, separators=(",", ":"))`.
  Reused across the workspace for any wire-format primitive that
  needs cross-language byte-equivalence.

## Cross-language interop

The on-disk format is the public contract. A chain written by
this crate verifies in `tessera.audit_log.verify_chain` and vice
versa, including the optional HMAC truncation seal. Pinned by
`crates/tessera-gateway/tests/python_audit_interop.rs`.

## Tests

22 unit tests covering high-throughput appends, writer-thread
join on drop, seal-key validation, sequence-gap detection, hash
mismatch on tampered records, plus 6 dedicated `verify_chain_mmap`
parity tests against the buffered path.
