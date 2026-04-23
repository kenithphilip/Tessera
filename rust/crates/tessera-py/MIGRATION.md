# Migration guide: `tessera` (Python) to `tessera_rs` (Rust)

For Python adapter authors who have integrated the
[`tessera`](https://pypi.org/project/tessera-mesh/) Python primitives
and want to swap the hot-path calls for the Rust-backed
[`tessera-rs`](https://pypi.org/project/tessera-rs/) wheel.

The two packages coexist (different import names: `tessera` vs
`tessera_rs`), so you can mix them: keep `tessera` for the bits
the wheel does not yet expose, and use `tessera_rs` for everything
on the request path.

## TL;DR (one paragraph that unblocks 80% of users)

```python
# Before (pure Python, ~50 us per evaluate)
from tessera.policy import Policy
from tessera.context import Context
policy = Policy()
policy.require_tool("send_email", trust_level=100)  # USER

# After (Rust wheel, ~110 ns per evaluate, ~450x faster)
from tessera_rs.policy import Policy
from tessera_rs.context import Context
policy = Policy()
policy.require_tool("send_email", level=100)
```

The Python-side API is intentionally close to the original. Where
keyword-argument names differ, the Rust wheel uses the shorter
form.

## Side-by-side import map

| Python (`tessera`)                            | Rust wheel (`tessera_rs`)                        |
|-----------------------------------------------|--------------------------------------------------|
| `from tessera.policy import Policy`           | `from tessera_rs.policy import Policy`           |
| `from tessera.context import Context`         | `from tessera_rs.context import Context`         |
| `from tessera.scanners.heuristic import injection_score` | `from tessera_rs.scanners import injection_score` |
| `from tessera.scanners.unicode import scan_unicode_tags` | `from tessera_rs.scanners import scan_unicode_tags` |
| `from tessera.audit_log import JSONLHashchainSink` | `from tessera_rs.audit import JsonlHashchainSink` |
| `from tessera.audit_log import make_replay_detail` | `from tessera_rs.audit import make_replay_detail` |
| `from tessera.audit_log import canonical_json` | `from tessera_rs.audit import canonical_json`    |
| `from tessera.ssrf_guard import SsrfGuard`    | `from tessera_rs.ssrf import SsrfGuard`          |
| `from tessera.url_rules import UrlRulesEngine` | `from tessera_rs.url_rules import UrlRulesEngine` |

## Per-API differences worth flagging

### `Context.add_segment`

The Rust wheel takes plain values, no `LabeledSegment` object.
The HMAC signing happens inside the wheel using a per-`Context`
key.

```python
# tessera (Python)
from tessera.labels import HmacSigner, Origin, TrustLevel, make_segment
signer = HmacSigner(key=b"...")
ctx = Context()
ctx.add(make_segment("user said hi", Origin.USER, "alice", signer))

# tessera_rs (Rust wheel)
from tessera_rs.context import Context
ctx = Context(signing_key=b"...")        # 32-byte key
ctx.add_segment(
    "user said hi",
    origin="user",                        # one of: user, system, tool, memory, web
    principal="alice",
    trust_level=100,                      # USER
)
```

### `Policy.evaluate` return shape

Both return a dict-like decision; the Rust wheel returns a real
Python `dict`:

```python
decision = policy.evaluate(ctx, "send_email")
# {
#   "allowed": True / False,
#   "reason": "min_trust meets required floor",
#   "tool": "send_email",
#   "required_trust": 100,
#   "observed_trust": 100,
# }
```

The `reason` string is shorter than Python's because the numeric
detail is in `required_trust` and `observed_trust`. If you need
the long-form reason, build it client-side from those fields.

### `SsrfGuard.check_url`

```python
# tessera (Python)
from tessera.ssrf_guard import SsrfGuard
guard = SsrfGuard()
decision = guard.check_url("http://169.254.169.254/")
# decision.allowed -> bool, decision.findings -> list[SsrfFinding]

# tessera_rs (Rust wheel)
from tessera_rs.ssrf import SsrfGuard
guard = SsrfGuard()
decision = guard.check_url("http://169.254.169.254/")
# {"allowed": False, "findings": ["cloud_metadata"]}
```

### `UrlRulesEngine`

```python
# tessera_rs (Rust wheel)
from tessera_rs.url_rules import UrlRulesEngine
engine = UrlRulesEngine()
engine.add_prefix(name="github.read", prefix="https://api.github.com/", action="allow")
engine.add_prefix(name="admin.deny", prefix="https://api.github.com/admin/", action="deny")
decision = engine.evaluate("https://api.github.com/repos/foo/bar", "GET")
# {"verdict": "allow", "rule_id": "github.read", "method": "GET", "url": "..."}
```

### `JsonlHashchainSink` and `make_replay_detail`

Hash-chain audit log. Both packages produce byte-for-byte
identical output, so a chain written by one verifies in the other.

```python
# tessera_rs (Rust wheel)
from tessera_rs.audit import JsonlHashchainSink, make_replay_detail
import json
sink = JsonlHashchainSink("/var/log/tessera/audit.jsonl", fsync_every=10)
detail = make_replay_detail(
    trajectory_id="t-abc",
    tool_name="send_email",
    args_json=json.dumps({"to": "alice@example.com"}),
    user_prompt="email alice the agenda",
    decision_allowed=True,
    decision_source="rust-policy",
)
seq = sink.append(
    timestamp="2026-04-23T00:00:00+00:00",
    kind="policy_deny",
    principal="alice",
    detail_json=json.dumps(detail),
)
```

The Rust wheel takes JSON strings (`args_json`, `detail_json`)
instead of Python dicts to keep the FFI surface narrow. Use
`json.dumps()` to serialize before the call.

## Surface NOT in the wheel yet

The wheel ships a minimum useful surface in 0.8.0. The following
Python primitives have no Rust binding yet (use the Python package
directly):

- Sensitivity / IFC (HighWaterMark, OutboundPolicy)
- Ratelimit (TokenBudget, ToolCallRateLimit)
- Evidence bundles (HMAC and JWT)
- Provenance envelopes / manifests
- Delegation tokens
- Replay (LabelStore, run_replay)
- Policy builder (analyze, score_proposal)
- SARIF correlation
- Approval gate
- Encrypted sessions
- LLM guardrail
- Most scanners other than `injection_score` and `scan_unicode_tags`

These are all implemented in the Rust workspace; later wheel
releases will re-export them. The roadmap is in
`~/.claude/plans/buzzing-baking-waterfall.md` (Phase 7 +).

## Performance reference

Microbench numbers from the Rust workspace (Apple M3 Pro, release
profile + LTO + mimalloc; full table at `rust/bench/baseline.md`):

| Operation                          | Python (~)   | Rust (~)  | Speedup |
|------------------------------------|--------------|-----------|---------|
| `Policy.evaluate` (allow path)     | 50 us        | 110 ns    | ~450x   |
| `make_segment` (sign + wrap)       | 8 us         | 784 ns    | ~10x    |
| `injection_score` (heuristic)      | 20 us        | <1 us     | >20x    |
| Audit log append (no fsync)        | 80 us        | 34 us     | ~2.4x   |
| URL rules evaluate (allow hit)     | n/a          | 78 ns     | n/a     |
| SSRF guard (literal IP)            | n/a          | 977 ns    | n/a     |

Python numbers are from `benchmarks/microbenchmarks.md` in the
`tessera-mesh` repo. Take all comparisons with appropriate salt:
loopback / single-host / synthetic. Production p99 depends on
your gateway's network stack.

## Common gotchas

1. **Import name has an underscore**: `tessera_rs`, not
   `tessera-rs`. PyPI distribution name uses the hyphen
   (`tessera-rs`); Python import name uses the underscore. This
   keeps it disjoint from the existing `tessera` package.

2. **HMAC keys are bytes, not strings**: pass `b"..."` not `"..."`.
   The wheel rejects non-bytes keys at construction.

3. **trust_level is an int**, not an enum: `100` for USER, `50`
   for TOOL, `0` for UNTRUSTED, `200` for SYSTEM. The values match
   the Python `TrustLevel` IntEnum exactly.

4. **No `make_segment` constructor**: use `Context.add_segment`,
   which signs internally with the per-`Context` key.

5. **`detail_json` is a string**: `JsonlHashchainSink.append` and
   `make_replay_detail` take pre-serialized JSON to keep the FFI
   surface narrow. Most callers wrap the call in their own helper
   that does the `json.dumps()`.

## Testing the swap

The smoke test that confirms `tessera_rs` is wired up:

```python
from tessera_rs import __version__
from tessera_rs.policy import Policy
from tessera_rs.context import Context

print("tessera_rs", __version__)

ctx = Context(signing_key=b"k" * 32)
ctx.add_segment("user input", origin="user", principal="alice", trust_level=100)
assert ctx.min_trust == 100

policy = Policy()
policy.require_tool("send_email", level=100)
decision = policy.evaluate(ctx, "send_email")
assert decision["allowed"] is True
print("OK")
```

If the import errors, you probably installed an architecture for
which we did not build a wheel. The CI matrix covers
manylinux2014 (x86_64, aarch64), macOS (x86_64, aarch64), and
Windows (x64) for cp310 / cp311 / cp312. Outside that matrix, fall
back to building from sdist with `pip install --no-binary
tessera-rs`.
