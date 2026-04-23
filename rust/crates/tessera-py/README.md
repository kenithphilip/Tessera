# tessera-rs

PyO3 bindings for the Tessera Rust workspace, distributed as
`tessera-rs` on PyPI and imported as `tessera_rs` in Python.

The underscore in the import name keeps this disjoint from the
existing `tessera` Python package, so the two coexist without
collisions.

## Status

Phase 3 alpha (`0.8.0a3`). Ships the smallest useful surface:

```python
from tessera_rs.policy import Policy
from tessera_rs.context import Context
from tessera_rs.scanners import injection_score, scan_unicode_tags
from tessera_rs.audit import canonical_json, JsonlHashchainSink, make_replay_detail
from tessera_rs.ssrf import SsrfGuard
from tessera_rs.url_rules import UrlRulesEngine
```

Later phases expand the surface to cover sensitivity, ratelimit,
evidence, provenance, delegation, and the rest of the moderate-tier
primitives ported in Phase 2 + 3.

## Build locally

```bash
cd /Users/kenith.philip/Tessera/rust/crates/tessera-py
maturin develop  # builds and installs into the current venv
python -c "from tessera_rs.policy import Policy; print(Policy().__class__)"
```

CI builds wheels via `messense/maturin-action` for cp310, cp311,
cp312 across manylinux2014 / macos-arm64 / macos-x86_64 / win64.
TestPyPI publishes happen on every merge to main during alpha;
public PyPI publish is gated on Phase 6.

## Why a separate crate?

The PyO3 layer is opt-in: building it requires the Python
development headers and the `maturin` toolchain. Keeping it in its
own crate means contributors who only touch the Rust data plane
do not need a Python toolchain installed.
