"""Tessera Rust bindings.

Pure-Rust implementations of the Tessera security primitives,
exposed via PyO3. Distribution name on PyPI is ``tessera-rs``;
import name is ``tessera_rs`` so this package can coexist with the
existing ``tessera`` Python package.

Submodule layout::

    from tessera_rs.policy import Policy
    from tessera_rs.context import Context
    from tessera_rs.scanners import injection_score, scan_unicode_tags
    from tessera_rs.audit import canonical_json, JsonlHashchainSink, make_replay_detail
    from tessera_rs.ssrf import SsrfGuard
    from tessera_rs.url_rules import UrlRulesEngine

Phase 3 (alpha.3) ships the smallest useful surface: zero-dependency
primitives that the AgentMesh adapter authors can drop in for the
fast path. Later phases expand coverage as more primitives stabilize.
"""

from tessera_rs._native import __version__

__all__ = ["__version__"]
