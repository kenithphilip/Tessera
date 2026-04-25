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
    from tessera_rs.cel import CelRule, CelPolicyEngine
    from tessera_rs.ratelimit import ToolCallRateLimit
    from tessera_rs.label import ProvenanceLabel  # v1.0 wave 4B

The v1.0 surface is frozen. Later 1.x releases will extend
coverage without breaking shape; see
``Tessera/docs/api_stability/v1.0_freeze.md`` for the contract.
"""

from tessera_rs._native import __version__

__all__ = ["__version__"]
