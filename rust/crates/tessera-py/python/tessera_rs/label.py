"""Provenance label surface (`ProvenanceLabel`).

v1.0 wave 4B: bit-identical Rust binding for
:class:`tessera.taint.label.ProvenanceLabel`. The Python class
remains the canonical source of truth for in-process Python
callers; this shim re-exports the PyO3 wrapper so the AgentMesh
fast-path and cross-language consumers can construct and
serialize labels without paying the Python-import cost.

Example::

    from tessera_rs.label import ProvenanceLabel

    user = ProvenanceLabel.trusted_user("alice")
    tool = ProvenanceLabel.untrusted_tool_output(
        "seg-1", "https://example.com/api"
    )
    joined = user.join(tool)
    print(joined.integrity_numeric())  # 2 (UNTRUSTED)
    print(joined.to_canonical_json())
"""

from __future__ import annotations

from tessera_rs._native import ProvenanceLabel

__all__ = ["ProvenanceLabel"]
