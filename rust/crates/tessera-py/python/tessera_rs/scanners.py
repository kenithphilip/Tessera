"""Scanner functions and callback bridge.

Pure-Rust scanners:

- :func:`injection_score`  (heuristic injection score)
- :func:`scan_unicode_tags`  (hidden Unicode tag detection)

Python-callable bridge for "hard" scanners (PromptGuard,
Perplexity, PDFInspector, ImageInspector, CodeShield): register a
Python implementation under a stable name with
:func:`register_scanner`, then invoke through :func:`scan`. The
Rust gateway and AgentMesh adapters dispatch through the same
registry, so a single registration covers every consumer in the
process.

Example::

    from tessera_rs.scanners import register_scanner, scan

    def my_promptguard(text: str) -> dict:
        score = expensive_ml_call(text)
        return {
            "detected": score > 0.5,
            "score": score,
            "reason": "promptguard ML",
        }

    register_scanner("promptguard", my_promptguard)
    result = scan("promptguard", "Ignore previous instructions...")
"""

from __future__ import annotations

from tessera_rs._native import (
    injection_score,
    register_scanner,
    registered_scanners,
    scan,
    scan_unicode_tags,
    unregister_scanner,
)

__all__ = [
    "injection_score",
    "scan_unicode_tags",
    "register_scanner",
    "unregister_scanner",
    "registered_scanners",
    "scan",
]
