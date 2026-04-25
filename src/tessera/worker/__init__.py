"""Worker-side provenance recovery and report-shape helpers.

The Worker model (see :mod:`tessera.quarantine`) returns a Pydantic
report whose fields have been serialized through a JSON boundary that
strips :class:`tessera.taint.tstr.TaintedStr` labels. The
:mod:`tessera.worker.recovery` module re-attaches per-field
provenance labels by matching field values against the untrusted
context segments the worker actually saw, with a documented
over-taint fallback when no match is found.

This package replaces the v0.7-era ``tessera.claim_provenance``
heuristic that grounded model claims by sentence-level token overlap.
The legacy module is preserved as a deprecated shim re-exporting the
same callable; new code should import from
:mod:`tessera.worker.recovery`. ``tessera.claim_provenance`` is
scheduled for deletion in Phase 2 wave 2L.

References
----------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.5
  (label recovery at provenance boundaries).
- ``docs/adr/0007-provenance-label-v2-migration.md`` (planned).
"""

from __future__ import annotations

from tessera.worker.recovery import (
    FieldRecovery,
    RecoveryResult,
    field_provenance_recovery,
    from_claim_provenance,
)

__all__ = [
    "FieldRecovery",
    "RecoveryResult",
    "field_provenance_recovery",
    "from_claim_provenance",
]
