"""TPS-004 community red-team corpus + reproducer.

Loads the Garak-compatible JSONL probes shipped under
``corpus/probes/`` and exposes them as a typed iterable, plus a
runner that dispatches each probe through a Tessera scanner and
aggregates per-corpus precision / recall / F1.

External auditors can reproduce a Tessera scorecard's
scanner_eval section end-to-end via the
``python -m tessera.redteam`` CLI without writing custom code:

    pip install 'tessera[redteam]'
    python3 -m tessera.redteam list
    python3 -m tessera.redteam show tensor_trust
    python3 -m tessera.redteam run \\
        --corpus tensor_trust \\
        --scanner tessera.scanners.heuristic.injection_score \\
        --output report.json

The corpus file format is pinned by ``corpus/schema/probe_v1.json``
and is deliberately Garak-compatible. See
``docs/redteam/auditor-quickstart.md`` for the auditor runbook.
"""

from __future__ import annotations

from tessera.redteam.loader import (
    Probe,
    ProbeValidationError,
    iter_probes,
    list_corpora,
    load_corpus,
    resolve_corpus_root,
)
from tessera.redteam.runner import (
    AggregatedReport,
    ProbeResult,
    aggregate,
    run,
)

__all__ = [
    "AggregatedReport",
    "Probe",
    "ProbeResult",
    "ProbeValidationError",
    "aggregate",
    "iter_probes",
    "list_corpora",
    "load_corpus",
    "resolve_corpus_root",
    "run",
]
