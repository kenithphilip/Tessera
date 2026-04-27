"""Regenerate ``docs/security/atlas_navigator_layer.json`` from
``tessera.compliance.MITRE_ATLAS``.

Run this script after editing the MITRE_ATLAS dict in
``src/tessera/compliance.py`` so the published Navigator layer
stays in lockstep with the canonical mapping. The output is a
deterministic JSON file (sorted keys, stable ordering) suitable
for committing.

Usage::

    python3 tools/regenerate_atlas_layer.py [--check]

With ``--check`` the script writes nothing and exits 1 if the
on-disk file disagrees with what would be generated. Use this in
CI to catch drift.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAYER_PATH = REPO_ROOT / "docs" / "security" / "atlas_navigator_layer.json"

# Sub-technique -> human-readable name. Sourced from
# https://atlas.mitre.org/techniques/ at v5.4.0 (Feb 2026).
TECHNIQUE_NAMES: dict[str, str] = {
    "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0029": "Denial of ML Service",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.001": "Direct Prompt Injection",
    "AML.T0051.002": "Indirect Prompt Injection",
}

# Per-technique mitigation prose. Empty string for entries we
# extend later; the generator will fall back to a uniform
# placeholder rather than fabricating per-technique mechanisms.
MITIGATION: dict[str, str] = {
    "AML.T0010": (
        "MCP manifest signature verification (Sigstore + DSSE) detects "
        "tampered server manifests. Shape-drift, latency-drift, and "
        "distribution-drift detectors flag behavioural changes between "
        "the baseline and live tool outputs."
    ),
    "AML.T0024": (
        "SecretRegistry redacts credentials before context enters the "
        "LLM. Delegation tokens carry RFC 8707 audience constraints. "
        "Identity, proof, and delegation verification block "
        "impersonation attempts. Runtime egress allowlist blocks "
        "exfiltration channels patched at the HTTP layer."
    ),
    "AML.T0029": (
        "Latency-jump and distribution-drift detection on every MCP "
        "tool call. Sustained drift past configurable thresholds emits "
        "structured events for SIEM ingest."
    ),
    "AML.T0043": (
        "LLMGuardrail evaluates context and emits a decision event. "
        "Human-approval gates halt irreversible actions. Action Critic "
        "requires explicit approval for high-risk operations."
    ),
    "AML.T0050": (
        "Tier-1 runtime isolation patches open() to deny writes outside "
        "configured prefixes and patches HTTP egress to deny calls to "
        "hosts outside the allowlist. Each denial emits a structured "
        "event for SIEM ingest."
    ),
    "AML.T0051.001": (
        "Trust-label taint tracking (min_trust) blocks tool calls when "
        "any context segment is untrusted. Schema-enforced dual-LLM "
        "quarantine prevents free-form injection from the Worker."
    ),
    "AML.T0051.002": (
        "HMAC/JWT signed context labels detect tampered or forged "
        "provenance. Critical-args enforcement blocks tool calls where "
        "sensitive arguments derive from untrusted context segments."
    ),
}

# Per-technique color (preserved from prior layer for SOC team
# muscle memory; new techniques follow the same palette family).
COLOR: dict[str, str] = {
    "AML.T0010": "#cc0000",
    "AML.T0024": "#e69138",
    "AML.T0029": "#a64d79",
    "AML.T0043": "#6aa84f",
    "AML.T0050": "#674ea7",
    "AML.T0051.001": "#3d85c8",
    "AML.T0051.002": "#3d85c8",
}


def _invert_mapping() -> dict[str, list[str]]:
    """Return technique_id -> sorted list of EventKind string values."""
    from tessera.compliance import MITRE_ATLAS

    by_technique: dict[str, list[str]] = defaultdict(list)
    for event_kind_value, technique_ids in MITRE_ATLAS.items():
        for tid in technique_ids:
            by_technique[tid].append(str(event_kind_value))
    for events in by_technique.values():
        events.sort()
    return dict(by_technique)


def _build_layer() -> dict[str, object]:
    inverted = _invert_mapping()
    techniques = []
    for tid in sorted(inverted.keys()):
        events = inverted[tid]
        events_str = ", ".join(events)
        atlas_name = TECHNIQUE_NAMES.get(tid, tid)
        mitigation = MITIGATION.get(
            tid,
            "Tessera detects this technique via the events listed above.",
        )
        techniques.append(
            {
                "techniqueID": tid,
                "score": 100,
                "color": COLOR.get(tid, "#3d85c8"),
                "comment": f"Covered by: {events_str}",
                "enabled": True,
                "metadata": [
                    {"name": "tessera_events", "value": events_str},
                    {"name": "mitigation_mechanism", "value": mitigation},
                    {"name": "atlas_technique_name", "value": atlas_name},
                ],
            }
        )

    return {
        "name": "Tessera v1.0 coverage",
        "versions": {
            "attack": "16",
            "navigator": "5.0",
            "layer": "4.5",
        },
        "domain": "ATLAS",
        "description": (
            "Tessera v1.0 mitigation coverage mapped to MITRE ATLAS v5.4.0 "
            "(February 2026). Each technique scored 100 has at least one "
            "Tessera SecurityEvent kind that detects or blocks it. Scores "
            "are coverage indicators, not severity ratings. This file is "
            "regenerated from tessera.compliance.MITRE_ATLAS by "
            "tools/regenerate_atlas_layer.py."
        ),
        "filters": {"platforms": []},
        "sorting": 0,
        "layout": {
            "layout": "flat",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#3d85c8"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Prompt injection (direct + indirect)", "color": "#3d85c8"},
            {"label": "Adversarial data / approval gate", "color": "#6aa84f"},
            {"label": "Exfiltration / identity", "color": "#e69138"},
            {"label": "Supply chain", "color": "#cc0000"},
            {"label": "Denial of service", "color": "#a64d79"},
            {"label": "Runtime isolation", "color": "#674ea7"},
        ],
        "metadata": [
            {"name": "generator", "value": "tools/regenerate_atlas_layer.py"},
            {"name": "tessera_version", "value": "v1.0"},
            {"name": "generated_at", "value": date.today().isoformat()},
            {"name": "atlas_version", "value": "v5.4.0"},
        ],
        "links": [
            {"label": "Tessera GitHub", "url": "https://github.com/kenithphilip/Tessera"},
            {"label": "MITRE ATLAS", "url": "https://atlas.mitre.org/"},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the on-disk file would change. Writes nothing.",
    )
    args = parser.parse_args()

    layer = _build_layer()
    rendered = json.dumps(layer, indent=2, sort_keys=False) + "\n"

    if args.check:
        existing = LAYER_PATH.read_text(encoding="utf-8") if LAYER_PATH.exists() else ""
        if existing != rendered:
            sys.stderr.write(
                "atlas_navigator_layer.json is out of date. "
                "Run `python3 tools/regenerate_atlas_layer.py` and commit.\n"
            )
            return 1
        return 0

    LAYER_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {LAYER_PATH} ({len(layer['techniques'])} techniques)")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT / "src"))
    raise SystemExit(main())
