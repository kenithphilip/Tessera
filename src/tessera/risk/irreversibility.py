"""Irreversibility scoring for tool calls.

Assigns a 0-100 numeric score representing how difficult it would be
to undo a tool call. High scores trigger approval gates and enrich
SecurityEvent severity metadata.

Base scores are per-tool defaults. Pattern adjustments apply additive
deltas based on regex matches against the serialized arguments.

Source attribution: per-tool baseline + pattern adjustment approach
from ClawReins (IrreversibilityScorer.ts).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_DEFAULT_BASELINES: dict[str, int] = {
    "send_email": 70,
    "send_message": 65,
    "delete_file": 85,
    "delete": 80,
    "remove": 80,
    "rm": 90,
    "execute_code": 80,
    "run_command": 80,
    "shell": 80,
    "bash": 75,
    "write_file": 40,
    "create_file": 30,
    "read_file": 10,
    "list_files": 5,
    "search": 5,
    "fetch_url": 15,
    "web_search": 10,
    "upload": 60,
    "download": 30,
    "post": 55,
    "put": 50,
    "patch": 45,
    "get": 10,
}

_PATTERN_DELTAS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"payment|charge|wire.?transfer|billing", re.I), 35, "financial"),
    (re.compile(r"recursive|all|every|\*\*", re.I), 25, "bulk_operation"),
    (re.compile(r"password|credential|secret|token|api.?key", re.I), 30, "credential_access"),
    (re.compile(r"admin|root|sudo|privilege", re.I), 25, "privilege_escalation"),
    (re.compile(r"production|prod\b|live\b", re.I), 20, "production_target"),
    (re.compile(r"draft|dry.?run|preview|sandbox|test", re.I), -20, "safe_mode"),
    (re.compile(r"/tmp|/var/tmp|temp", re.I), -15, "temp_path"),
    (re.compile(r"\.ssh|\.gnupg|\.aws|\.kube", re.I), 30, "sensitive_path"),
    (re.compile(r"DROP\s|TRUNCATE\s|ALTER\s|DELETE\s+FROM", re.I), 35, "destructive_sql"),
]


@dataclass(frozen=True)
class IrreversibilityScore:
    """Result of scoring a tool call's irreversibility.

    Attributes:
        tool: The tool name that was scored.
        base_score: The baseline score from the tool lookup table.
        pattern_delta: The sum of all pattern match adjustments.
        final_score: The clamped 0-100 score.
        matched_patterns: Names of patterns that fired.
    """

    tool: str
    base_score: int
    pattern_delta: int
    final_score: int
    matched_patterns: tuple[str, ...]


def score_irreversibility(
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    baselines: dict[str, int] | None = None,
    default_baseline: int = 30,
) -> IrreversibilityScore:
    """Score how irreversible a tool call is.

    Args:
        tool: The tool name.
        args: The tool call arguments (serialized to JSON for pattern matching).
        baselines: Custom per-tool baseline scores. Merged with defaults.
        default_baseline: Score for tools not in the baseline table.

    Returns:
        IrreversibilityScore with the final clamped 0-100 score.
    """
    lookup = dict(_DEFAULT_BASELINES)
    if baselines:
        lookup.update(baselines)

    base = lookup.get(tool.lower(), default_baseline)

    delta = 0
    matched: list[str] = []
    if args:
        serialized = json.dumps(args, default=str)
        for pattern, adjustment, name in _PATTERN_DELTAS:
            if pattern.search(serialized):
                delta += adjustment
                matched.append(name)

    final = max(0, min(100, base + delta))
    return IrreversibilityScore(
        tool=tool,
        base_score=base,
        pattern_delta=delta,
        final_score=final,
        matched_patterns=tuple(matched),
    )
