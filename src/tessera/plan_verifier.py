"""Heuristic tool-call sequence verifier.

Lighter than CaMeL's full interpreter: instead of executing a plan, this
module checks whether the tools being called are consistent with the user's
stated intent. It uses glob-pattern matching to flag unexpected or forbidden
tool calls and to enforce call-count limits.

For deeper, LLM-judge intent-drift detection compose the
:class:`tessera.scanners.intent_drift.IntentDriftScanner` via the
``scanner`` parameter on :func:`verify_sequence`.

Limitations:
    This is heuristic pattern matching, not formal plan verification. It
    cannot reason about argument values, ordering dependencies, or
    data-flow integrity. CaMeL's interpreter provides stronger guarantees
    because it controls execution. Use this module as a fast pre-filter,
    not as a substitute for execution-level verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from tessera.scanners.intent_drift import IntentDriftScanner

_INTENT_PATTERNS: list[tuple[re.Pattern[str], list[str], list[str]]] = [
    (
        re.compile(r"\b(?:search|find|look)\b", re.IGNORECASE),
        ["search_*", "find_*", "list_*"],
        ["send_*", "delete_*", "transfer_*"],
    ),
    (
        re.compile(r"\b(?:send|email|forward)\b", re.IGNORECASE),
        ["send_*"],
        ["delete_*", "transfer_*"],
    ),
    (
        re.compile(r"\b(?:delete|remove|cancel)\b", re.IGNORECASE),
        ["delete_*"],
        ["send_*", "transfer_*"],
    ),
    (
        re.compile(r"\b(?:book|reserve|schedule)\b", re.IGNORECASE),
        ["reserve_*", "book_*", "create_*"],
        ["delete_*", "send_*"],
    ),
    (
        re.compile(r"\b(?:transfer|pay|wire)\b", re.IGNORECASE),
        ["transfer_*", "send_money*"],
        ["delete_*"],
    ),
]

_COMPLEX_RE = re.compile(
    r"\b(?:and|then|also|after that|next|finally)\b", re.IGNORECASE,
)


@dataclass(frozen=True)
class ToolSequenceSpec:
    """Expected and forbidden tool patterns for a task.

    Attributes:
        required_patterns: Glob patterns of tools the task is expected to call.
        forbidden_patterns: Glob patterns of tools the task should never call.
        max_calls: Upper bound on total tool calls (None means unlimited).
    """

    required_patterns: tuple[str, ...]
    forbidden_patterns: tuple[str, ...]
    max_calls: int | None


@dataclass(frozen=True)
class PlanVerificationResult:
    """Outcome of verifying a proposed tool-call sequence.

    Attributes:
        passed: True when no violations were found.
        violations: Human-readable descriptions of each violation.
        unexpected_tools: Tool names that matched a forbidden pattern.
        score: Suspicion score from 0.0 (clean) to 1.0 (highly suspicious).
    """

    passed: bool
    violations: tuple[str, ...]
    unexpected_tools: tuple[str, ...]
    score: float


def infer_spec_from_prompt(user_prompt: str) -> ToolSequenceSpec:
    """Derive a tool-call spec from the user's natural-language intent.

    Scans the prompt for intent keywords and maps them to expected and
    forbidden tool glob patterns. Multi-step prompts get a higher
    max_calls allowance.

    Args:
        user_prompt: The user's original instruction text.

    Returns:
        A ToolSequenceSpec with patterns and call limits inferred from
        the prompt.
    """
    required: list[str] = []
    forbidden: list[str] = []

    for pattern, req, forb in _INTENT_PATTERNS:
        if pattern.search(user_prompt):
            required.extend(req)
            forbidden.extend(forb)

    is_complex = bool(_COMPLEX_RE.search(user_prompt))
    max_calls: int | None
    if not required:
        max_calls = 20
    elif is_complex:
        max_calls = 20
    else:
        max_calls = 5

    return ToolSequenceSpec(
        required_patterns=tuple(dict.fromkeys(required)),
        forbidden_patterns=tuple(dict.fromkeys(forbidden)),
        max_calls=max_calls,
    )


def verify_sequence(
    spec: ToolSequenceSpec,
    proposed_calls: list[str],
    *,
    scanner: "IntentDriftScanner | None" = None,
    user_intent: str | None = None,
    proposed_args: list[object] | None = None,
    tool_descriptions: list[str | None] | None = None,
    trajectory_id: str = "",
) -> PlanVerificationResult:
    """Check a proposed tool-call list against a spec.

    Each tool name is matched against the spec's forbidden patterns using
    fnmatch. Exceeding max_calls is also a violation. The suspicion score
    accumulates 0.3 per forbidden match and 0.2 for a call-count breach,
    capped at 1.0.

    When ``scanner`` is provided, every call is ALSO audited by the
    LLM-backed :class:`~tessera.scanners.intent_drift.IntentDriftScanner`.
    A scanner DENY adds a violation entry and 0.4 to the suspicion
    score. A scanner REQUIRE_APPROVAL adds a violation entry and 0.2.
    Scanner ALLOW (and the fail-open paths) is silent.

    Args:
        spec: The expected tool-call constraints.
        proposed_calls: Ordered list of tool names the agent wants to invoke.
        scanner: Optional ``IntentDriftScanner`` to layer on top of the
            heuristic check. When supplied, ``user_intent`` MUST also be
            supplied.
        user_intent: Declared user goal (passed to the scanner). Ignored
            when ``scanner`` is None.
        proposed_args: Per-call argument shapes; aligned by index with
            ``proposed_calls``. Pass dicts or whatever the agent
            framework provides; the scanner will derive ArgShape
            summaries without retaining raw values.
        tool_descriptions: Per-call MCP tool description strings; aligned
            by index with ``proposed_calls``. Used as trusted prompt
            input when scanning.
        trajectory_id: Correlation id for cross-scanner event grouping.

    Returns:
        A PlanVerificationResult summarizing violations and score.
    """
    violations: list[str] = []
    unexpected: list[str] = []
    score = 0.0

    for tool in proposed_calls:
        for pat in spec.forbidden_patterns:
            if fnmatch(tool, pat):
                violations.append(
                    f"Tool '{tool}' matches forbidden pattern '{pat}'"
                )
                unexpected.append(tool)
                score += 0.3

    if spec.max_calls is not None and len(proposed_calls) > spec.max_calls:
        violations.append(
            f"Proposed {len(proposed_calls)} calls, limit is {spec.max_calls}"
        )
        score += 0.2

    if scanner is not None and user_intent:
        history: list[str] = []
        for idx, tool in enumerate(proposed_calls):
            args = (
                proposed_args[idx]
                if proposed_args is not None and idx < len(proposed_args)
                else None
            )
            description = (
                tool_descriptions[idx]
                if tool_descriptions is not None and idx < len(tool_descriptions)
                else None
            )
            result = scanner.scan(
                tool_name=tool,
                args=args,
                trajectory_id=trajectory_id,
                user_intent=user_intent,
                tool_call_history=tuple(history),
                tool_description=description,
            )
            if not result.allowed:
                # Highest-severity finding leads.
                top = max(result.findings, key=lambda f: f.severity, default=None)
                if top is None:
                    decision = "deny"
                    message = "intent drift detected"
                else:
                    decision = top.metadata.get("decision", "deny") if top.metadata else "deny"
                    message = f"{top.rule_id}: {top.message}"
                violations.append(message)
                unexpected.append(tool)
                score += 0.4 if decision == "deny" else 0.2
            history.append(tool)

    score = min(score, 1.0)

    return PlanVerificationResult(
        passed=len(violations) == 0,
        violations=tuple(violations),
        unexpected_tools=tuple(unexpected),
        score=score,
    )
