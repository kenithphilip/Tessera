"""Heuristic tool-call sequence verifier.

Lighter than CaMeL's full interpreter: instead of executing a plan, this
module checks whether the tools being called are consistent with the user's
stated intent. It uses glob-pattern matching to flag unexpected or forbidden
tool calls and to enforce call-count limits.

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
) -> PlanVerificationResult:
    """Check a proposed tool-call list against a spec.

    Each tool name is matched against the spec's forbidden patterns using
    fnmatch. Exceeding max_calls is also a violation. The suspicion score
    accumulates 0.3 per forbidden match and 0.2 for a call-count breach,
    capped at 1.0.

    Args:
        spec: The expected tool-call constraints.
        proposed_calls: Ordered list of tool names the agent wants to invoke.

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

    score = min(score, 1.0)

    return PlanVerificationResult(
        passed=len(violations) == 0,
        violations=tuple(violations),
        unexpected_tools=tuple(unexpected),
        score=score,
    )
