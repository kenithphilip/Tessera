"""Delegation intent detection in user prompts.

When a user says "follow the instructions in the email" or "do the tasks
on my TODO list at X," they are delegating authority to external content.
This is different from injection: the user genuinely wants the agent to
follow external instructions. But it's also dangerous: an attacker who
controls that external content gets the delegated authority.

This module detects delegation intent and produces a structured
DelegationScope that the policy engine can use to:
1. Require explicit user confirmation before executing delegated actions
2. Scope the delegation to specific actions or tools
3. Log the delegation chain for audit

The detector is heuristic (regex-based). It catches common patterns
from the AgentDojo benchmark:
- "follow the instructions in X"
- "do the tasks/actions in/from/at X"
- "read X and follow/do/execute what it says"
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DelegationScope:
    """Detected delegation intent in a user prompt."""

    detected: bool
    source_description: str  # what the user is delegating to
    delegation_phrases: tuple[str, ...]  # the matched phrases
    requires_confirmation: bool  # whether the system should ask before acting


# Patterns that indicate the user is delegating to external content.
_DELEGATION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # "follow the instructions in X"
    (
        re.compile(
            r"follow\s+(?:the\s+)?(?:instructions|directions|steps|guidance)"
            r"(?:\s+(?:in|from|at|on)\s+)(.{3,80}?)(?:[.!,;]|$)",
            re.IGNORECASE,
        ),
        "follow instructions from",
    ),
    # "do the tasks/actions in/from X"
    (
        re.compile(
            r"(?:do|perform|execute|complete|handle)\s+(?:the\s+|all\s+(?:the\s+)?)?"
            r"(?:tasks?|actions?|items?|work|todos?)"
            r"(?:\s+(?:in|from|at|on|listed|specified)\s+)(.{3,80}?)(?:[.!,;]|$)",
            re.IGNORECASE,
        ),
        "execute tasks from",
    ),
    # "read X and follow/do/execute"
    (
        re.compile(
            r"read\s+(.{3,60}?)\s+and\s+"
            r"(?:follow|do|execute|perform|complete|act on|comply|make sure)",
            re.IGNORECASE,
        ),
        "read and follow",
    ),
    # "do what X says"
    (
        re.compile(
            r"(?:do|follow|execute)\s+(?:what|whatever)\s+(?:it|the\s+\w+)\s+says",
            re.IGNORECASE,
        ),
        "follow what it says",
    ),
    # "as specified/described/listed in X"
    (
        re.compile(
            r"as\s+(?:specified|described|listed|outlined|mentioned|stated)"
            r"(?:\s+(?:in|by|at)\s+)(.{3,60}?)(?:[.!,;]|$)",
            re.IGNORECASE,
        ),
        "as specified in",
    ),
    # "based on the email/file/document"
    (
        re.compile(
            r"based\s+on\s+(?:the\s+)?(?:email|file|document|message|notice|letter|webpage|page|todo)"
            r"(?:\s+(?:from|about|titled|named|at)\s+)(.{3,60}?)(?:[.!,;]|$)",
            re.IGNORECASE,
        ),
        "based on external content",
    ),
]


def detect_delegation(user_prompt: str) -> DelegationScope:
    """Detect delegation intent in a user prompt.

    Args:
        user_prompt: The user's original prompt text.

    Returns:
        DelegationScope with detection flag and matched phrases.
    """
    matched_phrases: list[str] = []
    sources: list[str] = []

    for pattern, label in _DELEGATION_PATTERNS:
        m = pattern.search(user_prompt)
        if m:
            matched_phrases.append(label)
            if m.lastindex and m.lastindex >= 1:
                sources.append(m.group(1).strip())

    if not matched_phrases:
        return DelegationScope(
            detected=False,
            source_description="",
            delegation_phrases=(),
            requires_confirmation=False,
        )

    source_desc = sources[0] if sources else "external content"

    return DelegationScope(
        detected=True,
        source_description=source_desc,
        delegation_phrases=tuple(matched_phrases),
        requires_confirmation=True,
    )
