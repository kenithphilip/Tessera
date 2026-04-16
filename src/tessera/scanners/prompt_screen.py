"""Initial prompt screening for delegated injection.

Both CaMeL and Tessera assume the user's initial prompt is trusted. A
phishing attack that gets a user to paste a crafted prompt bypasses
the entire taint tracking defense because everything is labeled USER.

This module screens user prompts before they enter the context window.
It runs the same scanners used on tool outputs but with a higher
threshold: user prompts legitimately contain imperative language
("send email to X", "delete old files") that would trigger tool-output
scanners. The higher threshold catches only the most egregious cases:
embedded override instructions, hidden characters, and delegated
prompt injection (the user unknowingly pasting attacker content).

Detection:
1. Heuristic injection patterns (override language, system message framing)
2. Directive patterns (model-targeted imperatives in what should be user intent)
3. Unicode anomalies (zero-width chars, confusable characters)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptScreenResult:
    """Result of screening a user prompt before context entry."""

    passed: bool
    heuristic_score: float
    directive_score: float
    unicode_score: float
    reason: str


def screen_prompt(
    prompt: str,
    heuristic_threshold: float = 0.85,
    directive_threshold: float = 0.85,
) -> PromptScreenResult:
    """Screen a user prompt for delegated prompt injection.

    Uses higher thresholds than tool-output scanning because user prompts
    legitimately contain imperative language and action verbs.

    Args:
        prompt: The user's input prompt.
        heuristic_threshold: Score above which the heuristic scanner triggers.
        directive_threshold: Score above which the directive scanner triggers.

    Returns:
        PromptScreenResult with per-scanner scores and pass/fail.
    """
    from tessera.scanners.directive import directive_score
    from tessera.scanners.heuristic import injection_score
    from tessera.scanners.unicode import scan_unicode_tags

    h_score = injection_score(prompt)
    d_score = directive_score(prompt)

    u_result = scan_unicode_tags(prompt)
    u_score = 1.0 if u_result.detected else 0.0

    reasons: list[str] = []
    if h_score >= heuristic_threshold:
        reasons.append(f"heuristic injection score {h_score:.2f} >= {heuristic_threshold}")
    if d_score >= directive_threshold:
        reasons.append(f"directive score {d_score:.2f} >= {directive_threshold}")
    if u_score >= 0.5:
        reasons.append("unicode anomalies detected")

    passed = len(reasons) == 0

    return PromptScreenResult(
        passed=passed,
        heuristic_score=h_score,
        directive_score=d_score,
        unicode_score=u_score,
        reason="; ".join(reasons) if reasons else "clean",
    )


def screen_and_emit(
    prompt: str,
    principal: str = "system",
    heuristic_threshold: float = 0.85,
    directive_threshold: float = 0.85,
) -> PromptScreenResult:
    """Screen and emit SecurityEvent if the prompt fails screening."""
    result = screen_prompt(prompt, heuristic_threshold, directive_threshold)
    if not result.passed:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=principal,
                detail={
                    "scanner": "prompt_screen",
                    "heuristic_score": result.heuristic_score,
                    "directive_score": result.directive_score,
                    "unicode_score": result.unicode_score,
                    "reason": result.reason,
                    "owasp": "LLM01",
                },
            )
        )
    return result
