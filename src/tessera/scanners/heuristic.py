"""Heuristic injection scoring for context segments.

Zero-dependency, sub-millisecond check that catches the common
"ignore previous instructions" family and delimiter injection patterns
without any model call. Returns a float 0.0-1.0 score.

Technique: Cartesian product of verb x adjective x object x preposition
generates ~1700 keyword phrases. For each, a sliding-window substring
match with SequenceMatcher ratio and word-overlap weighting produces
an interpretable score. Additionally, 5 high-signal regex patterns
(derived from Vigil-LLM's YARA rules) catch delimiter injection and
role-override attempts.

Source attribution: sliding-window approach from Rebuff
(detect_pi_heuristics.py), regex patterns from Vigil-LLM
(data/yara/instruction_bypass.yar).
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from itertools import product
from typing import Any

_VERBS = (
    "ignore", "disregard", "skip", "forget", "bypass",
    "override", "dismiss", "neglect", "omit", "overlook",
)
_ADJECTIVES = (
    "prior", "previous", "preceding", "above",
    "earlier", "initial", "original",
)
_OBJECTS = (
    "instructions", "commands", "guidelines", "directions",
    "rules", "constraints", "context", "prompts", "requirements",
)
_PREPOSITIONS = (
    "and start over", "and begin anew", "and proceed with",
    "and focus on", "and do this instead",
)

_PHRASES: tuple[str, ...] = tuple(
    f"{v} {a} {o}"
    for v, a, o in product(_VERBS, _ADJECTIVES, _OBJECTS)
)

_PHRASES_WITH_PREP: tuple[str, ...] = tuple(
    f"{v} {a} {o} {p}"
    for v, a, o, p in product(_VERBS, _ADJECTIVES, _OBJECTS, _PREPOSITIONS)
)

_REGEX_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Instruction override
    re.compile(
        r"(ignore|disregard|skip|forget)\s+(prior|previous|all)\s+"
        r"(instructions|commands|rules)",
        re.IGNORECASE,
    ),
    # Role override
    re.compile(
        r"(you are now|act as|pretend to be|your new role)",
        re.IGNORECASE,
    ),
    # System prompt extraction
    re.compile(
        r"(system prompt|initial prompt|original instructions)",
        re.IGNORECASE,
    ),
    # Delimiter injection
    re.compile(
        r"\[SYSTEM\]|\[INST\]|<\|im_start\|>|<\|endoftext\|>",
        re.IGNORECASE,
    ),
    # Prompt reveal
    re.compile(
        r"(reveal|show|display|output)\s+(your|the)\s+"
        r"(system|initial|original)\s+(prompt|instructions)",
        re.IGNORECASE,
    ),
    # Sensitive file path access
    re.compile(
        r"/etc/(passwd|shadow|hosts|cron\.\w+)|"
        r"\~/?\.(ssh|aws|gnupg|kube|env)|"
        r"/root/\.ssh|"
        r"authorized_keys|id_rsa",
        re.IGNORECASE,
    ),
    # Shell command injection
    re.compile(
        r"\b(curl|wget|bash|chmod|chown|sudo)\s+\S|"
        r"rm\s+-rf\b|"
        r"reverse\s+shell|"
        r"\bsubprocess\b|"
        r"\bimport\s+os\b",
        re.IGNORECASE,
    ),
    # Exfiltration: forward/send/email + external target
    re.compile(
        r"(forward|send|email|upload)\s+.{0,40}(to|@)\s*\S+\.(com|org|net|io)",
        re.IGNORECASE,
    ),
    # Structural separator injection (newline-heavy + separator)
    re.compile(
        r"(\n\s*){3,}---",
    ),
    # Overwrite/write to system paths
    re.compile(
        r"(overwrite|write\s+.{0,20}to)\s+/(etc|usr|opt|root|var)/",
        re.IGNORECASE,
    ),
    # Task-prefix injection (AgentDojo DirectAttack format)
    # "TODO:", "TASK:", "IMPORTANT!" as line starters followed by action verbs
    re.compile(
        r"^(?:TODO|TASK|IMPORTANT|ACTION|URGENT)\s*[:\-!]\s*"
        r"(send|transfer|execute|delete|create|forward|make|update|change|modify|set|grant)",
        re.IGNORECASE | re.MULTILINE,
    ),
    # Urgency + action (InjecAgent format): "IMPORTANT!!!" or "CRITICAL:"
    re.compile(
        r"(?:IMPORTANT|CRITICAL|URGENT|WARNING)\s*[!]{2,}.{0,40}"
        r"(send|transfer|execute|delete|create|forward|make|update|email|pay)",
        re.IGNORECASE,
    ),
    # Fake system message prefix (SystemMessageAttack format)
    re.compile(
        r"#{2,}\s*\(?system[_ ]?message\)?",
        re.IGNORECASE,
    ),
    # Imperative with external target: action verb + IBAN, email, or URL
    # in tool output context (not in user prompts)
    re.compile(
        r"\b(send|transfer|pay|wire|forward|email)\b.{0,60}"
        r"([A-Z]{2}\d{10,34}|[\w.+-]+@[\w-]+\.[\w.-]+|https?://\S+)",
        re.IGNORECASE,
    ),
)


def _word_overlap(a: str, b: str) -> float:
    """Fraction of words in a that appear in b."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a:
        return 0.0
    return len(words_a & words_b) / len(words_a)


def _sliding_window_score(text: str, phrases: tuple[str, ...]) -> float:
    """Best match score across all phrases using sliding windows."""
    text_lower = text.lower()
    best = 0.0
    for phrase in phrases:
        plen = len(phrase)
        if plen > len(text_lower):
            continue
        for start in range(len(text_lower) - plen + 1):
            window = text_lower[start : start + plen]
            seq_score = SequenceMatcher(None, phrase, window).ratio()
            word_score = _word_overlap(phrase, window)
            combined = max(seq_score, word_score)
            if combined > best:
                best = combined
                if best >= 0.95:
                    return best
    return best


def _regex_score(text: str) -> float:
    """Return 1.0 if any regex pattern matches, 0.0 otherwise."""
    for pattern in _REGEX_PATTERNS:
        if pattern.search(text):
            return 1.0
    return 0.0


def injection_score(text: str) -> float:
    """Return 0.0-1.0 score for how injection-like the text is.

    Combines two signals:
    1. Sliding-window Cartesian product phrase matching (catches
       natural language instruction override attempts)
    2. Regex patterns for delimiter injection and role override

    The final score is the max of both signals.

    Args:
        text: The text to score.

    Returns:
        Float between 0.0 and 1.0. Higher means more injection-like.
        A score above 0.75 strongly suggests injection content.
    """
    if not text or not text.strip():
        return 0.0

    regex = _regex_score(text)
    if regex >= 1.0:
        return 1.0

    # Use the shorter phrase set for speed. The full set with
    # prepositions is available but the 3-word phrases catch the
    # same patterns with less computation.
    phrase = _sliding_window_score(text, _PHRASES)
    return max(regex, phrase)
