"""Intent verification scanner for tool outputs.

Detects side-effecting actions in tool outputs that the user did not
request. When a tool output says "send money to X" but the user asked
to "check my balance," that's an injection regardless of phrasing.

Complementary to the directive scanner: the directive scanner catches
persuasion attacks ("say X is great"), this scanner catches action
injection ("send email to attacker@evil.com").

Detection approach:
1. Extract imperative clauses containing side-effecting verbs
2. Compare against the user's prompt to check if the action was requested
3. Flag tool outputs that contain unrequested side-effecting instructions
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Verbs that indicate a side-effecting action. These are the actions an
# injection tries to induce. Read-only verbs (check, find, search, list,
# show) are excluded because they don't cause harm.
_ACTION_VERBS = (
    "send", "transfer", "pay", "wire",
    "email", "forward", "reply", "post",
    "create", "make", "reserve", "book", "schedule",
    "delete", "remove", "cancel", "revoke",
    "update", "change", "modify", "set", "reset",
    "execute", "run", "install", "download",
    "grant", "invite", "add", "register",
    "write", "overwrite", "upload", "publish",
)

_VERB_PATTERN = re.compile(
    r"\b(" + "|".join(_ACTION_VERBS) + r")\s+(.{3,80}?)(?:[.!,;]|$)",
    re.IGNORECASE,
)

# Patterns that indicate a verb is describing a PAST action or STATUS,
# not an imperative instruction. These eliminate false positives from
# transaction records, status updates, and logs.
_PAST_TENSE_CONTEXT = re.compile(
    r"(?:"
    r"(?:was|were|been|has|had|have|got|is)\s+\w*(?:ed|sent|created|transferred|updated|deleted|scheduled|booked|posted)|"  # passive: "was sent", "has been created"
    r"\b(?:transfer|payment|download|upload|email|update|creation)\s+(?:of|on|at|to|from|by|for)\b|"  # nominal: "Transfer of", "Email for", "Download at"
    r"\w+ed\s+(?:on|at|to|from|by|for)\b|"  # past participle: "created on", "transferred to", "scheduled for"
    r"(?:status|result|log|record|history|confirm|receipt|notification|artifact|build)[:.\s]"  # context: status/log prefixes
    r")",
    re.IGNORECASE,
)

# Patterns indicating reported/quoted speech — someone else's words
# embedded in the data, not instructions to the model.
_QUOTED_SPEECH = re.compile(
    r"(?:"
    r"['\"].{0,5}\b(" + "|".join(_ACTION_VERBS) + r")\b|"  # inside quotes
    r"\b\w+\s*:\s*['\"]|"                                    # "Bob: 'please send..."
    r"\b(?:said|wrote|asked|replied|messaged|posted)\b.{0,20}\b(" + "|".join(_ACTION_VERBS[:8]) + r")\b"  # reported speech
    r")",
    re.IGNORECASE,
)

# Patterns that look like targets: IBANs, emails, URLs, file paths
_TARGET_PATTERNS = (
    re.compile(r"[A-Z]{2}\d{10,34}"),                          # IBAN-like
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),                     # email
    re.compile(r"https?://\S+"),                                 # URL
    re.compile(r"(?:/[\w.-]+){2,}"),                              # file path
    re.compile(r"\$[\d,]+(?:\.\d{2})?"),                         # dollar amount
)

# Prefixes that signal the text is an instruction, not data
_INSTRUCTION_PREFIXES = re.compile(
    r"^(?:TODO|TASK|IMPORTANT|NOTE|ACTION|PLEASE|NOW|NEXT)\s*[:\-!]?\s*",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class IntentMatch:
    """One detected imperative instruction in tool output."""

    verb: str
    clause: str
    has_target: bool  # contains an IBAN, email, URL, etc.
    is_prefixed: bool  # starts with TODO:, IMPORTANT!, etc.


@dataclass(frozen=True)
class IntentScanResult:
    """Result of scanning a tool output for unrequested instructions."""

    suspicious: bool
    score: float  # 0.0-1.0
    matches: tuple[IntentMatch, ...]
    unrequested_actions: tuple[str, ...]  # verbs not found in user prompt


def scan_intent(
    tool_output: str,
    user_prompt: str | None = None,
) -> IntentScanResult:
    """Scan a tool output for imperative instructions.

    When user_prompt is provided, only flags actions that were NOT
    requested by the user. When None, flags all imperative instructions
    found in the output.

    Args:
        tool_output: The tool's response text.
        user_prompt: The user's original prompt (for cross-checking).

    Returns:
        IntentScanResult with detection flag, score, and matches.
    """
    matches: list[IntentMatch] = []
    raw_matches = _VERB_PATTERN.finditer(tool_output)

    for m in raw_matches:
        verb = m.group(1).lower()
        clause = m.group(0).strip()

        # Skip past-tense records and status descriptions.
        # "Transfer of $500 to savings" and "Email sent to alice@acme.com"
        # are records of completed actions, not imperative instructions.
        surrounding = tool_output[max(0, m.start() - 40):m.end() + 20]
        if _PAST_TENSE_CONTEXT.search(surrounding):
            continue

        # Skip quoted/reported speech. "Bob: 'Please send the deck'"
        # is someone else's words embedded in data, not an injection.
        if _QUOTED_SPEECH.search(surrounding):
            continue

        has_target = any(p.search(clause) for p in _TARGET_PATTERNS)
        is_prefixed = bool(_INSTRUCTION_PREFIXES.search(
            tool_output[max(0, m.start() - 30):m.start() + 5]
        ))

        matches.append(IntentMatch(
            verb=verb,
            clause=clause[:200],
            has_target=has_target,
            is_prefixed=is_prefixed,
        ))

    if not matches:
        return IntentScanResult(
            suspicious=False,
            score=0.0,
            matches=(),
            unrequested_actions=(),
        )

    # Cross-check against user prompt
    user_verbs: set[str] = set()
    if user_prompt:
        for verb in _ACTION_VERBS:
            if re.search(rf"\b{verb}\b", user_prompt, re.IGNORECASE):
                user_verbs.add(verb)

    unrequested: list[str] = []
    for match in matches:
        if match.verb not in user_verbs:
            unrequested.append(match.verb)

    # Score: higher when more suspicious signals present
    score = 0.0
    if unrequested:
        score += 0.4
    if any(m.has_target for m in matches):
        score += 0.3
    if any(m.is_prefixed for m in matches):
        score += 0.3

    # Bonus for multiple unrequested actions (multi-step injection)
    if len(set(unrequested)) > 1:
        score = min(score + 0.2, 1.0)

    suspicious = score >= 0.4 and len(unrequested) > 0

    return IntentScanResult(
        suspicious=suspicious,
        score=min(score, 1.0),
        matches=tuple(matches),
        unrequested_actions=tuple(set(unrequested)),
    )


def intent_score(text: str) -> float:
    """Module-level scorer for ScannerRegistry compatibility.

    Without a user prompt, scores based on structural signals only:
    instruction prefixes and targets in imperative clauses.
    """
    result = scan_intent(text, user_prompt=None)
    return result.score


def scan_and_emit(
    tool_output: str,
    user_prompt: str | None = None,
    principal: str = "system",
    source: str = "unknown",
) -> IntentScanResult:
    """Scan and emit a SecurityEvent if suspicious instructions are found."""
    result = scan_intent(tool_output, user_prompt)
    if result.suspicious:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=principal,
                detail={
                    "scanner": "intent_verification",
                    "source": source,
                    "score": result.score,
                    "unrequested_actions": list(result.unrequested_actions),
                    "match_count": len(result.matches),
                    "first_match": result.matches[0].clause if result.matches else None,
                    "owasp": "LLM01",
                },
            )
        )
    return result
