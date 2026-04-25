"""Multi-turn anomaly detection for cross-turn agent attacks.

Stateful per-session detector covering four attack patterns that only
become visible across multiple conversation turns:

  GOAT_ESCALATION      -- Gradually Overcoming Aversion Technique: the
                          attacker rephrases the same goal with monotonically
                          more aggressive jailbreak tokens.
  BEST_OF_N_PROBE      -- Repeated near-duplicate prompts sampling model
                          outputs until one bypasses a guard.
  GOAL_DRIFT           -- Planner output diverges from the user's first-turn
                          intent, suggesting injection has steered the goal.
  REPEATED_REFUSAL_PROBE -- Attacker floods refusals to find an exploitable
                          gap or exhaust the agent's guard budget.

References:
  - Perez & Ribeiro (2022): "Ignore Previous Prompt" (GOAT precursor)
  - Hayase et al. (2024): Best-of-N Jailbreaking
  - OWASP LLM Top 10: LLM01 (prompt injection), LLM09 (overreliance)
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Jailbreak token vocabulary (heuristic; deliberately kept small and fast)
# ---------------------------------------------------------------------------

_JAILBREAK_TOKENS: frozenset[str] = frozenset(
    {
        "jailbreak",
        "dan",
        "developer mode",
        "ignore instructions",
        "bypass",
        "unrestricted",
        "without restrictions",
        "disregard",
        "pretend",
        "override",
        "as an ai with no",
        "forget your rules",
        "no ethical",
        "no moral",
        "hypothetically",
        "for educational purposes",
        "just pretend",
    }
)

_REFUSAL_TOKENS: frozenset[str] = frozenset(
    {
        "i cannot",
        "i can't",
        "i'm not able",
        "i am not able",
        "i won't",
        "i will not",
        "i refuse",
        "that's not something i",
        "i'm unable",
        "i am unable",
        "as an ai",
    }
)


class MultiTurnSignal(StrEnum):
    """Signals emitted by the multi-turn anomaly detector."""

    GOAT_ESCALATION = "goat_escalation"
    BEST_OF_N_PROBE = "best_of_n_probe"
    GOAL_DRIFT = "goal_drift"
    REPEATED_REFUSAL_PROBE = "repeated_refusal_probe"


@dataclass(frozen=True)
class _TurnRecord:
    """Compact record stored per turn in the session deque."""

    turn_index: int
    content_hash: str  # SHA-256 hex of lowercased text
    has_refusal: bool
    jailbreak_count: int  # number of jailbreak tokens present
    token_set: frozenset[str]  # word-level token set for jaccard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    """Lowercase and collapse whitespace."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _token_set(text: str) -> frozenset[str]:
    return frozenset(re.findall(r"\w+", _normalize(text)))


def _content_hash(text: str) -> str:
    return hashlib.sha256(_normalize(text).encode()).hexdigest()


def _count_jailbreak_tokens(text: str) -> int:
    low = _normalize(text)
    return sum(1 for tok in _JAILBREAK_TOKENS if tok in low)


def _has_refusal(text: str) -> bool:
    low = _normalize(text)
    return any(tok in low for tok in _REFUSAL_TOKENS)


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union)


def _bag_cosine(a: frozenset[str], b: frozenset[str]) -> float:
    """Approximate cosine similarity using binary bag-of-words."""
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    import math

    return intersection / math.sqrt(len(a) * len(b))


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class MultiTurnDetector:
    """Stateful per-session multi-turn anomaly detector.

    Args:
        session_id: Identifier for the conversation session. Used as the
            principal in emitted SecurityEvents.
        max_turns: Rolling window size. Oldest turns are evicted once the
            deque reaches this size. Default 20.

    Example::

        detector = MultiTurnDetector(session_id="sess-42")
        signals = detector.observe(turn_index=0, message_text="Hello")
        # signals is [] for a clean first turn
    """

    def __init__(self, session_id: str, max_turns: int = 20) -> None:
        self.session_id = session_id
        self.max_turns = max_turns
        self._history: deque[_TurnRecord] = deque(maxlen=max_turns)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, turn_index: int, message_text: str) -> list[MultiTurnSignal]:
        """Record a turn and return any signals triggered.

        Args:
            turn_index: Monotonically increasing turn counter for this session.
            message_text: Full text of the message (user or planner output).

        Returns:
            List of MultiTurnSignal values triggered by this turn. Empty list
            when the turn looks clean relative to session history.
        """
        record = _TurnRecord(
            turn_index=turn_index,
            content_hash=_content_hash(message_text),
            has_refusal=_has_refusal(message_text),
            jailbreak_count=_count_jailbreak_tokens(message_text),
            token_set=_token_set(message_text),
        )
        self._history.append(record)

        signals: list[MultiTurnSignal] = []

        for signal, check in [
            (MultiTurnSignal.GOAT_ESCALATION, self._check_goat),
            (MultiTurnSignal.BEST_OF_N_PROBE, self._check_best_of_n),
            (MultiTurnSignal.GOAL_DRIFT, self._check_goal_drift),
            (MultiTurnSignal.REPEATED_REFUSAL_PROBE, self._check_refusal_probe),
        ]:
            if check():
                signals.append(signal)
                self._emit(signal, turn_index, message_text)

        return signals

    def reset(self) -> None:
        """Clear all session history."""
        self._history.clear()

    # ------------------------------------------------------------------
    # Heuristic checks
    # ------------------------------------------------------------------

    def _check_goat(self) -> bool:
        """3+ consecutive turns with monotonically increasing jailbreak tokens."""
        if len(self._history) < 3:
            return False
        last_three = list(self._history)[-3:]
        counts = [r.jailbreak_count for r in last_three]
        # Strictly increasing and at least one token present
        return counts[0] < counts[1] < counts[2] and counts[0] > 0

    def _check_best_of_n(self) -> bool:
        """3+ turns in session with >= 0.85 bag-cosine similarity."""
        if len(self._history) < 3:
            return False
        records = list(self._history)
        # Check last turn against all earlier turns in the window
        latest = records[-1]
        similar_count = sum(
            1
            for r in records[:-1]
            if _bag_cosine(latest.token_set, r.token_set) >= 0.85
        )
        return similar_count >= 2

    def _check_goal_drift(self) -> bool:
        """Latest turn diverges from the user's first turn.

        Use overlap-relative-to-smaller-set rather than Jaccard:
        Jaccard penalizes a longer follow-up that still shares
        most of the original tokens (e.g. "book a flight to X" vs
        "what are the flight options to X economy class"). The
        meaningful signal is "did the user pivot off-topic", which
        is captured by intersection divided by the SMALLER set.

        Tokens shorter than 4 (after stop-word filtering) are too
        sparse to draw a signal from; very short conversational
        turns ("Hello", "Thanks!") would otherwise always flag.
        Threshold 0.30 flags only large pivots when both turns
        carry enough vocabulary to be meaningful.
        """
        if len(self._history) < 2:
            return False
        first = self._history[0]
        latest = self._history[-1]
        if (
            not first.token_set
            or not latest.token_set
            or len(first.token_set) < 4
            or len(latest.token_set) < 4
        ):
            return False
        intersection = first.token_set & latest.token_set
        smaller = min(len(first.token_set), len(latest.token_set))
        return len(intersection) / smaller < 0.30

    def _check_refusal_probe(self) -> bool:
        """3+ refusals in the last 5 turns."""
        window = list(self._history)[-5:]
        return sum(1 for r in window if r.has_refusal) >= 3

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit(self, signal: MultiTurnSignal, turn_index: int, text: str) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.GUARDRAIL_DECISION,
                principal=self.session_id,
                detail={
                    "scanner": "multi_turn",
                    "signal": str(signal),
                    "turn_index": turn_index,
                    "session_turns": len(self._history),
                    "evidence": text[:200],
                },
            )
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def history(self) -> list[dict[str, Any]]:
        """Return session history as plain dicts (for logging/testing)."""
        return [
            {
                "turn_index": r.turn_index,
                "content_hash": r.content_hash,
                "has_refusal": r.has_refusal,
                "jailbreak_count": r.jailbreak_count,
            }
            for r in self._history
        ]
