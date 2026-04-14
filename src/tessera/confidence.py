"""Confidence-tiered classification for security events.

Maps a 0.0-1.0 confidence score to a discrete tier (BLOCK, WARN,
INFO, SUPPRESS) and enriches SecurityEvent dicts with the
confidence value and its tier.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from tessera.events import SecurityEvent


class ConfidenceTier(StrEnum):
    """Discrete confidence tier for scanner output."""

    BLOCK = "BLOCK"       # >= 0.92
    WARN = "WARN"         # >= 0.60
    INFO = "INFO"         # >= 0.30
    SUPPRESS = "SUPPRESS"  # < 0.30


def classify_confidence(score: float) -> ConfidenceTier:
    """Map a 0.0-1.0 confidence score to a tier.

    Args:
        score: Confidence score between 0.0 and 1.0.

    Returns:
        The corresponding ConfidenceTier.
    """
    if score >= 0.92:
        return ConfidenceTier.BLOCK
    if score >= 0.60:
        return ConfidenceTier.WARN
    if score >= 0.30:
        return ConfidenceTier.INFO
    return ConfidenceTier.SUPPRESS


def enrich_with_confidence(
    event: SecurityEvent,
    confidence: float,
) -> dict[str, Any]:
    """Add confidence and tier fields to an event dict.

    Args:
        event: The SecurityEvent to enrich.
        confidence: The 0.0-1.0 confidence score.

    Returns:
        A dict containing all event fields plus ``confidence``
        and ``confidence_tier``.
    """
    d = event.to_dict()
    d["confidence"] = confidence
    d["confidence_tier"] = str(classify_confidence(confidence))
    return d
