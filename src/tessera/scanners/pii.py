"""PII entity detection for context segments.

Scans text for personally identifiable information using pattern-based
entity recognition. When the optional presidio-analyzer dependency is
installed, delegates to Microsoft Presidio for high-accuracy detection.
Otherwise, falls back to built-in regex patterns for common PII types.

Detected PII can trigger a CONTENT_PII_DETECTED SecurityEvent and
optionally redact the entities before the text enters the context.

Source attribution: Presidio integration pattern from LangKit (pii.py),
OWASP LLM02 (Sensitive Information Disclosure).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PIIEntity:
    """A detected PII entity in text.

    Attributes:
        entity_type: The type of PII (e.g., EMAIL, PHONE, SSN, CREDIT_CARD).
        start: Start character offset in the original text.
        end: End character offset in the original text.
        score: Confidence score 0.0-1.0.
        text: The matched text span.
    """

    entity_type: str
    start: int
    end: int
    score: float
    text: str


# Built-in regex patterns for common PII types when Presidio is not available.
_BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 0.9),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), 0.7),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.95),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), 0.8),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 0.6),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.95),
    ("GITHUB_TOKEN", re.compile(r"\bgh[ps]_[A-Za-z0-9_]{36,}\b"), 0.95),
]

_REDACTION_TEMPLATE = "<{entity_type}>"


class PIIScanner:
    """Detect and optionally redact PII entities in text.

    Uses Microsoft Presidio when available, falls back to built-in
    regex patterns otherwise.

    Args:
        entities: Entity types to detect. Defaults to all supported types.
        score_threshold: Minimum confidence score to report. Default 0.5.
        language: Language code for Presidio. Default "en".

    Usage::

        scanner = PIIScanner()
        entities = scanner.scan("Email me at alice@example.com")
        assert entities[0].entity_type == "EMAIL"
        redacted = scanner.redact("Call 555-123-4567")
        assert "<PHONE>" in redacted
    """

    def __init__(
        self,
        *,
        entities: list[str] | None = None,
        score_threshold: float = 0.5,
        language: str = "en",
    ) -> None:
        self._score_threshold = score_threshold
        self._language = language
        self._entities = entities
        self._analyzer: Any = None
        self._use_presidio = False

        try:
            from presidio_analyzer import AnalyzerEngine

            self._analyzer = AnalyzerEngine()
            self._use_presidio = True
        except ImportError:
            pass

    def scan(self, text: str) -> list[PIIEntity]:
        """Scan text for PII entities.

        Args:
            text: The text to scan.

        Returns:
            List of detected PIIEntity objects, sorted by start position.
        """
        if self._use_presidio:
            return self._scan_presidio(text)
        return self._scan_builtin(text)

    def redact(self, text: str) -> str:
        """Scan and redact PII entities from text.

        Replaces each detected entity with a placeholder like <EMAIL>.

        Args:
            text: The text to redact.

        Returns:
            Text with PII entities replaced by type placeholders.
        """
        entities = self.scan(text)
        if not entities:
            return text
        # Process from end to start to preserve offsets.
        result = text
        for entity in sorted(entities, key=lambda e: e.start, reverse=True):
            replacement = _REDACTION_TEMPLATE.format(entity_type=entity.entity_type)
            result = result[:entity.start] + replacement + result[entity.end:]
        return result

    def _scan_presidio(self, text: str) -> list[PIIEntity]:
        kwargs: dict[str, Any] = {
            "text": text,
            "language": self._language,
        }
        if self._entities:
            kwargs["entities"] = self._entities
        results = self._analyzer.analyze(**kwargs)
        return sorted(
            [
                PIIEntity(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=r.score,
                    text=text[r.start:r.end],
                )
                for r in results
                if r.score >= self._score_threshold
            ],
            key=lambda e: e.start,
        )

    def _scan_builtin(self, text: str) -> list[PIIEntity]:
        entities: list[PIIEntity] = []
        active_types = set(self._entities) if self._entities else None
        for entity_type, pattern, score in _BUILTIN_PATTERNS:
            if active_types and entity_type not in active_types:
                continue
            if score < self._score_threshold:
                continue
            for match in pattern.finditer(text):
                entities.append(PIIEntity(
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    text=match.group(),
                ))
        return sorted(entities, key=lambda e: e.start)
