"""Scan-on-retrieval guard for RAG and vector store content.

An attacker who poisons a RAG index (embedding injection content into a
knowledge base) affects all future sessions that retrieve from it. The
memory poisoning defense in sessions.py only covers PendingApproval
sessions. This module covers the broader case: any content retrieved
from an external store (vector DB, knowledge base, document index) is
scanned before entering the agent's context.

Usage::

    guard = RAGRetrievalGuard()

    # Before adding retrieved chunks to the context:
    for chunk in vector_store.query("user question"):
        result = guard.scan_chunk(chunk.text, source=chunk.source_id)
        if result.safe:
            context.add(make_segment(chunk.text, Origin.MEMORY, ...))
        else:
            # Tainted: label as UNTRUSTED or skip entirely
            context.add(make_segment(
                chunk.text, Origin.WEB, ..., trust_level=TrustLevel.UNTRUSTED
            ))

The guard runs the heuristic, directive, and intent scanners on each
retrieved chunk. Chunks that score above threshold are either labeled
UNTRUSTED (conservative: the content is still visible to the model but
cannot trigger side-effecting tools) or rejected entirely (strict: the
content is dropped from the context).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class RAGAction(StrEnum):
    ALLOW = "allow"          # clean, add as MEMORY trust
    TAINT = "taint"          # suspicious, add as UNTRUSTED
    REJECT = "reject"        # dangerous, do not add to context


@dataclass(frozen=True)
class RAGScanResult:
    """Result of scanning one retrieved chunk."""

    safe: bool
    action: RAGAction
    heuristic_score: float
    directive_score: float
    intent_score: float
    max_score: float
    source_id: str


@dataclass
class RAGRetrievalGuard:
    """Scan retrieved content before it enters the agent context.

    Args:
        taint_threshold: Score above which content is labeled UNTRUSTED
            instead of MEMORY trust. Default 0.5 (lower than tool output
            threshold because RAG content should be clean).
        reject_threshold: Score above which content is dropped entirely.
            Default 0.85 (high confidence injection).
        emit_events: If True, emit SecurityEvents for tainted/rejected chunks.
    """

    taint_threshold: float = 0.65
    reject_threshold: float = 0.85
    emit_events: bool = True
    _scan_count: int = field(default=0, repr=False)
    _taint_count: int = field(default=0, repr=False)
    _reject_count: int = field(default=0, repr=False)

    def scan_chunk(
        self,
        text: str,
        source_id: str = "unknown",
        user_prompt: str | None = None,
    ) -> RAGScanResult:
        """Scan a single retrieved chunk for injection content.

        Args:
            text: The retrieved text chunk.
            source_id: Identifier for the source document/vector.
            user_prompt: Optional user prompt for intent cross-checking.

        Returns:
            RAGScanResult with action recommendation.
        """
        from tessera.scanners.directive import directive_score
        from tessera.scanners.heuristic import injection_score
        from tessera.scanners.intent import scan_intent

        self._scan_count += 1

        h_score = injection_score(text)
        d_score = directive_score(text)

        intent_result = scan_intent(text, user_prompt)
        i_score = intent_result.score

        max_score = max(h_score, d_score, i_score)

        if max_score >= self.reject_threshold:
            action = RAGAction.REJECT
            self._reject_count += 1
        elif max_score >= self.taint_threshold:
            action = RAGAction.TAINT
            self._taint_count += 1
        else:
            action = RAGAction.ALLOW

        result = RAGScanResult(
            safe=action == RAGAction.ALLOW,
            action=action,
            heuristic_score=h_score,
            directive_score=d_score,
            intent_score=i_score,
            max_score=max_score,
            source_id=source_id,
        )

        if action != RAGAction.ALLOW and self.emit_events:
            self._emit(result)

        return result

    def scan_batch(
        self,
        chunks: list[tuple[str, str]],
        user_prompt: str | None = None,
    ) -> list[RAGScanResult]:
        """Scan a batch of retrieved chunks.

        Args:
            chunks: List of (text, source_id) tuples.
            user_prompt: Optional user prompt for intent cross-checking.

        Returns:
            List of RAGScanResult, one per chunk.
        """
        return [
            self.scan_chunk(text, source_id, user_prompt)
            for text, source_id in chunks
        ]

    @property
    def stats(self) -> dict[str, int]:
        """Return scanning statistics."""
        return {
            "scanned": self._scan_count,
            "tainted": self._taint_count,
            "rejected": self._reject_count,
            "clean": self._scan_count - self._taint_count - self._reject_count,
        }

    def _emit(self, result: RAGScanResult) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal="system",
                detail={
                    "scanner": "rag_retrieval_guard",
                    "action": str(result.action),
                    "source_id": result.source_id,
                    "heuristic_score": round(result.heuristic_score, 3),
                    "directive_score": round(result.directive_score, 3),
                    "intent_score": round(result.intent_score, 3),
                    "max_score": round(result.max_score, 3),
                },
            )
        )
