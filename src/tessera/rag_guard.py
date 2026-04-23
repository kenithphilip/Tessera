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

from collections.abc import Sequence
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


# ---------------------------------------------------------------------------
# Retrieval pattern tracker (PoisonedRAG defense)
# ---------------------------------------------------------------------------


class RetrievalPatternTracker:
    """Detect chunks with suspiciously narrow activation patterns.

    PoisonedRAG (Zou et al., USENIX Security 2025) showed that just 5
    crafted documents among millions achieve 90% attack success. These
    adversarial documents are optimized for high similarity to specific
    target queries, producing a narrow activation pattern: the document
    is retrieved many times but always for the same 1-2 queries.

    This tracker records which queries retrieve each chunk. Chunks with
    high retrieval frequency but low query diversity are flagged as
    potential PoisonedRAG artifacts.

    References:
    - PoisonedRAG (USENIX Security 2025): 5 docs, 90% ASR
    - Tan et al.: scoring-based filtering for narrow-activation docs
    - Prompt Security "Embedded Threat" (2025): poisoned vectors can
      sit unnoticed for years before activating
    """

    def __init__(self, min_retrievals: int = 10, max_unique_ratio: float = 0.2) -> None:
        self._history: dict[str, list[str]] = {}  # chunk_id -> [query_hashes]
        self._min_retrievals = min_retrievals
        self._max_unique_ratio = max_unique_ratio

    def record(self, chunk_id: str, query: str) -> None:
        """Record that a query retrieved a specific chunk."""
        import hashlib
        qhash = hashlib.sha256(query.encode()).hexdigest()[:16]
        if chunk_id not in self._history:
            self._history[chunk_id] = []
        self._history[chunk_id].append(qhash)

    def is_suspicious(self, chunk_id: str) -> bool:
        """Check if a chunk has a narrow activation pattern.

        Returns True if the chunk has been retrieved many times but
        always for very few unique queries (signature of adversarial
        documents optimized for specific queries).
        """
        history = self._history.get(chunk_id, [])
        if len(history) < self._min_retrievals:
            return False
        unique = len(set(history))
        ratio = unique / len(history)
        return ratio <= self._max_unique_ratio

    def get_stats(self, chunk_id: str) -> dict[str, int | float]:
        """Return retrieval statistics for a chunk."""
        history = self._history.get(chunk_id, [])
        total = len(history)
        unique = len(set(history))
        return {
            "total_retrievals": total,
            "unique_queries": unique,
            "diversity_ratio": unique / total if total > 0 else 1.0,
        }

    def clear(self, chunk_id: str | None = None) -> None:
        """Clear tracking history."""
        if chunk_id is None:
            self._history.clear()
        else:
            self._history.pop(chunk_id, None)


class EmbeddingAnomalyChecker:
    """Detect anomalous embeddings that may indicate adversarial documents.

    Adversarial RAG documents have embeddings optimized for retrieval,
    not for content faithfulness. This produces anomalies: unusual
    magnitude, outlier distance from the corpus centroid, or
    suspiciously high similarity scores.

    Requires baseline statistics computed from a legitimate corpus.
    Without baseline stats, only similarity threshold checking is active.

    References:
    - OWASP LLM08:2025: embedding space manipulation
    - Amine Raji (2025): embedding anomaly detection reduced
      PoisonedRAG success from 95% to 20%
    """

    def __init__(
        self,
        max_similarity: float = 0.98,
        magnitude_threshold: float | None = None,
        distance_threshold: float | None = None,
    ) -> None:
        self._max_similarity = max_similarity
        self._magnitude_threshold = magnitude_threshold
        self._distance_threshold = distance_threshold
        self._centroid: list[float] | None = None

    def set_baseline(
        self,
        centroid: list[float],
        magnitude_p99: float,
        distance_p95: float,
    ) -> None:
        """Set baseline statistics from a legitimate corpus.

        Args:
            centroid: Mean embedding vector of the corpus.
            magnitude_p99: 99th percentile of embedding magnitudes.
            distance_p95: 95th percentile of distances from centroid.
        """
        self._centroid = centroid
        self._magnitude_threshold = magnitude_p99
        self._distance_threshold = distance_p95

    def check(
        self,
        embedding: list[float],
        similarity_score: float,
    ) -> list[str]:
        """Check an embedding for anomalies.

        Args:
            embedding: The chunk's embedding vector.
            similarity_score: The retrieval similarity score.

        Returns:
            List of detected anomaly descriptions. Empty if clean.
        """
        anomalies: list[str] = []

        # Suspiciously high similarity
        if similarity_score > self._max_similarity:
            anomalies.append(
                f"suspiciously high similarity ({similarity_score:.3f} > {self._max_similarity})"
            )

        if self._centroid is None:
            return anomalies

        # Magnitude check
        magnitude = sum(x * x for x in embedding) ** 0.5
        if self._magnitude_threshold and magnitude > self._magnitude_threshold:
            anomalies.append(
                f"unusual embedding magnitude ({magnitude:.2f} > {self._magnitude_threshold:.2f})"
            )

        # Distance from centroid
        if self._distance_threshold and len(embedding) == len(self._centroid):
            dist_sq = sum(
                (a - b) ** 2 for a, b in zip(embedding, self._centroid)
            )
            distance = dist_sq ** 0.5
            if distance > self._distance_threshold:
                anomalies.append(
                    f"outlier distance from corpus centroid ({distance:.2f} > {self._distance_threshold:.2f})"
                )

        return anomalies


# ---------------------------------------------------------------------------
# Baseline computation (parity port from
# rust/crates/tessera-scanners/src/rag.rs::compute_baseline; see
# rust/crates/tessera-scanners/tests/python_rag_baseline_interop.rs for
# the cross-language byte-equal test).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Baseline:
    """Baseline statistics for ``EmbeddingAnomalyChecker.set_baseline``."""

    centroid: list[float]
    magnitude_p99: float
    distance_p95: float


class BaselineError(ValueError):
    """Raised by :func:`compute_baseline` when the corpus is invalid."""


def _nearest_rank_index(n: int, percentile: int) -> int:
    """Nearest-rank percentile index. ``n >= 1`` enforced by the caller."""
    return ((n - 1) * percentile) // 100


def compute_baseline(corpus: Sequence[Sequence[float]]) -> Baseline:
    """Compute baseline statistics from a corpus of legitimate embeddings.

    ``corpus`` must be non-empty, every row must share the same dimension,
    and no entry may be NaN. Percentiles use nearest-rank ordering
    (``((n - 1) * pct) // 100``); on a 100-element corpus this puts the
    p99 at index 99 and the p95 at index 95.

    The Rust port at ``tessera-scanners::compute_baseline`` uses the same
    rule, so the cross-language interop test pins both sides byte-for-byte.

    Returns a :class:`Baseline` suitable for
    :meth:`EmbeddingAnomalyChecker.set_baseline`.
    """
    if not corpus:
        raise BaselineError("corpus must not be empty")

    dim = len(corpus[0])
    for idx, row in enumerate(corpus):
        if len(row) != dim:
            raise BaselineError(
                f"embedding at index {idx} has dimension {len(row)}, expected {dim}"
            )
        if any(x != x for x in row):  # NaN check (NaN != NaN)
            raise BaselineError(f"embedding at index {idx} contains NaN")

    n = len(corpus)
    centroid = [0.0] * dim
    for row in corpus:
        for i, x in enumerate(row):
            centroid[i] += x
    centroid = [v / n for v in centroid]

    magnitudes = sorted(
        sum(x * x for x in row) ** 0.5 for row in corpus
    )
    distances = sorted(
        sum((a - b) ** 2 for a, b in zip(row, centroid)) ** 0.5 for row in corpus
    )

    return Baseline(
        centroid=centroid,
        magnitude_p99=magnitudes[_nearest_rank_index(len(magnitudes), 99)],
        distance_p95=distances[_nearest_rank_index(len(distances), 95)],
    )


def set_baseline_from_corpus(
    checker: EmbeddingAnomalyChecker, corpus: Sequence[Sequence[float]]
) -> Baseline:
    """Convenience: compute a baseline and install it on ``checker``."""
    baseline = compute_baseline(corpus)
    checker.set_baseline(
        centroid=list(baseline.centroid),
        magnitude_p99=baseline.magnitude_p99,
        distance_p95=baseline.distance_p95,
    )
    return baseline
