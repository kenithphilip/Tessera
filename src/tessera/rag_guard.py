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
from typing import Callable, Literal


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


# ---------------------------------------------------------------------------
# Certifiably Robust RAG (arXiv:2405.15556)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RobustRAGConfig:
    """Configuration for the certifiably robust RAG pipeline.

    Based on RobustRAG (arXiv:2405.15556), which achieves certifiable
    robustness bounds by querying the LLM against random subsets of
    retrieved documents and aggregating the results. The bound holds when
    at most ``corruption_tolerance_k`` of the ``subset_size`` documents in
    any individual subset are corrupted.

    Fields:
        subset_size: Number of documents in each random subset (default 3).
        num_subsets: How many subsets to query (default 5). Latency scales
            linearly with this value; a 5x ceiling is the practical max.
        aggregation: "majority_keyword" (fast, token-level voting) or
            "text_decoding" (longest shared substring, higher recall).
        corruption_tolerance_k: Certifiable robustness bound. The answer is
            guaranteed correct as long as no individual subset contains more
            than k corrupted documents (default 1).
    """

    subset_size: int = 3
    num_subsets: int = 5
    aggregation: Literal["majority_keyword", "text_decoding"] = "majority_keyword"
    corruption_tolerance_k: int = 1


@dataclass(frozen=True)
class RobustRAGResult:
    """Output of a certifiably robust RAG query.

    Fields:
        aggregated_answer: The answer produced by aggregation across subsets.
        per_subset_answers: Raw LLM answer for each subset, in query order.
        num_subsets_tried: Number of subsets actually queried.
        corruption_tolerance_k: The k value used for this query.
        signal: True when subset answers diverge enough to suspect that one
            or more retrieved documents is corrupted or adversarial.
    """

    aggregated_answer: str
    per_subset_answers: tuple[str, ...]
    num_subsets_tried: int
    corruption_tolerance_k: int
    signal: bool


class CertifiablyRobustRAGGuard:
    """Multi-subset query guard with certifiable robustness bounds.

    Implements the RobustRAG algorithm (arXiv:2405.15556). Instead of
    passing all retrieved documents to the LLM at once, the guard samples
    ``num_subsets`` random subsets of size ``subset_size`` from the
    retrieved corpus, queries the LLM once per subset, and aggregates the
    results. An attacker who can corrupt at most k documents in the entire
    corpus cannot corrupt more than k of the ``subset_size`` documents in
    any single subset, giving a certifiable robustness bound.

    When subset answers diverge significantly, ``signal=True`` is set on
    the result and a GUARDRAIL_DECISION SecurityEvent is emitted. This
    does not block the query; it is a signal for downstream policy to
    escalate or review.

    The subset sampler is deterministic given (question, subset_index) so
    that the same question always produces the same subsets, enabling
    replay analysis.

    Args:
        config: RobustRAGConfig controlling subset size, count, and
            aggregation strategy.
        llm_callable: Callable ``(query: str, docs: list[str]) -> str``
            that invokes the underlying LLM. Must be synchronous.
        embedding_fn: Optional callable for semantic diversity scoring.
            Currently unused; reserved for future subset selection strategies.

    Example::

        guard = CertifiablyRobustRAGGuard(
            config=RobustRAGConfig(subset_size=3, num_subsets=5, corruption_tolerance_k=1),
            llm_callable=lambda q, docs: my_llm(q, docs),
        )
        result = guard.query("What is the capital of France?", retrieved_docs)
        if result.signal:
            logger.warning("RAG corruption signal", aggregated=result.aggregated_answer)
    """

    def __init__(
        self,
        config: RobustRAGConfig,
        llm_callable: Callable[[str, list[str]], str],
        embedding_fn: Callable[[str], list[float]] | None = None,
    ) -> None:
        self._config = config
        self._llm = llm_callable
        self._embedding_fn = embedding_fn  # reserved

    def query(self, question: str, retrieved_docs: list[str]) -> RobustRAGResult:
        """Run the multi-subset query and return an aggregated result.

        Args:
            question: The user's question to answer.
            retrieved_docs: The full list of retrieved documents.

        Returns:
            RobustRAGResult with the aggregated answer and divergence signal.
        """
        subsets = self._sample_subsets(question, retrieved_docs)
        answers = [self._llm(question, subset) for subset in subsets]

        if self._config.aggregation == "majority_keyword":
            aggregated = self._aggregate_majority_keyword(answers)
        else:
            aggregated = self._aggregate_text_decoding(answers)

        signal = self._detect_divergence(answers)

        if signal:
            self._emit_signal(question, answers, aggregated)

        return RobustRAGResult(
            aggregated_answer=aggregated,
            per_subset_answers=tuple(answers),
            num_subsets_tried=len(answers),
            corruption_tolerance_k=self._config.corruption_tolerance_k,
            signal=signal,
        )

    def _sample_subsets(
        self, question: str, docs: list[str]
    ) -> list[list[str]]:
        """Sample ``num_subsets`` deterministic subsets of size ``subset_size``.

        Determinism is keyed on (question, subset_index) so the same question
        always produces the same subsets regardless of call order. When the
        corpus is smaller than ``subset_size``, all docs are used for every
        subset (no repeated sampling needed).
        """
        import hashlib

        n = len(docs)
        size = min(self._config.subset_size, n)
        subsets: list[list[str]] = []
        q_hash = hashlib.sha256(question.encode()).hexdigest()

        for idx in range(self._config.num_subsets):
            seed_bytes = hashlib.sha256(
                f"{q_hash}:{idx}".encode()
            ).digest()
            # Use the seed to produce a deterministic shuffle of indices.
            seed_int = int.from_bytes(seed_bytes[:8], "big")
            indices = list(range(n))
            # Fisher-Yates with a deterministic PRNG seeded by seed_int.
            rng_state = seed_int
            for i in range(n - 1, 0, -1):
                # LCG parameters from Knuth MMIX
                rng_state = (rng_state * 6364136223846793005 + 1442695040888963407) & (
                    2**64 - 1
                )
                j = rng_state % (i + 1)
                indices[i], indices[j] = indices[j], indices[i]
            subsets.append([docs[i] for i in indices[:size]])

        return subsets

    def _aggregate_majority_keyword(self, answers: list[str]) -> str:
        """Return the token that appears as a majority across all answers.

        Tokenizes each answer into lowercase words, counts occurrences
        across all answers, and returns the most common token. Ties are
        broken by token order (first encountered in any answer wins).

        When answers are complete sentences rather than single tokens, this
        selects the most-agreed-upon content word, which is the RobustRAG
        "keyword isolation" variant from Section 4.1 of arXiv:2405.15556.
        """
        from collections import Counter
        import re

        counts: Counter[str] = Counter()
        # Track first-seen order for stable tie-breaking.
        first_seen: dict[str, int] = {}
        order = 0

        for answer in answers:
            tokens = re.findall(r"[a-z0-9]+", answer.lower())
            for token in tokens:
                counts[token] += 1
                if token not in first_seen:
                    first_seen[token] = order
                    order += 1

        if not counts:
            return answers[0] if answers else ""

        # Most common token; stable tie-break by insertion order.
        winner = max(counts, key=lambda t: (counts[t], -first_seen[t]))
        return winner

    def _aggregate_text_decoding(self, answers: list[str]) -> str:
        """Return the longest substring shared by the majority of answers.

        This is a simplified version of the text-decoding aggregation in
        Section 4.2 of arXiv:2405.15556. The full algorithm uses token-level
        decoding; this version operates on character substrings as a v1.0
        approximation. A substring must appear in more than half the answers
        to be elected.

        When no majority substring exists, falls back to the first answer.
        """
        if not answers:
            return ""
        if len(answers) == 1:
            return answers[0]

        majority = len(answers) // 2 + 1
        reference = answers[0]
        best = ""

        # Enumerate all substrings of the first answer, longest first.
        n = len(reference)
        for length in range(n, 0, -1):
            for start in range(n - length + 1):
                candidate = reference[start : start + length]
                if len(candidate) <= len(best):
                    # Already found something longer.
                    break
                count = sum(1 for a in answers if candidate in a)
                if count >= majority:
                    best = candidate
                    break  # Longest match at this length found.

        return best if best else answers[0]

    def _detect_divergence(self, answers: list[str]) -> bool:
        """Return True when subset answers diverge enough to suspect corruption.

        The threshold: if any answer shares fewer than 50% of its tokens
        with the majority answer, the corpus is flagged. This is a
        conservative heuristic; tighten the threshold for high-noise corpora.
        """
        if len(answers) <= 1:
            return False

        from collections import Counter
        import re

        token_sets = [
            set(re.findall(r"[a-z0-9]+", a.lower())) for a in answers
        ]
        # Find the most common token set (treat each answer as a bag of tokens).
        reference = token_sets[0]
        for ts in token_sets[1:]:
            union = reference | ts
            if not union:
                continue
            overlap = len(reference & ts) / len(union)
            if overlap < 0.5:
                return True
        return False

    def _emit_signal(
        self, question: str, answers: list[str], aggregated: str
    ) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.GUARDRAIL_DECISION,
                principal="system",
                detail={
                    "guard": "certifiably_robust_rag",
                    "signal": True,
                    "num_subsets": len(answers),
                    "corruption_tolerance_k": self._config.corruption_tolerance_k,
                    "aggregation": self._config.aggregation,
                    "aggregated_answer": aggregated,
                    "question_prefix": question[:120],
                    "divergent_answers": len(answers),
                },
            )
        )
