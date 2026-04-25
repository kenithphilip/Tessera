# RAG Robustness: Certifiable Defense Against Retrieval Corruption

## Threat model

Retrieval-augmented generation (RAG) pipelines are vulnerable to
**retrieval corruption**: an attacker embeds an adversarial payload in
one or more documents that will be retrieved in response to legitimate
user queries. When the LLM processes those documents, it may follow the
embedded instructions instead of the user's query.

Concretely, the attacker controls a subset of the documents in the
knowledge base (or in a shared corpus the agent queries). The attacker's
goal is to produce a response that the user did not authorize, such as
exfiltrating data, taking a destructive action, or returning misleading
information.

This is distinct from direct prompt injection (where the attacker is the
user) and from model-level attacks (out of scope for Tessera). It is a
specific case of indirect prompt injection where the injection vector is
the retrieval corpus rather than a web page or tool output.

**Threat already covered elsewhere:** `tessera.scanners` (heuristic,
directive, intent scanners) and `RAGRetrievalGuard` catch known injection
patterns in individual chunks before they enter the context. The
certifiably robust guard in `CertifiablyRobustRAGGuard` is a complementary
defense that operates at the query level and provides a formal robustness
bound, not just a heuristic.


## Technique: RobustRAG

Reference: Xiang et al., "Certifiably Robust RAG against Retrieval
Corruption," arXiv:2405.15556, 2024.

The core idea is **multi-subset aggregation**: instead of querying the LLM
against all retrieved documents at once, the guard samples several random
subsets of size `subset_size` from the retrieved corpus, queries the LLM
once per subset, and aggregates the results by majority voting.

The certifiable robustness argument: if the attacker has corrupted at most
`k` documents in the entire corpus, and each subset has size `subset_size`,
then the expected number of corrupted documents in any individual subset is
bounded by `k * (subset_size / corpus_size)`. For small `k` and moderate
`subset_size`, most subsets are corruption-free and the majority vote
overrides the adversarial answers from the few subsets that contain a
corrupted document.

Two aggregation modes are supported:

- **majority_keyword** (default): tokenizes each answer and elects the
  token that appears in the majority of answers. Fast, deterministic, and
  the primary mode from Section 4.1 of the paper.
- **text_decoding**: finds the longest substring shared by the majority of
  answers. Higher recall for long-form answers; slightly more expensive.
  A simplified v1.0 approximation of the token-level decoding in Section 4.2.

**Divergence signal:** when subset answers diverge significantly (token
overlap below 50%), `RobustRAGResult.signal` is set to `True` and a
`GUARDRAIL_DECISION` SecurityEvent is emitted. This does not block the
query; it is a signal for downstream policy to escalate or review. In high-
assurance paths, treat `signal=True` as a reason to gate on human approval
via `tessera.approval`.


## Threshold trade-offs

The three parameters that control robustness and latency are:

| Parameter | Effect | Trade-off |
|---|---|---|
| `subset_size` | Documents per subset | Larger subsets improve answer quality per query but increase the odds that a corrupted document appears in every subset, weakening the bound. |
| `num_subsets` | Number of subsets queried | More subsets improve the majority vote stability but multiply query latency linearly. 5x is the practical ceiling. |
| `corruption_tolerance_k` | Number of corrupted docs the bound tolerates | Higher k requires more subsets to maintain robustness. This field is declarative: it records your assurance claim, it does not enforce it automatically. |

**5x latency ceiling:** running 5 subsets takes approximately 5x the
single-query latency when the LLM calls are sequential (the default). For
paths where latency is critical, reduce `num_subsets` to 3 and accept a
weaker majority vote.

The paper (Section 4.4) shows that RobustRAG achieves 80-90% clean
accuracy with k=2 and subset_size=5 on the Natural Questions and TriviaQA
benchmarks. These numbers assume the LLM is correct on clean subsets; a
weaker LLM or smaller subset_size will reduce clean accuracy.


## Configuration recipes

### "Conservative" (k=2, subsets=7)

Use this on SOC critical paths where the retrieval corpus is partially
untrusted (third-party threat intelligence feeds, shared knowledge bases).

```python
from tessera.rag_guard import CertifiablyRobustRAGGuard, RobustRAGConfig

guard = CertifiablyRobustRAGGuard(
    config=RobustRAGConfig(
        subset_size=5,
        num_subsets=7,
        aggregation="majority_keyword",
        corruption_tolerance_k=2,
    ),
    llm_callable=my_llm,
)
```

Latency cost: approximately 7x single-query. Suitable when the corpus may
contain up to 2 adversarial documents and the path is not latency-sensitive.

### "Balanced" (k=1, subsets=5)

The default configuration. Balances cost and robustness for most RAG use
cases where the corpus is mostly trusted but may contain one adversarial
document.

```python
guard = CertifiablyRobustRAGGuard(
    config=RobustRAGConfig(
        subset_size=3,
        num_subsets=5,
        aggregation="majority_keyword",
        corruption_tolerance_k=1,
    ),
    llm_callable=my_llm,
)
```

Latency cost: approximately 5x single-query. This is the default when you
construct `RobustRAGConfig()` with no arguments.

### "Detection only" (k=0, subsets=3)

Emit the divergence signal for telemetry warming without depending on the
aggregated answer. Set `corruption_tolerance_k=0` to document that you are
not claiming any robustness guarantee, then use the raw first answer.

```python
guard = CertifiablyRobustRAGGuard(
    config=RobustRAGConfig(
        subset_size=3,
        num_subsets=3,
        aggregation="majority_keyword",
        corruption_tolerance_k=0,
    ),
    llm_callable=my_llm,
)
result = guard.query(question, docs)
if result.signal:
    metrics.increment("rag.corruption_signal")
# Use per_subset_answers[0] or your own aggregation.
```

Latency cost: approximately 3x single-query. Useful in the first 2-4 weeks
of deployment to understand the signal rate in your corpus before choosing
a production k value.


## Defense in depth with existing Tessera scanners

`CertifiablyRobustRAGGuard` operates at the query level. Combine it with
the existing scan-on-retrieval primitive for layered defense:

```python
from tessera.rag_guard import RAGRetrievalGuard, CertifiablyRobustRAGGuard, RobustRAGConfig
from tessera.scanners.multi_turn import MultiTurnScanner
from tessera.scanners.memory_poisoning import MemoryPoisoningScanner

# Layer 1: scan each chunk for known injection patterns before retrieval.
scan_guard = RAGRetrievalGuard(taint_threshold=0.65, reject_threshold=0.85)
clean_chunks = []
for chunk in vector_store.query(question):
    result = scan_guard.scan_chunk(chunk.text, source_id=chunk.id)
    if result.safe:
        clean_chunks.append(chunk.text)

# Layer 2: certifiably robust query over the clean chunks.
robust_guard = CertifiablyRobustRAGGuard(
    config=RobustRAGConfig(subset_size=3, num_subsets=5, corruption_tolerance_k=1),
    llm_callable=my_llm,
)
result = robust_guard.query(question, clean_chunks)

# Layer 3: gate on human approval when the signal fires.
if result.signal:
    approval_gate.request(
        action="rag_answer",
        context={"question": question, "signal": True},
    )
```

**Multi-turn and memory poisoning scanners** (`tessera.scanners.multi_turn`,
`tessera.scanners.memory_poisoning`) defend against injection that arrives
via conversational history or agent memory rather than the retrieval corpus.
Run them on the full session context separately from the RAG retrieval path.

The combination of scan-on-retrieval (catches known patterns early),
certifiably robust querying (bounds the impact of unknown patterns), and
approval gating on signal (human-in-the-loop for flagged queries) gives
three independent failure modes an attacker must bypass simultaneously.
