"""Cross-server tool shadowing detection.

When an agent loads tools from multiple MCP servers, a malicious server can
register a tool with the same (or nearly the same) name as a legitimate tool
from a trusted server. The agent then calls the attacker's tool instead of
the real one. This is a confused-deputy attack at the tool registration layer.

Two detection strategies:

1. Edit distance (Levenshtein) for typosquatting: flag pairs from different
   servers with distance <= 2. No ML required.

2. Semantic embedding similarity for synonym attacks: an attacker names a
   tool "email_send" to shadow "send_email". Levenshtein distance is 6 but
   cosine similarity on embedded names is near 1.0. Use semantic_similarity_risk
   for this detection path.

Source attribution: Agent Audit (rule AGENT-055).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ShadowPair:
    """Two tools from different servers with suspiciously similar names."""

    tool_a: str
    server_a: str
    tool_b: str
    server_b: str
    distance: int  # Levenshtein distance


@dataclass(frozen=True)
class ShadowScanResult:
    """Result of cross-server tool shadow detection."""

    pairs: tuple[ShadowPair, ...]
    shadowed: bool


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance. O(mn) time, O(n) space."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Normalize case for comparison
    a = a.lower()
    b = b.lower()

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            if ca == cb:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev = curr
    return prev[-1]


def scan_cross_server_shadows(
    server_tools: dict[str, list[str]],
    max_distance: int = 2,
    principal: str = "system",
) -> ShadowScanResult:
    """Detect tool name shadowing across multiple MCP servers.

    Args:
        server_tools: Mapping of server_name -> list of tool names.
        max_distance: Levenshtein threshold. Pairs with distance <=
            max_distance are flagged. Default 2 catches typosquatting.
            Use 0 for exact-match-only detection.
        principal: Principal for emitted SecurityEvents.

    Returns:
        ShadowScanResult with all flagged pairs.
    """
    servers = list(server_tools.items())
    pairs: list[ShadowPair] = []

    # Compare every pair of (server_a, tool_a) x (server_b, tool_b) where
    # server_a != server_b. Only traverse each pair once (i < j).
    for i in range(len(servers)):
        server_a, tools_a = servers[i]
        for j in range(i + 1, len(servers)):
            server_b, tools_b = servers[j]
            for tool_a in tools_a:
                for tool_b in tools_b:
                    dist = _levenshtein(tool_a, tool_b)
                    if dist <= max_distance:
                        pairs.append(
                            ShadowPair(
                                tool_a=tool_a,
                                server_a=server_a,
                                tool_b=tool_b,
                                server_b=server_b,
                                distance=dist,
                            )
                        )

    result = ShadowScanResult(pairs=tuple(pairs), shadowed=bool(pairs))

    if result.shadowed:
        _emit_findings(result, principal)

    return result


@dataclass(frozen=True)
class ShadowRisk:
    """One candidate pair flagged by semantic similarity."""

    proposed: str
    registered: str
    similarity: float  # cosine similarity in [0, 1]


def semantic_similarity_risk(
    tool_name: str,
    registered_tools: Iterable[str],
    embedder: object = None,
    threshold: float = 0.88,
) -> list[ShadowRisk]:
    """Detect tool shadowing via embedding cosine similarity.

    Embeds the proposed tool name and each registered name, then flags
    pairs whose cosine similarity exceeds threshold. This catches synonym
    attacks that Levenshtein distance misses (e.g. "send_email" vs
    "email_send").

    Args:
        tool_name: The proposed (potentially malicious) tool name.
        registered_tools: Names already registered with the agent.
        embedder: Callable (str) -> list[float]. If None, falls back to
            tessera.mcp.embedding.get_embedder(). If that also returns
            None (package not installed), returns an empty list.
        threshold: Cosine similarity above which a pair is flagged.
            Default 0.88 balances recall and precision on tool name sets.

    Returns:
        List of ShadowRisk, one per registered tool above threshold.
        Empty list when no embedder is available or no pairs cross the
        threshold.
    """
    from tessera.mcp.embedding import cosine_similarity, get_embedder

    embed = embedder or get_embedder()
    if embed is None:
        return []

    proposed_vec = embed(tool_name)
    risks: list[ShadowRisk] = []
    for registered in registered_tools:
        registered_vec = embed(registered)
        sim = cosine_similarity(proposed_vec, registered_vec)
        if sim >= threshold:
            risks.append(ShadowRisk(proposed=tool_name, registered=registered, similarity=sim))
    return risks


def _emit_findings(result: ShadowScanResult, principal: str) -> None:
    from tessera.events import EventKind, SecurityEvent, emit

    # Emit one event per flagged pair. Callers with many servers may want
    # to debounce; that's their problem.
    for pair in result.pairs:
        kind = "exact_shadow" if pair.distance == 0 else "typosquatting"
        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=principal,
                detail={
                    "scanner": "cross_server_tool_shadow",
                    "kind": kind,
                    "tool_a": pair.tool_a,
                    "server_a": pair.server_a,
                    "tool_b": pair.tool_b,
                    "server_b": pair.server_b,
                    "levenshtein_distance": pair.distance,
                    "owasp": "LLM09",
                    "rule": "AGENT-055",
                },
            )
        )
