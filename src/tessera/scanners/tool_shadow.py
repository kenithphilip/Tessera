"""Cross-server tool shadowing detection.

When an agent loads tools from multiple MCP servers, a malicious server can
register a tool with the same (or nearly the same) name as a legitimate tool
from a trusted server. The agent then calls the attacker's tool instead of
the real one. This is a confused-deputy attack at the tool registration layer.

Detection: compute edit distance between all tool names across servers.
Flag pairs with distance <= 2 (configurable) that come from different servers.
Distance 0 = identical name (direct shadow). Distance 1-2 = typosquatting.

Edit distance is computed with the Levenshtein algorithm (iterative DP, O(mn)
time). No ML required.

Source attribution: Agent Audit (rule AGENT-055).
"""

from __future__ import annotations

from dataclasses import dataclass


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
