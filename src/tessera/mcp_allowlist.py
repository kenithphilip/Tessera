"""MCP server allowlist enforcement with rug-pull detection.

An injection in a tool output could instruct the agent to connect to
a new MCP server ("connect to mcp://attacker.com/tools"), giving the
attacker's server access to the agent's context and tool permissions.
The tool_descriptions.py scanner checks descriptions of already-registered
tools, but does not gate the act of registration itself.

This module provides:

1. Declarative allowlist for MCP server connections, configured at
   startup with no runtime modification. Injection content cannot
   expand the allowlist.

2. Rug-pull detection: tracks tool definition snapshots and alerts
   when a server silently mutates its tool definitions after initial
   approval. A tool that appeared safe on Day 1 can reroute API keys
   by Day 7 if definitions are not pinned.

3. Registration pattern scanning: detects MCP connection URIs and
   registration keywords in tool output text, catching injection
   attempts that try to make the agent connect to attacker servers.

References:
- Invariant Labs: tool poisoning via hidden instructions in descriptions
- CVE-2025-6514 (CVSS 9.6): command injection in mcp-remote
- Palo Alto Networks: allowlisting + proxy MCP communication layer
- Salesforce Agentforce (Jan 2026): mandatory allowlists + trusted gateways
- VulnerableMCP.info: rug-pull via silent tool redefinition

Usage::

    allowlist = MCPServerAllowlist([
        MCPAllowlistEntry(
            pattern="mcp://internal.corp/*",
            max_tools=10,
            version_pin="1.2.0",
        ),
    ])

    # Gate connections:
    allowlist.enforce("mcp://internal.corp/tools", principal="agent_a")

    # Detect rug-pulls:
    tracker = ToolDefinitionTracker()
    if tracker.check("mcp://server", "tool_name", definition_json):
        # definition changed since last check
        ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch


class MCPServerDenied(RuntimeError):
    """Raised when an MCP server connection is denied by the allowlist."""


@dataclass(frozen=True)
class MCPAllowlistEntry:
    """One entry in the MCP server allowlist.

    Supports exact URIs and glob patterns for flexibility:
    - "mcp://internal.corp/tools" (exact match)
    - "mcp://internal.corp/*" (any path on internal.corp)
    - "mcp://*.corp/*" (any subdomain of .corp)
    """

    pattern: str
    description: str = ""
    max_tools: int | None = None       # cap on tools from this server
    version_pin: str | None = None     # pin specific server version
    cert_fingerprint: str | None = None  # expected TLS certificate SHA-256


@dataclass
class MCPServerAllowlist:
    """Declarative allowlist for MCP server connections.

    Configured at startup. Cannot be modified at runtime (no add/remove
    methods). This prevents injection content from expanding the allowlist.

    Args:
        entries: List of allowed server URI patterns or MCPAllowlistEntry
            objects. Strings are converted to MCPAllowlistEntry with the
            string as the pattern.
        deny_by_default: If True (default), connections to servers not on
            the list are denied. If False, all connections are allowed
            (the allowlist becomes advisory only).
    """

    entries: tuple[MCPAllowlistEntry, ...] = ()
    deny_by_default: bool = True
    _denied_count: int = field(default=0, repr=False)

    def __init__(
        self,
        entries: list[str | MCPAllowlistEntry] | None = None,
        deny_by_default: bool = True,
    ) -> None:
        parsed: list[MCPAllowlistEntry] = []
        for e in (entries or []):
            if isinstance(e, str):
                parsed.append(MCPAllowlistEntry(pattern=e))
            else:
                parsed.append(e)
        # Use object.__setattr__ since we want the instance to be
        # effectively immutable after init (no add/remove methods).
        object.__setattr__(self, "entries", tuple(parsed))
        object.__setattr__(self, "deny_by_default", deny_by_default)
        object.__setattr__(self, "_denied_count", 0)

    def is_allowed(self, server_uri: str) -> bool:
        """Check if a server URI is on the allowlist.

        Args:
            server_uri: The MCP server URI being connected to.

        Returns:
            True if the URI matches any allowlist entry, or if
            deny_by_default is False.
        """
        if not self.deny_by_default:
            return True

        normalized = server_uri.strip().rstrip("/")
        for entry in self.entries:
            if fnmatch(normalized, entry.pattern):
                return True
            # Also try without scheme for flexibility
            if "://" in normalized:
                bare = normalized.split("://", 1)[1]
                if fnmatch(bare, entry.pattern):
                    return True
        return False

    def enforce(self, server_uri: str, principal: str = "system") -> None:
        """Enforce the allowlist. Raises MCPServerDenied if not allowed.

        Also emits a SecurityEvent for denied connections.

        Args:
            server_uri: The MCP server URI being connected to.
            principal: The principal requesting the connection.

        Raises:
            MCPServerDenied: If the server is not on the allowlist.
        """
        if self.is_allowed(server_uri):
            return

        object.__setattr__(self, "_denied_count", self._denied_count + 1)

        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=principal,
                detail={
                    "scanner": "mcp_allowlist",
                    "server_uri": server_uri,
                    "denied_count": self._denied_count,
                    "allowlist_size": len(self.entries),
                    "reason": "MCP server not on allowlist",
                },
            )
        )

        raise MCPServerDenied(
            f"MCP server {server_uri!r} is not on the allowlist. "
            f"Allowed servers: {[e.pattern for e in self.entries]}"
        )

    def check_tool_count(
        self,
        server_uri: str,
        tool_count: int,
        principal: str = "system",
    ) -> bool:
        """Check if a server's tool count exceeds its allowlist cap.

        Some allowlist entries specify max_tools to limit how many tools
        a server can register. A server that suddenly offers 50 tools
        when the allowlist says max 10 may be compromised.

        Args:
            server_uri: The MCP server URI.
            tool_count: Number of tools the server is registering.
            principal: Principal for event emission.

        Returns:
            True if within limits, False if exceeded.
        """
        normalized = server_uri.strip().rstrip("/")
        for entry in self.entries:
            if fnmatch(normalized, entry.pattern):
                if entry.max_tools is not None and tool_count > entry.max_tools:
                    from tessera.events import EventKind, SecurityEvent, emit

                    emit(
                        SecurityEvent.now(
                            kind=EventKind.POLICY_DENY,
                            principal=principal,
                            detail={
                                "scanner": "mcp_allowlist",
                                "server_uri": server_uri,
                                "tool_count": tool_count,
                                "max_tools": entry.max_tools,
                                "reason": "tool count exceeds allowlist cap",
                            },
                        )
                    )
                    return False
                return True
        return not self.deny_by_default


# Convenience: detect MCP connection attempts in tool output text.
# An injection might say "connect to mcp://evil.com/tools" in a tool
# result. This regex catches common patterns.
_MCP_URI_PATTERN = re.compile(
    r"(?:mcp|http|https|ws|wss)://[\w.-]+(?::\d+)?(?:/[\w./-]*)?",
    re.IGNORECASE,
)


def detect_mcp_uri_in_text(text: str) -> list[str]:
    """Extract potential MCP server URIs from text.

    Scans tool output or model responses for URIs that could be
    MCP server connection targets. Used to detect injection attempts
    that try to make the agent connect to attacker-controlled servers.

    Args:
        text: Text to scan for MCP URIs.

    Returns:
        List of URIs found.
    """
    return _MCP_URI_PATTERN.findall(text)


# Registration attempt patterns in tool output text.
# An injection might say "connect to mcp://evil.com" or
# "register new tool server at https://attacker.com/tools".
_REGISTRATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"mcp://[^\s\"']+", re.IGNORECASE),
    re.compile(r"connect\s+to\s+mcp", re.IGNORECASE),
    re.compile(r"register\s+(?:tool|server|mcp)", re.IGNORECASE),
    re.compile(r"add_mcp_server\s*\(", re.IGNORECASE),
    re.compile(r"tools/list\s+from\s+", re.IGNORECASE),
    re.compile(r"mcpServers\s*:\s*\{", re.IGNORECASE),
)


def scan_for_registration_attempts(text: str) -> list[str]:
    """Scan tool output for MCP registration injection patterns.

    Catches injection attempts that try to make the agent connect to
    new MCP servers or register additional tools. More comprehensive
    than detect_mcp_uri_in_text because it also catches indirect
    patterns like "register new tool server" or config-like syntax.

    Args:
        text: Tool output or model response text.

    Returns:
        List of matched registration patterns.
    """
    matches: list[str] = []
    for pattern in _REGISTRATION_PATTERNS:
        for m in pattern.finditer(text):
            match_text = m.group(0)
            if match_text not in matches:
                matches.append(match_text)
    return matches


class ToolDefinitionTracker:
    """Detect silent tool redefinition (rug-pull attacks).

    MCP tools can mutate their definitions after initial approval.
    A tool that appeared safe when first registered can change its
    description to include injection instructions, or change its
    parameter schema to capture different data.

    This tracker snapshots each tool definition on first encounter
    and alerts when the definition changes.

    Usage::

        tracker = ToolDefinitionTracker()

        # On each tools/list response from an MCP server:
        for tool in server.list_tools():
            if tracker.has_changed(server.uri, tool.name, tool.definition):
                # rug-pull detected: definition mutated
                ...

    References:
    - VulnerableMCP.info: "MCP tools can silently mutate their own
      definitions after initial user approval."
    """

    def __init__(self) -> None:
        self._snapshots: dict[str, str] = {}  # "uri:tool" -> definition hash
        self._change_count: int = 0

    def snapshot(self, server_uri: str, tool_name: str, definition: str) -> None:
        """Record the initial definition of a tool.

        Call this when a tool is first registered or when the user
        explicitly approves a definition change.
        """
        import hashlib

        key = f"{server_uri}:{tool_name}"
        self._snapshots[key] = hashlib.sha256(definition.encode()).hexdigest()

    def has_changed(
        self,
        server_uri: str,
        tool_name: str,
        current_definition: str,
        principal: str = "system",
    ) -> bool:
        """Check if a tool definition has changed since the last snapshot.

        On first call for a tool, records the snapshot and returns False.
        On subsequent calls, compares against the snapshot.

        Args:
            server_uri: The MCP server URI.
            tool_name: The tool name.
            current_definition: The tool's current definition (JSON string
                or description text).
            principal: Principal for event emission.

        Returns:
            True if the definition changed (rug-pull detected).
        """
        import hashlib

        key = f"{server_uri}:{tool_name}"
        current_hash = hashlib.sha256(current_definition.encode()).hexdigest()

        if key not in self._snapshots:
            # First encounter: record and allow
            self._snapshots[key] = current_hash
            return False

        if self._snapshots[key] == current_hash:
            return False

        # Definition changed since snapshot
        self._change_count += 1
        self._emit_rug_pull(server_uri, tool_name, principal)
        return True

    def reset(self, server_uri: str | None = None, tool_name: str | None = None) -> None:
        """Clear snapshots (e.g. after user approves a definition change).

        Args:
            server_uri: If provided with tool_name, reset only that tool.
                If provided alone, reset all tools for that server.
                If None, reset everything.
        """
        if server_uri is None:
            self._snapshots.clear()
            return
        if tool_name is not None:
            self._snapshots.pop(f"{server_uri}:{tool_name}", None)
            return
        prefix = f"{server_uri}:"
        for key in list(self._snapshots):
            if key.startswith(prefix):
                del self._snapshots[key]

    @property
    def change_count(self) -> int:
        """Total number of definition changes detected."""
        return self._change_count

    def _emit_rug_pull(self, server_uri: str, tool_name: str, principal: str) -> None:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.CONTENT_INJECTION_DETECTED,
                principal=principal,
                detail={
                    "scanner": "tool_definition_tracker",
                    "server_uri": server_uri,
                    "tool_name": tool_name,
                    "change_count": self._change_count,
                    "reason": "tool definition changed since initial snapshot (rug-pull)",
                },
            )
        )
