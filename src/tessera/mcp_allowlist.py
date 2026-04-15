"""MCP server allowlist enforcement.

An injection in a tool output could instruct the agent to connect to
a new MCP server ("connect to mcp://attacker.com/tools"), giving the
attacker's server access to the agent's context and tool permissions.
The tool_descriptions.py scanner checks descriptions of already-registered
tools, but does not gate the act of registration itself.

This module provides a declarative allowlist for MCP server connections.
Any connection attempt to a server not on the allowlist is denied and
emits a SecurityEvent. The allowlist is configured at startup, not at
runtime, so injection content cannot modify it.

Usage::

    allowlist = MCPServerAllowlist([
        "mcp://internal.corp/tools",
        "mcp://approved-vendor.com/api",
    ])

    # In the MCP connection handler:
    if not allowlist.is_allowed(requested_uri):
        # deny and emit event
        ...

    # Or use the enforcement wrapper:
    allowlist.enforce(requested_uri, principal="agent_a")
    # raises MCPServerDenied if not on the list
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
    max_tools: int | None = None  # optional cap on tools from this server


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
