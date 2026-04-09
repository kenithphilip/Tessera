"""Org-level MCP tool registry.

Per-agent configuration is not enough for this kind of security primitive.
If every agent has to remember to mark `fetch_url` as external, one of them
will forget, and the entire taint-tracking guarantee evaporates for that
agent. The registry moves that decision up to an org-level policy file
that individual agents cannot opt out of.

Semantics:

    - Agents can ADD tools to their local external set.
    - Agents cannot REMOVE tools from the registry.
    - Effective external set = registry UNION agent-local.

Load the registry from JSON at startup (or build one in code for tests).
The registry is intentionally not a singleton: pass it explicitly into
MCPInterceptor. Dependency injection beats globals for testing and for
multi-tenant deployments.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolRegistry:
    """Org-level set of MCP tools that must be treated as external fetchers.

    Any tool in `external_tools` is labeled `Origin.WEB` / `TrustLevel.UNTRUSTED`
    regardless of what the calling agent says. This is the load-bearing
    security property: agents cannot trust-launder a tool by omitting it
    from their local config.
    """

    external_tools: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_dict(cls, data: dict) -> "ToolRegistry":
        """Build a registry from a plain dict (e.g. parsed JSON)."""
        tools = data.get("external_tools", [])
        if not isinstance(tools, list):
            raise ValueError("external_tools must be a list of tool names")
        return cls(external_tools=frozenset(str(t) for t in tools))

    @classmethod
    def from_file(cls, path: str | Path) -> "ToolRegistry":
        """Load a registry from a JSON file.

        Expected shape:
            {"external_tools": ["fetch_url", "web_search", ...]}
        """
        return cls.from_dict(json.loads(Path(path).read_text()))

    def effective_external(self, agent_local: set[str] | None = None) -> frozenset[str]:
        """Merge the registry's external set with an agent's local additions.

        The union is one-way: the registry always wins on inclusion. An
        agent cannot drop a tool the registry marks as external.
        """
        if not agent_local:
            return self.external_tools
        return self.external_tools | frozenset(agent_local)

    def is_external(self, tool_name: str, agent_local: set[str] | None = None) -> bool:
        return tool_name in self.effective_external(agent_local)
