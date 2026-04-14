"""MCP baseline drift detection.

MCP servers are ephemeral and can change between connections. An MCP server
that passes initial security review and then changes its tool descriptions
before the agent's next session is an "MCP rug pull." This module detects it.

Usage::

    # At session start (or after initial vetting):
    baseline = MCPBaseline.snapshot(tools, server_name="acme-mcp")
    baseline.save("/var/lib/tessera/baselines/acme-mcp.json")

    # On subsequent connection:
    baseline = MCPBaseline.load("/var/lib/tessera/baselines/acme-mcp.json")
    result = baseline.check(current_tools)
    if result.drifted:
        # handle per policy: warn, deny-new, deny-all
        ...

The snapshot hashes each tool's name, description, and input schema using
SHA-256. Any change to any of these fields is drift.

Source attribution: Agent Audit mcp_baseline.py (rule AGENT-054).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DriftPolicy(StrEnum):
    """What to do when drift is detected."""

    WARN = "warn"
    DENY_NEW_TOOLS = "deny_new_tools"
    DENY_ALL = "deny_all"


@dataclass(frozen=True)
class ToolDrift:
    """Describes a single drifted tool."""

    tool_name: str
    kind: str  # "modified", "added", "removed"
    baseline_hash: str | None
    current_hash: str | None


@dataclass(frozen=True)
class DriftResult:
    """Result of comparing current tools against a saved baseline."""

    drifted: bool
    drifts: tuple[ToolDrift, ...]
    baseline_server: str
    current_tool_count: int
    baseline_tool_count: int


def _tool_hash(tool: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON for name + description + inputSchema."""
    canonical = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema"),
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()
    return digest


@dataclass
class MCPBaseline:
    """SHA-256 snapshot of a set of MCP tool definitions.

    Tracks: name, description, inputSchema for each tool.
    Any change to any field registers as drift.
    """

    server_name: str
    hashes: dict[str, str] = field(default_factory=dict)  # tool_name -> sha256

    @classmethod
    def snapshot(cls, tools: list[dict[str, Any]], server_name: str) -> "MCPBaseline":
        """Build a baseline from the current tool list.

        Args:
            tools: Tool definitions from the MCP server.
            server_name: Human-readable server identifier.

        Returns:
            MCPBaseline instance.
        """
        baseline = cls(server_name=server_name)
        for tool in tools:
            name = tool.get("name", "")
            baseline.hashes[name] = _tool_hash(tool)
        return baseline

    def check(self, current_tools: list[dict[str, Any]]) -> DriftResult:
        """Compare current tools against this baseline.

        Args:
            current_tools: Current tool definitions from the MCP server.

        Returns:
            DriftResult with all detected drifts.
        """
        current: dict[str, str] = {}
        for tool in current_tools:
            name = tool.get("name", "")
            current[name] = _tool_hash(tool)

        drifts: list[ToolDrift] = []

        # Modified or removed tools
        for name, baseline_hash in self.hashes.items():
            if name not in current:
                drifts.append(
                    ToolDrift(
                        tool_name=name,
                        kind="removed",
                        baseline_hash=baseline_hash,
                        current_hash=None,
                    )
                )
            elif current[name] != baseline_hash:
                drifts.append(
                    ToolDrift(
                        tool_name=name,
                        kind="modified",
                        baseline_hash=baseline_hash,
                        current_hash=current[name],
                    )
                )

        # New tools not in baseline
        for name, current_hash in current.items():
            if name not in self.hashes:
                drifts.append(
                    ToolDrift(
                        tool_name=name,
                        kind="added",
                        baseline_hash=None,
                        current_hash=current_hash,
                    )
                )

        return DriftResult(
            drifted=bool(drifts),
            drifts=tuple(drifts),
            baseline_server=self.server_name,
            current_tool_count=len(current),
            baseline_tool_count=len(self.hashes),
        )

    def check_and_emit(
        self,
        current_tools: list[dict[str, Any]],
        principal: str = "system",
        policy: DriftPolicy = DriftPolicy.WARN,
    ) -> DriftResult:
        """Compare against baseline and emit a SecurityEvent on drift.

        Args:
            current_tools: Current tool definitions.
            principal: Principal for the SecurityEvent.
            policy: Controls what happens on drift (WARN, DENY_NEW_TOOLS,
                DENY_ALL). This method only emits the event; enforcement
                is the caller's responsibility.

        Returns:
            DriftResult. Check result.drifted and result.drifts.
        """
        result = self.check(current_tools)
        if result.drifted:
            from tessera.events import EventKind, SecurityEvent, emit

            emit(
                SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=principal,
                    detail={
                        "scanner": "mcp_baseline_drift",
                        "server": self.server_name,
                        "policy": str(policy),
                        "drift_count": len(result.drifts),
                        "added": [d.tool_name for d in result.drifts if d.kind == "added"],
                        "modified": [d.tool_name for d in result.drifts if d.kind == "modified"],
                        "removed": [d.tool_name for d in result.drifts if d.kind == "removed"],
                        "owasp": "LLM09",
                        "rule": "AGENT-054",
                    },
                )
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {"server_name": self.server_name, "hashes": dict(self.hashes)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MCPBaseline":
        baseline = cls(server_name=data["server_name"])
        baseline.hashes = data.get("hashes", {})
        return baseline

    def save(self, path: str) -> None:
        """Write baseline to a JSON file.

        Args:
            path: File path to write. Parent directory must exist.
        """
        import pathlib

        pathlib.Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str) -> "MCPBaseline":
        """Load baseline from a JSON file.

        Args:
            path: File path previously written by save().

        Returns:
            MCPBaseline instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is malformed.
        """
        import pathlib

        try:
            data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed baseline file at {path}: {exc}") from exc
        return cls.from_dict(data)
