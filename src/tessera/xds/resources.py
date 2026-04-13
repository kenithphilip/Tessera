"""xDS resource types for Tessera policy distribution.

Mirrors the proto definitions in proto/tessera/xds/v1/resources.proto
as frozen dataclasses. The proto files are the contract; this module
provides a pure-Python implementation without requiring protobuf
compilation.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ToolRequirementResource:
    """A single tool's trust requirement, matching the proto ToolRequirement."""

    name: str
    resource_type: str
    required_trust: int


@dataclass(frozen=True)
class PolicyBundleResource:
    """Policy bundle distributed via xDS, matching the proto PolicyBundle."""

    version: str
    revision: str
    requirements: tuple[ToolRequirementResource, ...]
    default_trust_level: int
    human_approval_tools: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revision": self.revision,
            "requirements": [asdict(r) for r in self.requirements],
            "default_trust_level": self.default_trust_level,
            "human_approval_tools": list(self.human_approval_tools),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyBundleResource:
        return cls(
            version=data["version"],
            revision=data["revision"],
            requirements=tuple(
                ToolRequirementResource(**r) for r in data.get("requirements", [])
            ),
            default_trust_level=data.get("default_trust_level", 100),
            human_approval_tools=tuple(data.get("human_approval_tools", [])),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> PolicyBundleResource:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class ToolRegistryEntryResource:
    """A single tool entry, matching the proto ToolRegistryEntry."""

    name: str
    is_external: bool


@dataclass(frozen=True)
class ToolRegistryResource:
    """Tool registry distributed via xDS, matching the proto ToolRegistry."""

    version: str
    revision: str
    tools: tuple[ToolRegistryEntryResource, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revision": self.revision,
            "tools": [asdict(t) for t in self.tools],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRegistryResource:
        return cls(
            version=data["version"],
            revision=data["revision"],
            tools=tuple(
                ToolRegistryEntryResource(**t) for t in data.get("tools", [])
            ),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> ToolRegistryResource:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class TrustConfigResource:
    """Trust level configuration distributed via xDS, matching the proto TrustConfig."""

    version: str
    revision: str
    trust_levels: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revision": self.revision,
            "trust_levels": dict(self.trust_levels),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustConfigResource:
        return cls(
            version=data["version"],
            revision=data["revision"],
            trust_levels=dict(data.get("trust_levels", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> TrustConfigResource:
        return cls.from_dict(json.loads(raw))
