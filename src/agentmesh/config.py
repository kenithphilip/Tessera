"""AgentMesh SDK configuration loading.

Supports YAML files, dicts, and programmatic construction. Trust levels
accept case-insensitive strings ("user", "TOOL") that map to Tessera's
TrustLevel enum.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tessera.labels import TrustLevel

_TRUST_NAMES: dict[str, TrustLevel] = {
    "untrusted": TrustLevel.UNTRUSTED,
    "tool": TrustLevel.TOOL,
    "user": TrustLevel.USER,
    "system": TrustLevel.SYSTEM,
}


def _parse_trust(value: str | int) -> TrustLevel:
    """Resolve a trust level from a string name or integer."""
    if isinstance(value, int):
        return TrustLevel(value)
    key = value.strip().lower()
    if key not in _TRUST_NAMES:
        raise ValueError(
            f"unknown trust level {value!r}, expected one of {list(_TRUST_NAMES)}"
        )
    return _TRUST_NAMES[key]


@dataclass(frozen=True)
class ToolPolicy:
    """Minimum trust level required to invoke a specific tool."""

    name: str
    required_trust: TrustLevel


@dataclass(frozen=True)
class AgentMeshConfig:
    """Immutable SDK configuration.

    Constructed via ``from_dict``, ``from_yaml_path``, or
    ``from_yaml_string``. The HMAC key is resolved at construction time
    so runtime code never touches env vars or filesystem.
    """

    hmac_key: bytes
    tool_policies: tuple[ToolPolicy, ...]
    default_required_trust: TrustLevel
    otel_enabled: bool
    budget_usd: float | None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentMeshConfig:
        """Build config from a plain dict (e.g. parsed YAML or inline)."""
        key = _resolve_key(data)
        raw_policies = data.get("tool_policies") or []
        policies = tuple(
            ToolPolicy(
                name=tp["name"],
                required_trust=_parse_trust(tp["required_trust"]),
            )
            for tp in raw_policies
        )
        default_trust = _parse_trust(data.get("default_required_trust", "user"))
        return cls(
            hmac_key=key,
            tool_policies=policies,
            default_required_trust=default_trust,
            otel_enabled=bool(data.get("otel_enabled", False)),
            budget_usd=data.get("budget_usd"),
        )

    @classmethod
    def from_yaml_path(cls, path: Path) -> AgentMeshConfig:
        """Load config from a YAML file on disk."""
        import yaml  # type: ignore[import-untyped]

        text = Path(path).read_text(encoding="utf-8")
        return cls.from_dict(yaml.safe_load(text))

    @classmethod
    def from_yaml_string(cls, text: str) -> AgentMeshConfig:
        """Parse config from a YAML string."""
        import yaml  # type: ignore[import-untyped]

        return cls.from_dict(yaml.safe_load(text))


def _resolve_key(data: dict[str, Any]) -> bytes:
    """Extract and validate the HMAC signing key from config data."""
    env_var = data.get("hmac_key_env")
    if env_var:
        raw = os.environ.get(env_var)
        if not raw:
            raise ValueError(
                f"environment variable {env_var!r} is not set or empty"
            )
        key = raw.encode("utf-8")
        if len(key) < 8:
            raise ValueError("HMAC key must be at least 8 bytes")
        return key

    raw_key = data.get("hmac_key")
    if raw_key is None:
        raise ValueError(
            "config must provide hmac_key, hmac_key: auto, or hmac_key_env"
        )
    if isinstance(raw_key, bytes):
        if len(raw_key) < 8:
            raise ValueError("HMAC key must be at least 8 bytes")
        return raw_key
    if isinstance(raw_key, str):
        if raw_key.strip().lower() == "auto":
            return secrets.token_bytes(32)
        encoded = raw_key.encode("utf-8")
        if len(encoded) < 8:
            raise ValueError("HMAC key must be at least 8 bytes")
        return encoded

    raise ValueError(f"hmac_key must be str or bytes, got {type(raw_key).__name__}")
