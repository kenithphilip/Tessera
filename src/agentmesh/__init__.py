"""AgentMesh SDK: the developer entry point for Tessera-backed agent security.

Typical usage:

    from agentmesh import init

    mesh = init({"hmac_key": "auto"})
    seg = mesh.label("do something", Origin.USER, "alice")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tessera.context import Context, LabeledSegment, make_segment
from tessera.events import register_sink, stdout_sink
from tessera.labels import Origin, TrustLevel
from tessera.policy import Decision, Policy
from tessera.signing import HMACSigner, HMACVerifier

from agentmesh.config import AgentMeshConfig

__all__ = [
    "AgentMeshContext",
    "init",
]


@dataclass
class AgentMeshContext:
    """Runtime handle returned by ``init()``.

    Holds the signer, verifier, policy engine, and spend tracker so
    callers do not need to wire Tessera primitives by hand.
    """

    _signer: HMACSigner
    _verifier: HMACVerifier
    _policy: Policy
    _budget_limit: float | None
    _spent: float = field(default=0.0, init=True)

    def label(
        self,
        content: str,
        origin: Origin,
        principal: str,
        trust_level: TrustLevel | None = None,
    ) -> LabeledSegment:
        """Create a signed LabeledSegment."""
        return make_segment(
            content=content,
            origin=origin,
            principal=principal,
            signer=self._signer,
            trust_level=trust_level,
        )

    def evaluate(self, context: Context, tool: str) -> Decision:
        """Evaluate whether a tool call is allowed given the context."""
        return self._policy.evaluate(context, tool)

    def budget(self, cost_usd: float) -> bool:
        """Track cumulative spend. Returns False when the budget is exceeded."""
        if self._budget_limit is None:
            return True
        self._spent += cost_usd
        return self._spent <= self._budget_limit


def init(
    config: AgentMeshConfig | dict[str, Any] | str | Path | None = None,
) -> AgentMeshContext:
    """Bootstrap the AgentMesh SDK and return a ready-to-use context.

    Args:
        config: One of:
            - None: look for ``agentmesh.yaml`` in cwd, fall back to defaults
            - dict: passed to ``AgentMeshConfig.from_dict()``
            - str or Path: path to a YAML config file
            - AgentMeshConfig: used directly

    Returns:
        An AgentMeshContext wired with signer, verifier, policy, and sink.
    """
    cfg = _resolve_config(config)
    signer = HMACSigner(key=cfg.hmac_key)
    verifier = HMACVerifier(key=cfg.hmac_key)
    policy = _build_policy(cfg)
    register_sink(stdout_sink)
    return AgentMeshContext(
        _signer=signer,
        _verifier=verifier,
        _policy=policy,
        _budget_limit=cfg.budget_usd,
    )


def _resolve_config(
    config: AgentMeshConfig | dict[str, Any] | str | Path | None,
) -> AgentMeshConfig:
    if isinstance(config, AgentMeshConfig):
        return config
    if isinstance(config, dict):
        return AgentMeshConfig.from_dict(config)
    if isinstance(config, (str, Path)):
        return AgentMeshConfig.from_yaml_path(Path(config))
    # None: try cwd yaml, then defaults
    cwd_yaml = Path.cwd() / "agentmesh.yaml"
    if cwd_yaml.is_file():
        return AgentMeshConfig.from_yaml_path(cwd_yaml)
    return AgentMeshConfig.from_dict({"hmac_key": "auto"})


def _build_policy(cfg: AgentMeshConfig) -> Policy:
    policy = Policy(default_required_trust=cfg.default_required_trust)
    for tp in cfg.tool_policies:
        policy.require(tp.name, tp.required_trust)
    return policy
