"""tessera.runtime: runtime isolation tiers for agent tool calls.

Provides three tiers of isolation:

- Tier 1 (Solo): pure Python, <0.5 ms overhead, HTTP egress allowlist +
  write-mode filesystem guard. No external dependencies beyond stdlib.
- Tier 2 (Team): Firecracker microVM per destructive tool call. The operator
  installs the firecracker binary on the host; this package provides the
  Python wrapper and ``DestructiveToolGate`` decorator.
- Tier 3 (Enterprise): Tetragon eBPF syscall policy + Cilium NetworkPolicy +
  WireGuard mesh. The Python builders produce ready-to-deploy YAML; the
  operator applies them to the cluster.

Select the active tier via ``TESSERA_RUNTIME_TIER`` (default ``1``).
"""

from __future__ import annotations

from tessera.runtime.solo import (
    EgressAllowlist,
    FilesystemGuard,
    RuntimeViolation,
    Tier1Sandbox,
)
from tessera.runtime.firecracker import (
    DestructiveToolGate,
    FirecrackerConfig,
    FirecrackerNotAvailableError,
    FirecrackerRunner,
)
from tessera.runtime.tetragon import (
    CiliumNetworkPolicyBuilder,
    TetragonPolicyBuilder,
    WireGuardConfig,
)

__all__ = [
    # Tier 1
    "EgressAllowlist",
    "FilesystemGuard",
    "RuntimeViolation",
    "Tier1Sandbox",
    # Tier 2
    "FirecrackerConfig",
    "FirecrackerNotAvailableError",
    "FirecrackerRunner",
    "DestructiveToolGate",
    # Tier 3
    "TetragonPolicyBuilder",
    "CiliumNetworkPolicyBuilder",
    "WireGuardConfig",
]
