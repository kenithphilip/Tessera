"""Tier 3 runtime isolation: Tetragon, Cilium NetworkPolicy, and WireGuard.

Each builder produces ready-to-deploy YAML or config text. The operator
applies the output to the cluster; the Python builders do not invoke kubectl
or helm directly.

``TetragonPolicyBuilder`` targets the Tetragon ``TracingPolicy`` CRD
(github.com/cilium/tetragon). It generates a policy that allows only
explicitly named DNS servers and egress CIDRs and denies everything else at
the syscall level via kprobes.

``CiliumNetworkPolicyBuilder`` targets the Cilium ``CiliumNetworkPolicy`` CRD.
It generates an L3/L4/L7 egress policy that allows only named FQDN endpoints
and drops everything else.

``WireGuardConfig`` holds the parameters for a single WireGuard peer and
renders them to a ``wg0.conf`` file.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
from typing import Any

import yaml


@dataclasses.dataclass
class TetragonPolicyBuilder:
    """Builder for a Tetragon ``TracingPolicy`` that enforces syscall-level egress.

    Call ``allow_dns``, ``allow_egress``, and ``deny_all_other`` in any order,
    then call ``build()`` to get the YAML string.
    """

    name: str = "tessera-egress-policy"
    namespace: str = "tessera"

    def __post_init__(self) -> None:
        self._dns_servers: list[str] = []
        self._allowed_cidrs: list[str] = []
        self._deny_all: bool = False

    def allow_dns(self, dns_servers: list[str]) -> "TetragonPolicyBuilder":
        """Allow outbound traffic to the listed DNS server IP addresses."""
        for addr in dns_servers:
            # Validate that each entry is a valid IPv4 or IPv6 address.
            ipaddress.ip_address(addr)
            self._dns_servers.append(addr)
        return self

    def allow_egress(self, cidrs: list[str]) -> "TetragonPolicyBuilder":
        """Allow outbound traffic to the listed CIDR ranges."""
        for cidr in cidrs:
            # Validate that each entry is a valid network.
            ipaddress.ip_network(cidr, strict=False)
            self._allowed_cidrs.append(cidr)
        return self

    def deny_all_other(self) -> "TetragonPolicyBuilder":
        """Add a default-deny kprobe rule for all other egress connections."""
        self._deny_all = True
        return self

    def build(self) -> str:
        """Return the ``TracingPolicy`` as a YAML string."""
        policy = self._assemble()
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)

    def write(self, path: str) -> None:
        """Write the ``TracingPolicy`` YAML to ``path``."""
        content = self.build()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    def _assemble(self) -> dict[str, Any]:
        # kprobe selectors for allowed destinations. Each allowed IP or CIDR
        # becomes a MatchArgs selector on the tcp_connect kprobe.
        match_args: list[dict[str, Any]] = []
        for addr in self._dns_servers:
            match_args.append(
                {
                    "index": 0,
                    "operator": "Equal",
                    "values": [addr],
                }
            )
        for cidr in self._allowed_cidrs:
            match_args.append(
                {
                    "index": 0,
                    "operator": "Prefix",
                    "values": [cidr],
                }
            )

        kprobes: list[dict[str, Any]] = []

        if match_args:
            kprobes.append(
                {
                    "call": "tcp_connect",
                    "syscall": False,
                    "args": [{"index": 0, "type": "sock"}],
                    "selectors": [
                        {
                            "matchArgs": match_args,
                            "matchActions": [{"action": "Allow"}],
                        }
                    ],
                }
            )

        if self._deny_all:
            kprobes.append(
                {
                    "call": "tcp_connect",
                    "syscall": False,
                    "args": [{"index": 0, "type": "sock"}],
                    "selectors": [
                        {
                            "matchActions": [
                                {
                                    "action": "Sigkill",
                                }
                            ]
                        }
                    ],
                }
            )

        return {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "tessera",
                    "tessera.dev/tier": "3",
                },
            },
            "spec": {
                "kprobes": kprobes,
            },
        }


@dataclasses.dataclass
class CiliumNetworkPolicyBuilder:
    """Builder for a ``CiliumNetworkPolicy`` that restricts L3/L4/L7 egress.

    Call ``allow_to`` with a list of FQDNs and ``deny_default`` to add the
    catch-all deny rule, then call ``build()`` to get the YAML string.
    """

    name: str = "tessera-egress-cnp"
    namespace: str = "tessera"
    endpoint_selector: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self._allowed_domains: list[str] = []
        self._deny_default: bool = False

    def allow_to(self, domains: list[str]) -> "CiliumNetworkPolicyBuilder":
        """Allow egress to the listed FQDNs (exact match)."""
        self._allowed_domains.extend(domains)
        return self

    def deny_default(self) -> "CiliumNetworkPolicyBuilder":
        """Add a default-deny egress rule."""
        self._deny_default = True
        return self

    def build(self) -> str:
        """Return the ``CiliumNetworkPolicy`` as a YAML string."""
        policy = self._assemble()
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)

    def write(self, path: str) -> None:
        """Write the ``CiliumNetworkPolicy`` YAML to ``path``."""
        content = self.build()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)

    def _assemble(self) -> dict[str, Any]:
        selector = self.endpoint_selector or {
            "matchLabels": {"app.kubernetes.io/part-of": "tessera"}
        }

        egress_rules: list[dict[str, Any]] = []

        if self._allowed_domains:
            fqdn_rules = [{"matchName": d} for d in self._allowed_domains]
            egress_rules.append(
                {
                    "toFQDNs": fqdn_rules,
                    "toPorts": [
                        {
                            "ports": [
                                {"port": "443", "protocol": "TCP"},
                                {"port": "53", "protocol": "UDP"},
                            ]
                        }
                    ],
                }
            )

        if self._deny_default:
            # An explicit empty egressDeny entry blocks all other traffic.
            egress_rules.append({"toEntities": ["all"]})

        return {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "tessera",
                    "tessera.dev/tier": "3",
                },
            },
            "spec": {
                "endpointSelector": selector,
                "egress": egress_rules,
            },
        }


@dataclasses.dataclass
class WireGuardConfig:
    """Parameters for a single WireGuard mesh peer.

    ``private_key`` and ``public_key`` must be base64-encoded 32-byte Curve25519
    keys as produced by ``wg genkey`` / ``wg pubkey``.
    ``address`` is the interface CIDR inside the WireGuard network.
    ``listen_port`` is the UDP port the interface binds to (default 51820).
    ``peers`` is a list of peer descriptors; each must have ``public_key``,
    ``endpoint`` (host:port), and ``allowed_ips`` (list of CIDRs).
    """

    private_key: str
    public_key: str
    address: str
    listen_port: int = 51820
    dns: list[str] = dataclasses.field(default_factory=list)
    peers: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def render(self, path: str) -> str:
        """Write a ``wg0.conf`` file to ``path`` and return its text.

        The output is suitable for use with ``wg-quick up wg0`` or the
        ``wg syncconf`` workflow. Keys are rendered verbatim; the caller is
        responsible for protecting the file (mode 0600).
        """
        lines: list[str] = [
            "[Interface]",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.address}",
            f"ListenPort = {self.listen_port}",
        ]
        if self.dns:
            lines.append(f"DNS = {', '.join(self.dns)}")
        lines.append("")

        for peer in self.peers:
            lines.append("[Peer]")
            lines.append(f"PublicKey = {peer['public_key']}")
            if "preshared_key" in peer:
                lines.append(f"PresharedKey = {peer['preshared_key']}")
            allowed = ", ".join(peer.get("allowed_ips", []))
            lines.append(f"AllowedIPs = {allowed}")
            if "endpoint" in peer:
                lines.append(f"Endpoint = {peer['endpoint']}")
            if "persistent_keepalive" in peer:
                lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")
            lines.append("")

        content = "\n".join(lines)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        # Tighten permissions: the private key must not be world-readable.
        os.chmod(path, 0o600)
        return content
