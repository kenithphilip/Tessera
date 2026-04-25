"""Tests for Tessera runtime isolation tier skeletons (Tier 2 and Tier 3).

Tier 2: FirecrackerConfig, FirecrackerRunner, DestructiveToolGate.
Tier 3: TetragonPolicyBuilder, CiliumNetworkPolicyBuilder, WireGuardConfig.

The tests exercise the Python wrapper API and generated output. They do NOT
require a firecracker binary, a Kubernetes cluster, or a Linux kernel with
eBPF support.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile

import pytest
import yaml

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


# ---------------------------------------------------------------------------
# FirecrackerConfig
# ---------------------------------------------------------------------------


class TestFirecrackerConfig:
    def _sample(self, **overrides: object) -> FirecrackerConfig:
        base: dict[str, object] = dict(
            vm_id="test-vm-1",
            kernel_image_path="/var/tessera/vmlinux",
            rootfs_path="/var/tessera/rootfs.ext4",
        )
        base.update(overrides)
        return FirecrackerConfig(**base)  # type: ignore[arg-type]

    def test_defaults(self) -> None:
        cfg = self._sample()
        assert cfg.cpu_count == 1
        assert cfg.memory_mb == 256
        assert cfg.network_interface is None
        assert "console=ttyS0" in cfg.boot_args

    def test_frozen(self) -> None:
        cfg = self._sample()
        with pytest.raises((AttributeError, TypeError)):
            cfg.cpu_count = 4  # type: ignore[misc]

    def test_to_json_round_trip(self) -> None:
        cfg = self._sample(
            cpu_count=2,
            memory_mb=512,
            network_interface="tapFc0",
        )
        raw = cfg.to_json()
        data = json.loads(raw)
        assert data["machine-config"]["vcpu_count"] == 2
        assert data["machine-config"]["mem_size_mib"] == 512
        assert data["network-interfaces"][0]["host_dev_name"] == "tapFc0"
        assert data["drives"][0]["is_root_device"] is True

    def test_from_json_restores_fields(self) -> None:
        cfg = self._sample(cpu_count=4, memory_mb=1024)
        raw = cfg.to_json()
        restored = FirecrackerConfig.from_json(raw)
        assert restored.cpu_count == 4
        assert restored.memory_mb == 1024
        assert restored.kernel_image_path == "/var/tessera/vmlinux"
        assert restored.rootfs_path == "/var/tessera/rootfs.ext4"

    def test_no_network_interface_omits_section(self) -> None:
        cfg = self._sample()
        data = json.loads(cfg.to_json())
        assert "network-interfaces" not in data

    def test_machine_config_shape(self) -> None:
        cfg = self._sample(cpu_count=2, memory_mb=512)
        mc = cfg.to_machine_config()
        assert mc == {"vcpu_count": 2, "mem_size_mib": 512}

    def test_boot_source_shape(self) -> None:
        cfg = self._sample()
        bs = cfg.to_boot_source()
        assert bs["kernel_image_path"] == "/var/tessera/vmlinux"
        assert "pci=off" in bs["boot_args"]


# ---------------------------------------------------------------------------
# FirecrackerRunner
# ---------------------------------------------------------------------------


class TestFirecrackerRunner:
    def test_start_raises_when_binary_missing(self) -> None:
        runner = FirecrackerRunner(binary="__tessera_no_such_binary__")
        cfg = FirecrackerConfig(
            vm_id="x",
            kernel_image_path="/k",
            rootfs_path="/r",
        )
        with pytest.raises(FirecrackerNotAvailableError) as exc_info:
            runner.start(cfg)
        msg = str(exc_info.value).lower()
        assert "firecracker" in msg
        assert "path" in msg

    def test_vm_invoke_raises_when_binary_missing(self) -> None:
        """FirecrackerRunner.exec() raises when the binary is absent."""
        runner = FirecrackerRunner(binary="__tessera_no_such_binary__")
        with pytest.raises(FirecrackerNotAvailableError):
            runner.exec("any-id", ["ls"])

    def test_stop_raises_when_binary_missing(self) -> None:
        runner = FirecrackerRunner(binary="__tessera_no_such_binary__")
        with pytest.raises(FirecrackerNotAvailableError):
            runner.stop("any-id")

    def test_invoke_raises_key_error_for_unknown_vm(self) -> None:
        """exec() raises KeyError for a vm_id that was never started."""
        stub = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False
        )
        stub.write("#!/bin/sh\nexit 0\n")
        stub.flush()
        os.chmod(stub.name, 0o755)
        runner = FirecrackerRunner(binary=stub.name)
        try:
            with pytest.raises(KeyError):
                runner.exec("no-such-vm", ["ls"])
        finally:
            os.unlink(stub.name)


# ---------------------------------------------------------------------------
# DestructiveToolGate
# ---------------------------------------------------------------------------


class TestDestructiveToolGate:
    def test_passthrough_at_tier_1(self) -> None:
        """At tier 1 the decorator is transparent."""
        calls: list[tuple[int, str]] = []

        @DestructiveToolGate
        def my_tool(x: int, label: str) -> str:
            calls.append((x, label))
            return f"{x}-{label}"

        os.environ.pop("TESSERA_RUNTIME_TIER", None)
        result = my_tool(42, "hello")
        assert result == "42-hello"
        assert calls == [(42, "hello")]

    def test_gate_marker_attribute(self) -> None:
        @DestructiveToolGate
        def tool() -> None:
            pass

        assert getattr(tool, "__tessera_destructive_gate__", False) is True

    def test_functools_wraps_preserves_name(self) -> None:
        @DestructiveToolGate
        def important_tool() -> None:
            """Docstring."""

        assert important_tool.__name__ == "important_tool"
        assert important_tool.__doc__ == "Docstring."

    def test_tier_2_raises_when_no_binary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """At tier 2 with no binary present the gate raises FirecrackerNotAvailableError."""
        monkeypatch.setenv("TESSERA_RUNTIME_TIER", "2")
        monkeypatch.setenv("TESSERA_FC_KERNEL", "/k")
        monkeypatch.setenv("TESSERA_FC_ROOTFS", "/r")

        @DestructiveToolGate
        def tool() -> str:
            return "ok"

        with pytest.raises(FirecrackerNotAvailableError):
            tool()


# ---------------------------------------------------------------------------
# TetragonPolicyBuilder
# ---------------------------------------------------------------------------


class TestTetragonPolicyBuilder:
    def test_build_produces_valid_yaml(self) -> None:
        raw = (
            TetragonPolicyBuilder(name="test-policy", namespace="tessera")
            .allow_dns(["10.96.0.10"])
            .allow_egress(["10.0.0.0/8"])
            .deny_all_other()
            .build()
        )
        parsed = yaml.safe_load(raw)
        assert parsed is not None
        assert isinstance(parsed, dict)

    def test_api_version_and_kind(self) -> None:
        raw = TetragonPolicyBuilder().build()
        parsed = yaml.safe_load(raw)
        assert parsed["apiVersion"] == "cilium.io/v1alpha1"
        assert parsed["kind"] == "TracingPolicy"

    def test_metadata_labels(self) -> None:
        parsed = yaml.safe_load(TetragonPolicyBuilder().build())
        labels = parsed["metadata"]["labels"]
        assert labels["app.kubernetes.io/part-of"] == "tessera"
        assert labels["tessera.dev/tier"] == "3"

    def test_kprobes_present_when_deny_set(self) -> None:
        raw = (
            TetragonPolicyBuilder()
            .allow_dns(["8.8.8.8"])
            .deny_all_other()
            .build()
        )
        parsed = yaml.safe_load(raw)
        kprobes = parsed["spec"]["kprobes"]
        assert len(kprobes) >= 2
        calls = [k["call"] for k in kprobes]
        assert all(c == "tcp_connect" for c in calls)

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError):
            TetragonPolicyBuilder().allow_dns(["not-an-ip"])

    def test_invalid_cidr_raises(self) -> None:
        with pytest.raises(ValueError):
            TetragonPolicyBuilder().allow_egress(["not-a-cidr"])

    def test_write_creates_file(self, tmp_path: object) -> None:
        import pathlib

        out = pathlib.Path(str(tmp_path)) / "subdir" / "policy.yaml"
        TetragonPolicyBuilder().allow_dns(["1.1.1.1"]).write(str(out))
        assert out.exists()
        parsed = yaml.safe_load(out.read_text())
        assert parsed["kind"] == "TracingPolicy"


# ---------------------------------------------------------------------------
# CiliumNetworkPolicyBuilder
# ---------------------------------------------------------------------------


class TestCiliumNetworkPolicyBuilder:
    def test_api_version_and_kind(self) -> None:
        raw = CiliumNetworkPolicyBuilder().allow_to(["api.example.com"]).build()
        parsed = yaml.safe_load(raw)
        assert parsed["apiVersion"] == "cilium.io/v2"
        assert parsed["kind"] == "CiliumNetworkPolicy"

    def test_fqdn_entries_present(self) -> None:
        raw = (
            CiliumNetworkPolicyBuilder()
            .allow_to(["api.openai.com", "api.anthropic.com"])
            .build()
        )
        parsed = yaml.safe_load(raw)
        egress = parsed["spec"]["egress"]
        fqdn_names: list[str] = []
        for rule in egress:
            for fqdn in rule.get("toFQDNs", []):
                fqdn_names.append(fqdn["matchName"])
        assert "api.openai.com" in fqdn_names
        assert "api.anthropic.com" in fqdn_names

    def test_endpoint_selector_present(self) -> None:
        parsed = yaml.safe_load(
            CiliumNetworkPolicyBuilder().allow_to(["x.example.com"]).build()
        )
        assert "endpointSelector" in parsed["spec"]

    def test_custom_endpoint_selector(self) -> None:
        sel = {"matchLabels": {"my-label": "my-value"}}
        parsed = yaml.safe_load(
            CiliumNetworkPolicyBuilder(endpoint_selector=sel).build()
        )
        assert parsed["spec"]["endpointSelector"] == sel

    def test_produces_valid_yaml(self) -> None:
        raw = (
            CiliumNetworkPolicyBuilder()
            .allow_to(["example.com"])
            .deny_default()
            .build()
        )
        assert yaml.safe_load(raw) is not None


# ---------------------------------------------------------------------------
# WireGuardConfig
# ---------------------------------------------------------------------------


class TestWireGuardConfig:
    def _sample_config(self) -> WireGuardConfig:
        return WireGuardConfig(
            private_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            address="10.200.0.1/24",
            listen_port=51820,
            dns=["10.96.0.10"],
            peers=[
                {
                    "public_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                    "allowed_ips": ["10.200.0.2/32"],
                    "endpoint": "peer.example.com:51820",
                    "persistent_keepalive": 25,
                }
            ],
        )

    def test_render_creates_file(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        self._sample_config().render(path)
        assert os.path.exists(path)

    def test_render_file_mode_is_600(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        self._sample_config().render(path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_render_contains_interface_section(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        content = self._sample_config().render(path)
        assert "[Interface]" in content
        assert "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in content
        assert "Address = 10.200.0.1/24" in content
        assert "ListenPort = 51820" in content

    def test_render_contains_peer_section(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        content = self._sample_config().render(path)
        assert "[Peer]" in content
        assert "PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" in content
        assert "AllowedIPs = 10.200.0.2/32" in content
        assert "Endpoint = peer.example.com:51820" in content
        assert "PersistentKeepalive = 25" in content

    def test_render_contains_dns(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        content = self._sample_config().render(path)
        assert "DNS = 10.96.0.10" in content

    def test_no_peers_produces_only_interface(self, tmp_path: object) -> None:
        import pathlib

        path = str(pathlib.Path(str(tmp_path)) / "wg0.conf")
        cfg = WireGuardConfig(
            private_key="AAAA=",
            public_key="BBBB=",
            address="10.200.0.1/24",
        )
        content = cfg.render(path)
        assert "[Interface]" in content
        assert "[Peer]" not in content
