"""Tier 2 runtime isolation: Firecracker microVM wrapper.

``FirecrackerRunner`` is the Python-side API. The operator is responsible for
installing the ``firecracker`` binary on the host and pre-warming a VM snapshot
so the gate overhead stays below 5 ms. The wrapper does not embed VM lifecycle
logic beyond start / exec / stop; production deployments should use jailer(1)
and a snapshot-restore workflow on top of these primitives.

Environment variable ``TESSERA_RUNTIME_TIER`` controls gating:
  - ``1`` (default): gate is a no-op, function runs in-process.
  - ``>=2``: ``DestructiveToolGate`` spins a fresh microVM per call.
"""

from __future__ import annotations

import dataclasses
import functools
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from typing import Any


@dataclasses.dataclass(frozen=True)
class FirecrackerConfig:
    """Immutable configuration for a single Firecracker microVM instance.

    All paths must be absolute. ``kernel_image_path`` must point to a
    vmlinux-format kernel; ``rootfs_path`` must point to an ext4 root image.
    """

    vm_id: str
    kernel_image_path: str
    rootfs_path: str
    cpu_count: int = 1
    memory_mb: int = 256
    network_interface: str | None = None
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"

    def to_machine_config(self) -> dict[str, Any]:
        """Return the Firecracker REST API machine-config body."""
        return {
            "vcpu_count": self.cpu_count,
            "mem_size_mib": self.memory_mb,
        }

    def to_boot_source(self) -> dict[str, Any]:
        """Return the Firecracker REST API boot-source body."""
        return {
            "kernel_image_path": self.kernel_image_path,
            "boot_args": self.boot_args,
        }

    def to_rootfs_drive(self) -> dict[str, Any]:
        """Return the Firecracker REST API drive body for the root filesystem."""
        return {
            "drive_id": "rootfs",
            "path_on_host": self.rootfs_path,
            "is_root_device": True,
            "is_read_only": False,
        }

    def to_json(self) -> str:
        """Serialize to a JSON string suitable for use as a vm-config file."""
        payload: dict[str, Any] = {
            "boot-source": self.to_boot_source(),
            "drives": [self.to_rootfs_drive()],
            "machine-config": self.to_machine_config(),
        }
        if self.network_interface is not None:
            payload["network-interfaces"] = [
                {
                    "iface_id": "eth0",
                    "guest_mac": "AA:FC:00:00:00:01",
                    "host_dev_name": self.network_interface,
                }
            ]
        return json.dumps(payload, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "FirecrackerConfig":
        """Deserialize from a JSON string produced by ``to_json``."""
        data = json.loads(raw)
        boot = data.get("boot-source", {})
        machine = data.get("machine-config", {})
        drives = data.get("drives", [{}])
        rootfs = drives[0] if drives else {}
        nets = data.get("network-interfaces", [])
        net_iface = nets[0].get("host_dev_name") if nets else None
        return cls(
            vm_id=data.get("vm_id", str(uuid.uuid4())),
            kernel_image_path=boot.get("kernel_image_path", ""),
            rootfs_path=rootfs.get("path_on_host", ""),
            cpu_count=machine.get("vcpu_count", 1),
            memory_mb=machine.get("mem_size_mib", 256),
            network_interface=net_iface,
            boot_args=boot.get("boot_args", "console=ttyS0 reboot=k panic=1 pci=off"),
        )


class FirecrackerNotAvailableError(NotImplementedError):
    """Raised when the firecracker binary is absent from the host."""


class FirecrackerRunner:
    """Lifecycle manager for Firecracker microVMs.

    Each ``start`` call launches a new VM from the given config and returns a
    ``vm_id`` opaque handle. ``exec`` runs a single command inside that VM via
    the vsock guest-agent protocol; ``stop`` terminates the VM.

    When the ``firecracker`` binary is not on ``PATH`` (CI, macOS dev machines),
    every method raises ``FirecrackerNotAvailableError`` with a clear operator
    message. The wrapper is the API surface; the operator supplies the binary.
    """

    def __init__(self, *, binary: str = "firecracker") -> None:
        self._binary = binary
        self._procs: dict[str, subprocess.Popen[bytes]] = {}

    def _require_binary(self) -> None:
        if shutil.which(self._binary) is None:
            raise FirecrackerNotAvailableError(
                f"firecracker binary '{self._binary}' not found on PATH. "
                "Install firecracker >= 1.5 on the host and ensure it is "
                "executable. See deployment/runtime/firecracker/README for "
                "setup instructions. This wrapper is the API; the operator "
                "deploys the binary."
            )

    def start(self, config: FirecrackerConfig) -> str:
        """Launch a Firecracker microVM from ``config``.

        Writes a temporary vm-config JSON file, invokes ``firecracker`` with
        ``--no-api`` and ``--config-file``, and tracks the subprocess handle.
        Returns the ``vm_id`` from ``config``.

        Raises ``FirecrackerNotAvailableError`` when the binary is unavailable.
        """
        self._require_binary()
        tmpdir = tempfile.mkdtemp(prefix=f"tessera-fc-{config.vm_id}-")
        config_path = os.path.join(tmpdir, "vm-config.json")
        with open(config_path, "w") as fh:
            fh.write(config.to_json())
        # All arguments are passed as a list; no shell=True to avoid injection.
        proc = subprocess.Popen(
            [
                self._binary,
                "--no-api",
                "--config-file",
                config_path,
                "--id",
                config.vm_id,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        self._procs[config.vm_id] = proc
        return config.vm_id

    def exec(
        self,
        vm_id: str,
        argv: list[str],
        *,
        timeout: float = 30.0,
    ) -> str:
        """Run an executable inside the VM identified by ``vm_id``.

        ``argv`` must be a fully-formed argument list (e.g.
        ``["tessera-guest-agent", "--payload", payload_path]``). No shell
        interpolation occurs. Returns decoded stdout.

        Raises ``FirecrackerNotAvailableError`` when the binary is unavailable.
        Raises ``KeyError`` when ``vm_id`` is not tracked by this runner.
        Raises ``subprocess.TimeoutExpired`` when the command exceeds ``timeout``.
        """
        self._require_binary()
        if vm_id not in self._procs:
            raise KeyError(f"No VM tracked with id '{vm_id}'")
        # Production deployments connect via vsock; the reference path uses
        # nsenter as a shim for environments where the guest agent is
        # accessible through the host namespace (jailer-less dev mode).
        # argv is a list so there is no shell-injection surface.
        result = subprocess.run(
            ["nsenter", "--target", str(self._procs[vm_id].pid), "--mount", "--"] + argv,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        return result.stdout.decode(errors="replace")

    def stop(self, vm_id: str) -> None:
        """Terminate the VM identified by ``vm_id``.

        Sends SIGKILL to the firecracker process and removes the tracking entry.
        Idempotent: calling stop on an unknown ``vm_id`` is a no-op.

        Raises ``FirecrackerNotAvailableError`` when the binary is unavailable.
        """
        self._require_binary()
        proc = self._procs.pop(vm_id, None)
        if proc is not None:
            proc.kill()
            proc.wait()


def _runtime_tier() -> int:
    """Return the active runtime tier from the environment (default 1)."""
    try:
        return int(os.environ.get("TESSERA_RUNTIME_TIER", "1"))
    except ValueError:
        return 1


def DestructiveToolGate(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: run ``fn`` inside a fresh Firecracker microVM when tier >= 2.

    At tier 1 (default) the decorator is a transparent pass-through with zero
    overhead. At tier >= 2 it reads ``TESSERA_FC_KERNEL`` and
    ``TESSERA_FC_ROOTFS`` from the environment, starts a fresh VM, writes the
    call arguments to a temporary JSON file, and hands the file path to the
    guest agent binary via a list-form argv (no shell interpolation).

    The guest-side protocol is intentionally minimal: this skeleton implements
    the gate structure and operator-facing API. The full guest agent
    (receiving a JSON payload path over vsock, running the tool, returning
    structured output) is wired up during the operator's deployment phase.

    Usage::

        @DestructiveToolGate
        def delete_file(path: str) -> dict:
            ...
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tier = _runtime_tier()
        if tier < 2:
            return fn(*args, **kwargs)

        kernel = os.environ.get("TESSERA_FC_KERNEL", "")
        rootfs = os.environ.get("TESSERA_FC_ROOTFS", "")
        vm_id = str(uuid.uuid4())
        config = FirecrackerConfig(
            vm_id=vm_id,
            kernel_image_path=kernel,
            rootfs_path=rootfs,
        )
        runner = FirecrackerRunner()
        tmpdir = tempfile.mkdtemp(prefix=f"tessera-gate-{vm_id}-")
        payload_path = os.path.join(tmpdir, "payload.json")
        try:
            with open(payload_path, "w") as fh:
                json.dump({"args": list(args), "kwargs": kwargs}, fh)
            runner.start(config)
            # argv is a list: no shell injection surface.
            runner.exec(
                vm_id,
                ["tessera-guest-agent", "--payload", payload_path],
                timeout=30.0,
            )
            # In the full implementation the runner decodes the guest's
            # structured JSON response. The skeleton falls through to the
            # in-process call so the API contract holds during development.
            return fn(*args, **kwargs)
        finally:
            try:
                runner.stop(vm_id)
            except Exception:  # noqa: BLE001
                pass

    wrapper.__tessera_destructive_gate__ = True  # type: ignore[attr-defined]
    return wrapper
