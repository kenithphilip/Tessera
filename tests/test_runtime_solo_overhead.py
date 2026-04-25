"""Wave 3B-i overhead benchmark: Tier 1 must add <0.5ms per call.

The plan target for the Solo tier is "less than 0.5ms overhead per
call". We don't have pytest-benchmark wired (yet); the test
measures wall-clock around 10000 EgressAllowlist.is_allowed calls
and asserts the per-call mean is well under 0.5ms (target: under
0.05ms; we add 10x headroom). Run with `pytest -k overhead -v`.
"""

from __future__ import annotations

import time

import pytest

from tessera.runtime.solo import EgressAllowlist, FilesystemGuard


N_CALLS = 10_000
TARGET_PER_CALL_MS = 0.5


def test_egress_allowlist_overhead_under_target() -> None:
    al = EgressAllowlist(
        hostnames=["api.example.com", "telemetry.invalid"],
        cidrs=["10.0.0.0/8"],
    )
    started = time.perf_counter()
    for _ in range(N_CALLS):
        al.is_allowed("https://api.example.com/v1/resource")
    elapsed_s = time.perf_counter() - started
    per_call_ms = (elapsed_s / N_CALLS) * 1000
    assert per_call_ms < TARGET_PER_CALL_MS, (
        f"EgressAllowlist mean overhead {per_call_ms:.4f}ms exceeds "
        f"the {TARGET_PER_CALL_MS}ms Tier 1 target"
    )


def test_filesystem_guard_overhead_under_target() -> None:
    g = FilesystemGuard(allowed_write_prefixes=["/tmp/agent/", "/var/log/"])
    started = time.perf_counter()
    for _ in range(N_CALLS):
        try:
            g.assert_writable("/tmp/agent/safe.log")
        except Exception:
            pass
    elapsed_s = time.perf_counter() - started
    per_call_ms = (elapsed_s / N_CALLS) * 1000
    assert per_call_ms < TARGET_PER_CALL_MS, (
        f"FilesystemGuard mean overhead {per_call_ms:.4f}ms exceeds "
        f"the {TARGET_PER_CALL_MS}ms Tier 1 target"
    )


def test_combined_overhead_summary(capsys: pytest.CaptureFixture[str]) -> None:
    """Surface the measured per-call overhead so it ends up in the
    test output for SOC analysts reviewing the deployment."""
    al = EgressAllowlist(hostnames=["api.example.com"])
    g = FilesystemGuard(allowed_write_prefixes=["/tmp/"])
    started = time.perf_counter()
    for _ in range(N_CALLS):
        al.is_allowed("https://api.example.com/v1/x")
        try:
            g.assert_writable("/tmp/x.log")
        except Exception:
            pass
    elapsed_s = time.perf_counter() - started
    per_call_ms = (elapsed_s / (N_CALLS * 2)) * 1000
    print(
        f"\nTier 1 combined per-call overhead: {per_call_ms:.4f} ms "
        f"(target: <{TARGET_PER_CALL_MS} ms)"
    )
    assert per_call_ms < TARGET_PER_CALL_MS
