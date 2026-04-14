"""Side-channel mitigation tests."""

from __future__ import annotations

import time

import pytest

from tessera.side_channels import (
    ConstantTimeDispatch,
    LoopBoundExceeded,
    LoopGuard,
    StructuredResult,
)


# ---------------------------------------------------------------------------
# LoopGuard
# ---------------------------------------------------------------------------


def test_loop_guard_tainted_exceeds_limit():
    guard = LoopGuard(max_iterations=100)
    with pytest.raises(LoopBoundExceeded):
        list(guard.guard(range(200), tainted=True))


def test_loop_guard_untainted_no_limit():
    guard = LoopGuard(max_iterations=100)
    result = list(guard.guard(range(200), tainted=False))
    assert len(result) == 200


def test_loop_guard_tainted_within_limit():
    guard = LoopGuard(max_iterations=100)
    result = list(guard.guard(range(50), tainted=True))
    assert len(result) == 50


# ---------------------------------------------------------------------------
# StructuredResult
# ---------------------------------------------------------------------------


def test_structured_result_ok():
    r = StructuredResult.ok(42)
    assert r.success is True
    assert r.value == 42


def test_structured_result_fail():
    r = StructuredResult.fail()
    assert r.success is False
    assert r.value is None
    assert r.error_code == "tool_error"


def test_structured_result_same_type():
    ok = StructuredResult.ok("hello")
    fail = StructuredResult.fail("denied")
    assert type(ok) is type(fail)


# ---------------------------------------------------------------------------
# ConstantTimeDispatch
# ---------------------------------------------------------------------------


def test_constant_time_sync():
    dispatch = ConstantTimeDispatch(min_latency_ms=100.0)
    start = time.monotonic()
    dispatch.sync_dispatch(lambda: 1)
    elapsed_ms = (time.monotonic() - start) * 1000
    assert elapsed_ms >= 80.0, f"Expected >= 80ms, got {elapsed_ms:.1f}ms"
