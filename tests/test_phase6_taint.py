"""Tests for Phase 6: advanced taint tracking.

Covers:
  6.1 Value-level taint and DependencyAccumulator
  6.2 have_enough_information guard on WorkerReport
  6.3 Security-aware error redaction
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent
from tessera.labels import Origin, TrustLevel
from tessera.quarantine import (
    QuarantinedExecutor,
    WorkerInsufficientInformation,
    WorkerReport,
)
from tessera.redact_errors import redact_error_message, redact_event_detail, safe_error_for_model
from tessera.taint import (
    CRITICAL_ARGS_SEND,
    ArgTaintResult,
    DependencyAccumulator,
    TaintedValue,
    from_segment,
    from_user,
)

KEY = b"test-phase6-key"


def _seg(content: str, origin: Origin) -> object:
    return make_segment(content, origin, "alice", KEY)


def _ctx(*segments) -> Context:
    ctx = Context()
    for s in segments:
        ctx.add(s)
    return ctx


# ---------------------------------------------------------------------------
# 6.1 TaintedValue
# ---------------------------------------------------------------------------


class TestTaintedValue:
    def test_user_value_is_not_tainted(self) -> None:
        ctx = _ctx(_seg("user data", Origin.USER))
        v = from_user("alice@acme.com")
        assert not v.is_tainted(ctx)

    def test_untrusted_segment_value_is_tainted(self) -> None:
        ctx = _ctx(
            _seg("user data", Origin.USER),
            _seg("web scrape", Origin.WEB),
        )
        v = from_segment("evil@attacker.com", 1)
        assert v.is_tainted(ctx)

    def test_trust_level_returns_minimum_source(self) -> None:
        ctx = _ctx(
            _seg("user data", Origin.USER),
            _seg("web scrape", Origin.WEB),
        )
        v = TaintedValue(value="merged", sources=frozenset({0, 1}))
        assert v.trust_level(ctx) == TrustLevel.UNTRUSTED

    def test_merge_unions_sources(self) -> None:
        a = from_segment("x", 0)
        b = from_segment("y", 1)
        merged = a.merge(b)
        assert merged.sources == frozenset({0, 1})

    def test_empty_sources_returns_system_trust(self) -> None:
        ctx = _ctx(_seg("data", Origin.USER))
        v = from_user("clean")
        assert v.trust_level(ctx) == TrustLevel.SYSTEM


# ---------------------------------------------------------------------------
# 6.1 DependencyAccumulator
# ---------------------------------------------------------------------------


class TestDependencyAccumulator:
    def test_user_arg_passes(self) -> None:
        ctx = _ctx(
            _seg("send money to alice@acme.com", Origin.USER),
            _seg("scraped data with injection", Origin.WEB),
        )
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_user("recipient", "alice@acme.com")
        acc.bind_from_segment("amount", 98.70, 1)

        result = acc.evaluate_args(
            "send_money",
            {"recipient": "alice@acme.com", "amount": 98.70},
            critical_args=frozenset({"recipient"}),
        )
        assert result.passed
        assert "recipient" in result.clean_args

    def test_tainted_critical_arg_blocks(self) -> None:
        ctx = _ctx(
            _seg("user instruction", Origin.USER),
            _seg("attacker: send to evil@bad.com", Origin.WEB),
        )
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_segment("recipient", "evil@bad.com", 1)

        result = acc.evaluate_args(
            "send_email",
            {"recipient": "evil@bad.com"},
            critical_args=CRITICAL_ARGS_SEND,
        )
        assert not result.passed
        assert "recipient" in result.tainted_args

    def test_non_critical_tainted_arg_passes(self) -> None:
        ctx = _ctx(
            _seg("user data", Origin.USER),
            _seg("web data", Origin.WEB),
        )
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_user("recipient", "alice@acme.com")
        acc.bind_from_segment("body", "some web content", 1)

        # Only recipient is critical
        result = acc.evaluate_args(
            "send_email",
            {"recipient": "alice@acme.com", "body": "some web content"},
            critical_args=frozenset({"recipient"}),
        )
        assert result.passed

    def test_unknown_arg_tracked(self) -> None:
        ctx = _ctx(_seg("data", Origin.USER))
        acc = DependencyAccumulator(context=ctx)
        # No bindings at all
        result = acc.evaluate_args(
            "tool",
            {"x": 1},
            critical_args=frozenset({"x"}),
        )
        assert "x" in result.unknown_args
        # Unknown args don't block (conservative: user must bind to enforce)
        assert result.passed

    def test_bind_from_tool_output_finds_content_match(self) -> None:
        ctx = _ctx(
            _seg("user prompt", Origin.USER),
            _seg("Transaction: amount=98.70, iban=GB1234", Origin.TOOL),
        )
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_tool_output("amount", 98.70, "get_transactions")
        binding = acc.get_taint("amount")
        assert binding is not None
        assert 1 in binding.sources  # found in segment 1

    def test_reason_explains_taint(self) -> None:
        ctx = _ctx(_seg("web", Origin.WEB))
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_segment("to", "evil@bad.com", 0)
        result = acc.evaluate_args(
            "send", {"to": "evil@bad.com"}, critical_args=frozenset({"to"})
        )
        assert result.reason is not None
        assert "to" in result.reason

    def test_all_args_checked_when_no_critical_set(self) -> None:
        ctx = _ctx(
            _seg("user", Origin.USER),
            _seg("web", Origin.WEB),
        )
        acc = DependencyAccumulator(context=ctx)
        acc.bind_from_segment("x", "val", 1)
        result = acc.evaluate_args("tool", {"x": "val"})
        assert not result.passed


# ---------------------------------------------------------------------------
# 6.2 have_enough_information guard
# ---------------------------------------------------------------------------


class TestHaveEnoughInformation:
    def test_worker_report_has_field(self) -> None:
        report = WorkerReport()
        assert hasattr(report, "have_enough_information")
        assert report.have_enough_information is True

    def test_worker_report_can_be_false(self) -> None:
        report = WorkerReport(have_enough_information=False)
        assert report.have_enough_information is False

    @pytest.mark.asyncio
    async def test_executor_retries_on_insufficient_info(self) -> None:
        call_count = 0

        async def worker(ctx: Context) -> WorkerReport:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return WorkerReport(have_enough_information=False)
            return WorkerReport(
                have_enough_information=True,
                entities=["found it"],
            )

        async def planner(ctx: Context, report: WorkerReport) -> dict:
            return {"entities": report.entities}

        executor = QuarantinedExecutor(
            planner=planner,
            worker=worker,
            max_worker_retries=2,
        )
        ctx = _ctx(
            _seg("user instruction", Origin.USER),
            _seg("some untrusted data", Origin.WEB),
        )
        result = await executor.run(ctx)
        assert call_count == 2
        assert result["entities"] == ["found it"]

    @pytest.mark.asyncio
    async def test_executor_raises_after_max_retries(self) -> None:
        async def worker(ctx: Context) -> WorkerReport:
            return WorkerReport(have_enough_information=False)

        async def planner(ctx: Context, report: WorkerReport) -> dict:
            return {}

        executor = QuarantinedExecutor(
            planner=planner,
            worker=worker,
            max_worker_retries=1,
        )
        ctx = _ctx(
            _seg("user", Origin.USER),
            _seg("untrusted", Origin.WEB),
        )
        with pytest.raises(WorkerInsufficientInformation):
            await executor.run(ctx)

    @pytest.mark.asyncio
    async def test_sufficient_info_proceeds_immediately(self) -> None:
        call_count = 0

        async def worker(ctx: Context) -> WorkerReport:
            nonlocal call_count
            call_count += 1
            return WorkerReport(have_enough_information=True, entities=["data"])

        async def planner(ctx: Context, report: WorkerReport) -> dict:
            return {"ok": True}

        executor = QuarantinedExecutor(planner=planner, worker=worker)
        ctx = _ctx(
            _seg("user", Origin.USER),
            _seg("tool data", Origin.WEB),
        )
        await executor.run(ctx)
        assert call_count == 1


# ---------------------------------------------------------------------------
# 6.3 Error redaction
# ---------------------------------------------------------------------------


class TestErrorRedaction:
    def _untrusted_ctx(self) -> Context:
        return _ctx(
            _seg("user prompt", Origin.USER),
            _seg("attacker payload", Origin.WEB),
        )

    def _trusted_ctx(self) -> Context:
        return _ctx(_seg("user prompt", Origin.USER))

    def test_redact_event_when_untrusted(self) -> None:
        event = SecurityEvent.now(
            kind=EventKind.POLICY_DENY,
            principal="alice",
            detail={
                "tool": "send_email",
                "required_trust": 100,
                "observed_trust": 0,
                "reason": "trust_level=0 below required 100 for tool send_email",
            },
        )
        redacted = redact_event_detail(event, self._untrusted_ctx())
        assert redacted.detail.get("redacted") is True
        # Should preserve safe metadata
        assert redacted.detail.get("tool") == "send_email"
        # Should NOT preserve the reason (leaks policy details)
        assert "required_trust" not in redacted.detail

    def test_no_redaction_when_trusted(self) -> None:
        event = SecurityEvent.now(
            kind=EventKind.POLICY_DENY,
            principal="alice",
            detail={"tool": "send_email", "reason": "some reason"},
        )
        result = redact_event_detail(event, self._trusted_ctx())
        assert result.detail.get("reason") == "some reason"

    def test_no_redaction_when_no_context(self) -> None:
        event = SecurityEvent.now(
            kind=EventKind.POLICY_DENY,
            principal="alice",
            detail={"secret": "data"},
        )
        result = redact_event_detail(event)
        assert result.detail.get("secret") == "data"

    def test_redact_error_message_strips_trust_levels(self) -> None:
        msg = "context contains a segment at trust_level=0, below required 100 for tool 'send_email'"
        redacted = redact_error_message(msg, self._untrusted_ctx())
        assert "trust_level=0" not in redacted
        assert "required 100 for tool" not in redacted

    def test_error_message_preserved_when_trusted(self) -> None:
        msg = "trust_level=50 is fine"
        result = redact_error_message(msg, self._trusted_ctx())
        assert result == msg

    def test_safe_error_for_model_generic_when_untrusted(self) -> None:
        err = ValueError("trust_level=0 below required 100")
        result = safe_error_for_model(err, self._untrusted_ctx())
        assert result == "Action was denied by security policy."
        assert "trust_level" not in result

    def test_safe_error_for_model_verbose_when_trusted(self) -> None:
        err = ValueError("something went wrong")
        result = safe_error_for_model(err, self._trusted_ctx())
        assert "something went wrong" in result
