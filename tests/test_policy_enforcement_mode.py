"""Phase 1B-iii audit gap 5: policy.py honors TESSERA_ENFORCEMENT_MODE."""

from __future__ import annotations

import pytest

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.policy import Policy, ResourceRequirement, ResourceType
from tessera.policy.tool_critical_args import (
    EnforcementMode,
    get_enforcement_mode,
)
from tessera.taint import DependencyAccumulator, from_segment


_KEY = b"k" * 32


def _ctx_with_untrusted(content: str) -> Context:
    seg = make_segment(
        content=content,
        origin=Origin.WEB,
        principal="untrusted",
        key=_KEY,
        trust_level=TrustLevel.UNTRUSTED,
    )
    ctx = Context()
    ctx.add(seg)
    return ctx


def _build_policy() -> Policy:
    return Policy(
        requirements={
            ("send_email", ResourceType.TOOL): ResourceRequirement(
                name="send_email",
                resource_type=ResourceType.TOOL,
                required_trust=TrustLevel.UNTRUSTED,
                side_effects=True,
            ),
        },
        default_required_trust=TrustLevel.UNTRUSTED,
    )


def test_get_enforcement_mode_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """v1.0 wave 4A flipped the default from BOTH to ARGS."""
    monkeypatch.delenv("TESSERA_ENFORCEMENT_MODE", raising=False)
    assert get_enforcement_mode() == EnforcementMode.ARGS


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("scalar", EnforcementMode.SCALAR),
        ("args", EnforcementMode.ARGS),
        ("both", EnforcementMode.BOTH),
        ("ARGS", EnforcementMode.ARGS),
        # v1.0 default: unknown values fall back to ARGS, not BOTH.
        ("totally-bogus", EnforcementMode.ARGS),
    ],
)
def test_enforcement_mode_env_parsing(
    raw: str,
    expected: EnforcementMode,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TESSERA_ENFORCEMENT_MODE", raw)
    assert get_enforcement_mode() == expected


def test_policy_evaluate_skips_arg_check_in_scalar_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scalar mode: arg-level check does NOT fire even when an
    accumulator is provided. Min_trust floor is the only gate."""
    monkeypatch.setenv("TESSERA_ENFORCEMENT_MODE", "scalar")
    policy = _build_policy()
    ctx = _ctx_with_untrusted("hi")
    accumulator = DependencyAccumulator(context=ctx)
    accumulator.bind("recipient", from_segment("evil@x", 0))
    decision = policy.evaluate(
        ctx,
        tool_name="send_email",
        args={"recipient": "evil@x"},
        accumulator=accumulator,
    )
    assert decision.allowed is True


def test_policy_evaluate_runs_arg_check_in_both_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both mode: arg-level check fires; UNTRUSTED critical arg denies."""
    monkeypatch.setenv("TESSERA_ENFORCEMENT_MODE", "both")
    policy = _build_policy()
    ctx = _ctx_with_untrusted("hi")
    accumulator = DependencyAccumulator(context=ctx)
    accumulator.bind("recipient", from_segment("evil@x", 0))
    decision = policy.evaluate(
        ctx,
        tool_name="send_email",
        args={"recipient": "evil@x"},
        accumulator=accumulator,
    )
    assert decision.allowed is False


def test_policy_evaluate_runs_arg_check_in_args_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Args mode also runs the arg-level check (it is the v1.0 primary)."""
    monkeypatch.setenv("TESSERA_ENFORCEMENT_MODE", "args")
    policy = _build_policy()
    ctx = _ctx_with_untrusted("hi")
    accumulator = DependencyAccumulator(context=ctx)
    accumulator.bind("recipient", from_segment("evil@x", 0))
    decision = policy.evaluate(
        ctx,
        tool_name="send_email",
        args={"recipient": "evil@x"},
        accumulator=accumulator,
    )
    assert decision.allowed is False
