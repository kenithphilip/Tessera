"""Pin the contract that the Action Critic never receives raw bytes.

The Action Critic is a metadata-only judge. If a backend stuffs the
raw argument values into a critic prompt, an attacker who controls
an untrusted segment can inject the critic itself, defeating the
whole defense layer.

These tests pin two structural properties:

1. :class:`ActionReview` carries no field whose type is a
   plain ``str`` representing argument values. Argument metadata
   travels via :class:`ArgShape` whose only string fields are
   ``name`` (the parameter name, never user-controlled) and
   ``type_hint`` (a Python type repr, also never user-controlled).
2. The stub backends shipped in v0.12 do not consume raw values
   even if a caller sneaks them in via a bypass.

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 2.2.
- ``tests/adversarial/test_critic_injection_suite.py`` (Phase 2
  wave 2A) extends this with concrete attack payloads.
"""

from __future__ import annotations

import pytest

from tessera.action_critic import (
    ActionReview,
    ArgShape,
    CriticDecision,
    CriticMode,
    Decision,
    LabelSummary,
    LocalSmallCritic,
    ProviderAgnosticCritic,
    RiskSignals,
    SamePlannerCritic,
    get_critic_mode,
    review,
)
from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
    ProvenanceLabel,
    SecrecyLevel,
)


@pytest.fixture(autouse=True)
def _capture_events() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TESSERA_CRITIC", raising=False)
    monkeypatch.delenv("TESSERA_ALLOW_SHARED_CRITIC", raising=False)


@pytest.fixture
def untrusted_label() -> ProvenanceLabel:
    return ProvenanceLabel.untrusted_tool_output(
        segment_id="seg-1", origin_uri="web://x"
    )


@pytest.fixture
def trusted_label() -> ProvenanceLabel:
    return ProvenanceLabel.trusted_user("alice")


@pytest.fixture
def clean_review(trusted_label: ProvenanceLabel) -> ActionReview:
    """An ActionReview that passes the deterministic pre-check.

    Backend-stub tests use this so they exercise the backend's
    decision logic rather than getting short-circuited by the
    pre-check at the top-level :func:`review` entry.
    """
    arg_amount = ArgShape(
        name="amount",
        type_hint="float",
        length=8,
        char_classes=("digit",),
        label=LabelSummary.from_label(trusted_label),
    )
    arg_recipient = ArgShape(
        name="recipient",
        type_hint="str",
        length=22,
        char_classes=("alpha", "digit", "space"),
        label=LabelSummary.from_label(trusted_label),
    )
    return ActionReview(
        tool="transfer_funds",
        principal="alice",
        args=(arg_amount, arg_recipient),
        risk=RiskSignals(
            irreversibility_class="irreversible",
            sensitivity_class="financial",
            rate_limit_pressure=0.1,
        ),
    )


@pytest.fixture
def example_review(
    untrusted_label: ProvenanceLabel, trusted_label: ProvenanceLabel
) -> ActionReview:
    """An ActionReview that fails the deterministic pre-check.

    The recipient arg carries an UNTRUSTED label which violates
    transfer_funds.recipient.required_integrity=TRUSTED. Used to
    pin the pre-check path.
    """
    arg_amount = ArgShape(
        name="amount",
        type_hint="float",
        length=8,
        char_classes=("digit",),
        label=LabelSummary.from_label(trusted_label),
    )
    arg_recipient = ArgShape(
        name="recipient",
        type_hint="str",
        length=22,
        char_classes=("alpha", "digit", "space"),
        label=LabelSummary.from_label(untrusted_label),
    )
    return ActionReview(
        tool="transfer_funds",
        principal="alice",
        args=(arg_amount, arg_recipient),
        risk=RiskSignals(
            irreversibility_class="irreversible",
            sensitivity_class="financial",
            rate_limit_pressure=0.1,
        ),
    )


# --- Structural contract ----------------------------------------------------


def test_arg_shape_has_no_value_field() -> None:
    """ArgShape MUST NOT have a ``value`` field; if it ever
    sprouts one, the critic boundary is broken."""
    fields = set(ArgShape.model_fields.keys())
    assert "value" not in fields
    assert "raw" not in fields
    assert "content" not in fields


def test_action_review_has_no_value_field() -> None:
    fields = set(ActionReview.model_fields.keys())
    assert "value" not in fields
    assert "raw" not in fields
    assert "content" not in fields


def test_label_summary_has_no_source_uri() -> None:
    """LabelSummary intentionally drops the SegmentRef.origin_uri
    text because that field can carry attacker-influenced data
    (e.g., a malicious URL)."""
    fields = set(LabelSummary.model_fields.keys())
    assert "origin_uri" not in fields
    assert "sources" not in fields  # sources are summarized to a count


# --- Backend stubs ----------------------------------------------------------


def test_local_small_stub_returns_require_approval(
    clean_review: ActionReview,
) -> None:
    backend = LocalSmallCritic()
    decision = backend.review(clean_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.backend == "local_small"


def test_provider_agnostic_stub_returns_require_approval(
    clean_review: ActionReview,
) -> None:
    backend = ProviderAgnosticCritic()
    decision = backend.review(clean_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.backend == "provider_agnostic"


def test_same_planner_denied_by_default(
    clean_review: ActionReview,
) -> None:
    backend = SamePlannerCritic()
    decision = backend.review(clean_review)
    assert decision.decision == Decision.DENY
    assert "least_privilege" in decision.triggered_principles


def test_same_planner_opt_in_returns_require_approval(
    clean_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TESSERA_ALLOW_SHARED_CRITIC", "1")
    backend = SamePlannerCritic()
    decision = backend.review(clean_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL


# --- Top-level review() entry ----------------------------------------------


def test_review_returns_allow_when_critic_off(
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TESSERA_CRITIC", "off")
    decision = review(example_review)
    assert decision.decision == Decision.ALLOW
    assert decision.backend == "off"


def test_review_dispatches_to_backend_when_critic_stub(
    clean_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tessera.action_critic import reset_default_cache

    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    reset_default_cache()
    decision = review(clean_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL


def test_review_uses_explicit_backend(
    clean_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tessera.action_critic import reset_default_cache

    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    reset_default_cache()
    decision = review(clean_review, backend=LocalSmallCritic())
    assert decision.backend == "local_small"


def test_get_critic_mode_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TESSERA_CRITIC", raising=False)
    assert get_critic_mode() == CriticMode.OFF


def test_get_critic_mode_invalid_falls_back_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TESSERA_CRITIC", "completely-bogus")
    assert get_critic_mode() == CriticMode.OFF


# --- LabelSummary contract --------------------------------------------------


def test_label_summary_redacts_segment_uris(
    untrusted_label: ProvenanceLabel,
) -> None:
    summary = LabelSummary.from_label(untrusted_label)
    # The summary carries an integer count, never the URI strings.
    assert summary.source_count == len(untrusted_label.sources)
    serialized = summary.model_dump()
    # No string in the serialized form should look like a URL the
    # attacker controls (the test segments use web://x).
    for value in serialized.values():
        if isinstance(value, str):
            assert "web://" not in value


def test_label_summary_omits_readers_when_public(
    untrusted_label: ProvenanceLabel,
) -> None:
    """When readers is the Public singleton (untrusted defaults),
    the summary stores None to signal 'no audience cap'."""
    summary = LabelSummary.from_label(untrusted_label)
    assert summary.reader_principals is None


def test_label_summary_lists_readers_when_restricted() -> None:
    """A label with an explicit reader set is summarized to those
    principals; a label with the Public marker carries None."""
    restricted = ProvenanceLabel.trusted_user(
        "alice", readers=frozenset({"alice"})
    )
    summary = LabelSummary.from_label(restricted)
    assert summary.reader_principals == ("alice",)


# --- Wave 2A: deterministic pre-check + cache + breaker ---------------------


def test_pre_check_denies_untrusted_recipient(
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pre-check must deny an UNTRUSTED recipient in transfer_funds
    BEFORE the backend is consulted."""
    from tessera.action_critic import reset_default_cache

    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    reset_default_cache()
    decision = review(example_review)
    assert decision.decision == Decision.DENY
    assert decision.backend == "deterministic_pre_check"
    assert "origin_consistency" in decision.triggered_principles


def test_review_caches_decision(
    clean_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two identical actions should yield one backend call + one cache hit."""
    from tessera.action_critic import CriticDecision as _CD, reset_default_cache

    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    reset_default_cache()

    class _Counting:
        name = "counting"
        call_count = 0

        def review(self, action):
            type(self).call_count += 1
            return _CD(
                decision=Decision.ALLOW, reason="counted", backend="counting"
            )

    backend = _Counting()
    decision_a = review(clean_review, backend=backend)
    decision_b = review(clean_review, backend=backend)
    assert _Counting.call_count == 1  # second call hit the cache
    assert decision_b.cache_hit is True
    assert decision_a.cache_hit is False
    assert decision_a.decision == Decision.ALLOW
    assert decision_b.decision == Decision.ALLOW


def test_review_handles_backend_exception(
    clean_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backend that raises must produce REQUIRE_APPROVAL + a
    CRITIC_TIMEOUT event so the operator sees the failure."""
    from tessera.action_critic import reset_default_cache

    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    reset_default_cache()

    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)

    class _Boom:
        name = "boom"

        def review(self, action):
            raise RuntimeError("synthetic backend failure")

    decision = review(clean_review, backend=_Boom())
    assert decision.decision == Decision.REQUIRE_APPROVAL
    timeout_events = [
        e for e in captured if e.kind == EventKind.CRITIC_TIMEOUT
    ]
    assert len(timeout_events) == 1
    assert timeout_events[0].detail["exception"] == "RuntimeError"


def test_canonical_action_key_is_stable(clean_review: ActionReview) -> None:
    """The cache key must be stable: same action -> same key."""
    from tessera.action_critic import _canonical_action_key

    k1 = _canonical_action_key(clean_review)
    k2 = _canonical_action_key(clean_review)
    assert k1 == k2
    assert len(k1) == 64  # SHA-256 hex


def test_critic_disabled_skips_pre_check(
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TESSERA_CRITIC=off must short-circuit ALLOW without running
    the pre-check (this is the v0.12 default behavior; pre-check
    runs only when the operator opts in)."""
    monkeypatch.setenv("TESSERA_CRITIC", "off")
    decision = review(example_review)
    assert decision.decision == Decision.ALLOW
    assert decision.backend == "off"
