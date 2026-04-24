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
def example_review(
    untrusted_label: ProvenanceLabel, trusted_label: ProvenanceLabel
) -> ActionReview:
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
    example_review: ActionReview, _capture_events
) -> None:
    backend = LocalSmallCritic()
    decision = backend.review(example_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.backend == "local_small"
    approval_events = [
        e for e in _capture_events if e.kind == EventKind.CRITIC_APPROVAL_REQUIRED
    ]
    assert len(approval_events) == 1


def test_provider_agnostic_stub_returns_require_approval(
    example_review: ActionReview, _capture_events
) -> None:
    backend = ProviderAgnosticCritic()
    decision = backend.review(example_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.backend == "provider_agnostic"


def test_same_planner_denied_by_default(
    example_review: ActionReview, _capture_events
) -> None:
    backend = SamePlannerCritic()
    decision = backend.review(example_review)
    assert decision.decision == Decision.DENY
    assert "least_privilege" in decision.triggered_principles
    deny_events = [e for e in _capture_events if e.kind == EventKind.CRITIC_DENY]
    assert len(deny_events) == 1


def test_same_planner_opt_in_returns_require_approval(
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TESSERA_ALLOW_SHARED_CRITIC", "1")
    backend = SamePlannerCritic()
    decision = backend.review(example_review)
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
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    decision = review(example_review)
    assert decision.decision == Decision.REQUIRE_APPROVAL


def test_review_uses_explicit_backend(
    example_review: ActionReview, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TESSERA_CRITIC", "stub")
    decision = review(example_review, backend=LocalSmallCritic())
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
