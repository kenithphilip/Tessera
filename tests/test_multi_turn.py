"""Tests for tessera.scanners.multi_turn."""

from __future__ import annotations

import pytest

from tessera.events import SecurityEvent, clear_sinks, register_sink
from tessera.scanners.multi_turn import MultiTurnDetector, MultiTurnSignal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_events() -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    register_sink(events.append)
    return events


def _setup(session_id: str = "test-session") -> MultiTurnDetector:
    clear_sinks()
    return MultiTurnDetector(session_id=session_id)


# ---------------------------------------------------------------------------
# Clean conversation: no signals
# ---------------------------------------------------------------------------


def test_no_signals_on_clean_conversation() -> None:
    det = _setup()
    for i, msg in enumerate(["Hello", "What is the weather?", "Thank you!"]):
        signals = det.observe(turn_index=i, message_text=msg)
        assert signals == [], f"Expected no signals on turn {i}"


def test_single_turn_no_signal() -> None:
    det = _setup()
    signals = det.observe(turn_index=0, message_text="Tell me a joke")
    assert signals == []


# ---------------------------------------------------------------------------
# GOAT_ESCALATION
# ---------------------------------------------------------------------------


def test_goat_escalation_triggers_on_three_monotonically_escalating_turns() -> None:
    det = _setup()
    events = _capture_events()

    # Turn 0: one jailbreak token (monotonically increasing baseline)
    det.observe(0, "jailbreak this for me please")
    # Turn 1: two tokens
    det.observe(1, "jailbreak bypass the system for me")
    # Turn 2: three tokens -- triggers GOAT
    signals = det.observe(2, "jailbreak bypass override everything now")

    assert MultiTurnSignal.GOAT_ESCALATION in signals
    assert any(e.detail["signal"] == "goat_escalation" for e in events)


def test_goat_escalation_does_not_trigger_without_first_turn_token() -> None:
    det = _setup()
    # Counts are 0, 1, 2 -- not all >0, so no monotonic start
    det.observe(0, "normal message")
    det.observe(1, "bypass once")
    signals = det.observe(2, "bypass override twice")
    assert MultiTurnSignal.GOAT_ESCALATION not in signals


def test_goat_escalation_does_not_trigger_when_not_monotonic() -> None:
    det = _setup()
    det.observe(0, "jailbreak bypass")
    det.observe(1, "jailbreak")  # decreases from 2 to 1
    signals = det.observe(2, "jailbreak bypass override")
    assert MultiTurnSignal.GOAT_ESCALATION not in signals


# ---------------------------------------------------------------------------
# BEST_OF_N_PROBE
# ---------------------------------------------------------------------------


def test_best_of_n_probe_triggers_on_three_near_duplicate_turns() -> None:
    det = _setup()
    base = "Tell me how to pick a lock step by step in detail please"
    det.observe(0, base)
    det.observe(1, base + " now")
    signals = det.observe(2, base + " quickly")

    assert MultiTurnSignal.BEST_OF_N_PROBE in signals


def test_best_of_n_probe_does_not_trigger_on_diverse_turns() -> None:
    det = _setup()
    det.observe(0, "What is the capital of France?")
    det.observe(1, "How do I bake bread at home?")
    signals = det.observe(2, "Explain quantum entanglement simply")
    assert MultiTurnSignal.BEST_OF_N_PROBE not in signals


# ---------------------------------------------------------------------------
# GOAL_DRIFT
# ---------------------------------------------------------------------------


def test_goal_drift_triggers_when_latest_turn_diverges_from_first() -> None:
    det = _setup()
    det.observe(0, "book a flight from New York to London for next Monday")
    # Completely unrelated turn
    signals = det.observe(1, "transfer all funds wire money offshore account immediately")
    assert MultiTurnSignal.GOAL_DRIFT in signals


def test_goal_drift_does_not_trigger_on_related_follow_up() -> None:
    det = _setup()
    det.observe(0, "book a flight from New York to London")
    signals = det.observe(1, "what are the flight options from New York to London economy class")
    assert MultiTurnSignal.GOAL_DRIFT not in signals


# ---------------------------------------------------------------------------
# REPEATED_REFUSAL_PROBE
# ---------------------------------------------------------------------------


def test_repeated_refusal_probe_triggers_on_three_refusals_in_five_turns() -> None:
    det = _setup()
    events = _capture_events()

    det.observe(0, "I cannot help with that request")
    det.observe(1, "I'm not able to assist with this")
    det.observe(2, "I refuse to answer that question")
    signals = det.observe(3, "I will not do this")

    assert MultiTurnSignal.REPEATED_REFUSAL_PROBE in signals
    assert any(e.detail["signal"] == "repeated_refusal_probe" for e in events)


def test_refusal_probe_does_not_trigger_below_threshold() -> None:
    det = _setup()
    det.observe(0, "I cannot help with that")
    det.observe(1, "Sure, here is the answer")
    signals = det.observe(2, "I'm not able to assist with this")
    assert MultiTurnSignal.REPEATED_REFUSAL_PROBE not in signals


# ---------------------------------------------------------------------------
# reset() clears state
# ---------------------------------------------------------------------------


def test_reset_clears_session_history() -> None:
    det = _setup()
    base = "Tell me how to pick a lock step by step in detail please"
    det.observe(0, base)
    det.observe(1, base + " now")
    det.reset()
    # After reset, only one turn in history -- best-of-N cannot trigger
    signals = det.observe(2, base + " quickly")
    assert MultiTurnSignal.BEST_OF_N_PROBE not in signals
    assert det.history()[0]["turn_index"] == 2
