"""Tests for the native AlignmentCheck-style intent-drift scanner.

Covers:
- Default backend (off mode) returns ALLOW without an LLM call.
- StubBackend returning DENY produces ScanResult(allowed=False)
  with a high-severity finding.
- Backend exception or unparseable response is fail-open
  (allowed=True), with a GUARDRAIL_DECISION event recording the
  failure.
- Raw bytes never reach the assembled prompt: payload literals
  in the args dict do NOT appear in the prompt the backend
  receives; only ArgShape summaries do.
- Trajectory awareness: the same intent + tool combination
  flips decision when tool_call_history is added.
- Fast-path: low injection_score and no history short-circuits to
  ALLOW without invoking the backend.
- Plan-verifier composition: passing a scanner via
  verify_sequence() folds scanner verdicts into violations.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink
from tessera.plan_verifier import ToolSequenceSpec, verify_sequence
from tessera.scanners import ScanResult
from tessera.scanners.intent_drift import (
    BackendUnconfigured,
    IntentDriftBackend,
    IntentDriftScanner,
    StubBackend,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _CapturingBackend:
    """Test backend that records the prompts it receives."""

    name: str = "capture"
    response: str = '{"decision": "allow", "reason": "ok"}'
    last_system_prompt: str | None = None
    last_user_prompt: str | None = None

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return self.response


@dataclass
class _RaisingBackend:
    name: str = "raise"
    exc: Exception = RuntimeError("boom")

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        raise self.exc


@pytest.fixture(autouse=True)
def _isolated_event_sinks():
    clear_sinks()
    yield
    clear_sinks()


@pytest.fixture
def collected_events() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    register_sink(captured.append)
    return captured


# ---------------------------------------------------------------------------
# Default behaviour
# ---------------------------------------------------------------------------


def test_default_backend_off_returns_allow(monkeypatch):
    monkeypatch.delenv("TESSERA_INTENT_DRIFT_BACKEND", raising=False)
    scanner = IntentDriftScanner()
    result = scanner.scan(
        tool_name="search_inbox",
        args={"query": "vacation"},
        user_intent="Find emails about my vacation",
    )
    assert result.allowed is True
    assert result.findings == ()


def test_no_user_intent_returns_allow():
    scanner = IntentDriftScanner(backend=StubBackend(canned_decision="deny"))
    result = scanner.scan(tool_name="send_email", args={"to": "x"})
    assert result.allowed is True


# ---------------------------------------------------------------------------
# Decision mapping
# ---------------------------------------------------------------------------


def test_deny_decision_produces_high_severity_finding(collected_events):
    scanner = IntentDriftScanner(
        backend=StubBackend(
            canned_decision="deny",
            canned_reason="send_email is not part of the search request",
        ),
        injection_threshold=0.0,  # always invoke the backend
    )
    result = scanner.scan(
        tool_name="send_email",
        args={"to": "attacker@example.com", "body": "secrets"},
        user_intent="Search my inbox for vacation emails",
        tool_call_history=("search_inbox",),
    )
    assert result.allowed is False
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "high"
    assert finding.rule_id == "intent_drift.deny"
    assert "send_email" in finding.arg_path
    # Event emitted.
    deny_events = [e for e in collected_events if e.detail.get("outcome") == "deny"]
    assert len(deny_events) == 1
    assert deny_events[0].kind == EventKind.GUARDRAIL_DECISION


def test_require_approval_decision_is_medium_severity():
    scanner = IntentDriftScanner(
        backend=StubBackend(canned_decision="require_approval", canned_reason="ambiguous"),
        injection_threshold=0.0,
    )
    result = scanner.scan(
        tool_name="transfer_funds",
        args={"to": "1234", "amount": 100},
        user_intent="Pay rent",
        tool_call_history=("get_balance",),
    )
    assert result.allowed is False
    assert result.findings[0].severity == "medium"
    assert result.findings[0].rule_id == "intent_drift.require_approval"


def test_allow_decision_returns_allowed(collected_events):
    scanner = IntentDriftScanner(
        backend=StubBackend(canned_decision="allow", canned_reason="aligned"),
        injection_threshold=0.0,
    )
    result = scanner.scan(
        tool_name="search_inbox",
        args={"query": "vacation"},
        user_intent="Find vacation emails",
    )
    assert result.allowed is True
    # Allow path emits no security event (silent allow).
    decisions = [e for e in collected_events if e.detail.get("outcome") == "allow"]
    assert decisions == []


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


def test_backend_exception_is_fail_open(collected_events):
    scanner = IntentDriftScanner(
        backend=_RaisingBackend(exc=TimeoutError("network blew up")),
        injection_threshold=0.0,
    )
    result = scanner.scan(
        tool_name="search_inbox",
        args={"query": "vacation"},
        user_intent="search inbox for vacation emails",
    )
    assert result.allowed is True
    failures = [e for e in collected_events if e.detail.get("outcome") == "backend_failure"]
    assert len(failures) == 1
    assert "TimeoutError" in failures[0].detail["reason"]


def test_backend_unconfigured_is_fail_open(collected_events):
    scanner = IntentDriftScanner(
        backend=_RaisingBackend(exc=BackendUnconfigured("no key")),
        injection_threshold=0.0,
    )
    result = scanner.scan(
        tool_name="search_inbox",
        args={"q": "x"},
        user_intent="search emails",
    )
    assert result.allowed is True
    assert any(e.detail.get("outcome") == "backend_failure" for e in collected_events)


def test_unparseable_response_falls_back_to_require_approval():
    scanner = IntentDriftScanner(
        backend=StubBackend(canned_decision="??not-json", canned_reason="x"),
        injection_threshold=0.0,
    )
    # The StubBackend serialises canned_decision verbatim into JSON,
    # so the parse will succeed but the decision will be normalised
    # to require_approval. Use a backend that returns true garbage.
    raw = _RawBackend(payload="not json at all <<<")
    scanner.backend = raw
    result = scanner.scan(
        tool_name="search_inbox",
        args={"q": "x"},
        user_intent="search",
    )
    assert result.allowed is False
    assert result.findings[0].rule_id == "intent_drift.require_approval"
    assert "unparseable" in result.findings[0].message


@dataclass
class _RawBackend:
    payload: str = ""
    name: str = "raw"

    def review(self, *, system_prompt: str, user_prompt: str) -> str:
        return self.payload


# ---------------------------------------------------------------------------
# Raw-bytes invariant
# ---------------------------------------------------------------------------


def test_raw_argument_bytes_never_appear_in_backend_prompt():
    """Load-bearing: the LLM judge must NEVER see raw argument
    values. Pin via a backend that captures the prompt and asserts
    the literal payload string is absent."""
    capture = _CapturingBackend()
    scanner = IntentDriftScanner(backend=capture, injection_threshold=0.0)

    secret = "TOP_SECRET_API_KEY_DO_NOT_LEAK_42"
    scanner.scan(
        tool_name="send_email",
        args={"to": "dest@example.com", "body": secret},
        user_intent="Send a status update to the team",
        tool_call_history=("read_status",),
        tool_description="Send a plain-text email to the named recipient.",
    )
    assert capture.last_user_prompt is not None
    assert secret not in capture.last_user_prompt, (
        "raw argument value leaked into LLM prompt"
    )
    # The shape SHOULD appear (length, char_classes).
    assert "length" in capture.last_user_prompt
    # User intent and tool description SHOULD appear (trusted segments).
    assert "Send a status update" in capture.last_user_prompt
    assert "Send a plain-text email" in capture.last_user_prompt


# ---------------------------------------------------------------------------
# Trajectory awareness
# ---------------------------------------------------------------------------


def test_history_changes_decision_with_dynamic_backend():
    """The same (intent, tool) flips decision when history grows.

    We use a backend that toggles based on history length to prove the
    history is plumbed all the way through.
    """

    @dataclass
    class _HistoryAwareBackend:
        name: str = "history-aware"

        def review(self, *, system_prompt: str, user_prompt: str) -> str:
            if "search_inbox" in user_prompt and "send_email" in user_prompt:
                return '{"decision": "deny", "reason": "send_email after search not in intent"}'
            return '{"decision": "allow", "reason": "consistent"}'

    scanner = IntentDriftScanner(
        backend=_HistoryAwareBackend(), injection_threshold=0.0
    )
    intent = "Search my inbox for vacation emails"

    # No history: allow.
    r1 = scanner.scan(
        tool_name="search_inbox", args={"q": "vacation"}, user_intent=intent
    )
    assert r1.allowed is True

    # With send_email in history: deny.
    r2 = scanner.scan(
        tool_name="send_email",
        args={"to": "x", "body": "y"},
        user_intent=intent,
        tool_call_history=("search_inbox",),
    )
    assert r2.allowed is False


# ---------------------------------------------------------------------------
# Fast path (no LLM call)
# ---------------------------------------------------------------------------


def test_low_injection_score_short_circuits_to_allow():
    """Very benign intents should not pay the LLM cost when there's no history."""
    capture = _CapturingBackend()
    scanner = IntentDriftScanner(
        backend=capture, injection_threshold=1.0  # always short-circuit
    )
    result = scanner.scan(
        tool_name="search_inbox",
        args={"q": "hello"},
        user_intent="Find emails from my mom",
    )
    assert result.allowed is True
    assert capture.last_user_prompt is None  # backend not called


def test_destination_shaped_arg_skips_fast_path():
    """Calls with a recipient/url-shaped argument always go to the LLM."""

    capture = _CapturingBackend(response='{"decision": "allow", "reason": "ok"}')
    scanner = IntentDriftScanner(backend=capture, injection_threshold=1.0)
    scanner.scan(
        tool_name="send_email",
        args={"recipient": "x@example.com", "body": "y"},
        user_intent="Send a quick note",
    )
    assert capture.last_user_prompt is not None


# ---------------------------------------------------------------------------
# plan_verifier composition
# ---------------------------------------------------------------------------


def test_verify_sequence_with_intent_drift_scanner_records_violation():
    """When a scanner DENIES a call, verify_sequence should fold the
    verdict into its violations + score."""
    scanner = IntentDriftScanner(
        backend=StubBackend(canned_decision="deny", canned_reason="off-intent"),
        injection_threshold=0.0,
    )
    spec = ToolSequenceSpec(
        required_patterns=("search_*",),
        forbidden_patterns=(),
        max_calls=10,
    )
    proposed = ["search_inbox", "send_email"]
    args_list: list[object] = [{"q": "vacation"}, {"to": "x", "body": "y"}]
    result = verify_sequence(
        spec,
        proposed,
        scanner=scanner,
        user_intent="Search my inbox for vacation emails",
        proposed_args=args_list,
    )
    assert result.passed is False
    assert any("intent_drift.deny" in v for v in result.violations)
    assert "send_email" in result.unexpected_tools
    # Two scanner DENYs would add 0.4 each, but we only fail the
    # second one; assert the score is at least 0.4.
    assert result.score >= 0.4


def test_verify_sequence_without_scanner_unchanged():
    """Backwards-compat: existing callers that don't pass scanner=
    must see identical behaviour to before."""
    spec = ToolSequenceSpec(
        required_patterns=("search_*",),
        forbidden_patterns=("send_*",),
        max_calls=2,
    )
    result = verify_sequence(spec, ["search_inbox", "send_email"])
    assert result.passed is False
    assert any("send_email" in v for v in result.violations)


def test_verify_sequence_scanner_off_when_no_user_intent():
    """If the caller forgets to pass user_intent, the scanner is silently
    skipped (the heuristic check still runs)."""
    scanner = IntentDriftScanner(
        backend=StubBackend(canned_decision="deny"), injection_threshold=0.0
    )
    spec = ToolSequenceSpec(
        required_patterns=("search_*",), forbidden_patterns=(), max_calls=10
    )
    result = verify_sequence(
        spec, ["search_inbox"], scanner=scanner, user_intent=None
    )
    assert result.passed is True


# ---------------------------------------------------------------------------
# Backend selection from env var
# ---------------------------------------------------------------------------


def test_env_var_selects_local_small_backend(monkeypatch):
    monkeypatch.setenv("TESSERA_INTENT_DRIFT_BACKEND", "local-small")
    scanner = IntentDriftScanner()
    from tessera.scanners.intent_drift import LocalSmallBackend

    assert isinstance(scanner.backend, LocalSmallBackend)


def test_env_var_selects_provider_agnostic_backend(monkeypatch):
    monkeypatch.setenv("TESSERA_INTENT_DRIFT_BACKEND", "provider-agnostic")
    scanner = IntentDriftScanner()
    from tessera.scanners.intent_drift import ProviderAgnosticBackend

    assert isinstance(scanner.backend, ProviderAgnosticBackend)


def test_unknown_env_var_falls_back_to_off(monkeypatch):
    monkeypatch.setenv("TESSERA_INTENT_DRIFT_BACKEND", "this-does-not-exist")
    scanner = IntentDriftScanner()
    assert isinstance(scanner.backend, StubBackend)
    # The fallback canned decision is allow.
    result = scanner.scan(
        tool_name="search", args={"q": "x"}, user_intent="search inbox"
    )
    assert result.allowed is True


# ---------------------------------------------------------------------------
# IntentDriftBackend protocol surface
# ---------------------------------------------------------------------------


def test_protocol_is_satisfied_by_stub():
    """StubBackend must satisfy the runtime-checkable IntentDriftBackend protocol."""
    assert isinstance(StubBackend(), IntentDriftBackend)
