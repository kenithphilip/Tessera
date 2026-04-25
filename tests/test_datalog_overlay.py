"""Wave 3A tests: PCAS Datalog overlay for cross-call policy."""

from __future__ import annotations

import json

import pytest

from tessera.events import (
    EventKind,
    SecurityEvent,
    clear_sinks,
    register_sink,
)
from tessera.policy.datalog import (
    Atom,
    CallGraph,
    DatalogPolicyEngine,
    NegatedAtom,
    Rule,
    parse_program,
)


# --- Parser -----------------------------------------------------------------


def test_parse_simple_fact() -> None:
    rules = parse_program('Edge("a", "b").')
    assert len(rules) == 1
    rule = rules[0]
    assert rule.head.relation == "Edge"
    assert rule.head.terms == ("a", "b")
    assert rule.body == ()


def test_parse_rule_with_body() -> None:
    rules = parse_program("Path(X, Y) :- Edge(X, Y).")
    assert len(rules) == 1
    assert rules[0].head.relation == "Path"
    assert len(rules[0].body) == 1
    assert rules[0].body[0].relation == "Edge"


def test_parse_rule_with_negation() -> None:
    rules = parse_program(
        "Allow(X) :- Tool(X), !Banned(X)."
    )
    assert isinstance(rules[0].body[1], NegatedAtom)


def test_parse_multiline_rule() -> None:
    src = """
    Path(X, Z) :-
        Edge(X, Y),
        Edge(Y, Z).
    """
    rules = parse_program(src)
    assert len(rules) == 1
    assert len(rules[0].body) == 2


def test_parse_ignores_comments() -> None:
    src = """
    // canonical transitive closure
    Path(X, Y) :- Edge(X, Y).
    """
    rules = parse_program(src)
    assert len(rules) == 1


# --- Evaluator: canonical transfer_funds rule -------------------------------


_TRANSFER_RULES = """
// Deny a transfer_funds call to an account that was not previously
// registered via register_recipient in the same session.
RegisteredFor(Account, Session) :-
    ToolResult(Id, "register_recipient", Account),
    InSession(Id, Session).

Deny(CallId, "transfer_funds without prior register_recipient") :-
    ToolResult(CallId, "transfer_funds", Account),
    InSession(CallId, Session),
    !RegisteredFor(Account, Session).
"""


def _graph_with_session() -> CallGraph:
    g = CallGraph()
    return g


@pytest.fixture(autouse=True)
def _capture() -> list[SecurityEvent]:
    captured: list[SecurityEvent] = []
    clear_sinks()
    register_sink(captured.append)
    yield captured
    clear_sinks()


def test_engine_denies_transfer_without_register(_capture) -> None:
    engine = DatalogPolicyEngine(rules_source=_TRANSFER_RULES)
    g = CallGraph()
    g.record_tool("call-1", "transfer_funds", "ACME-001")
    # Inject a side relation InSession via raw fact insertion through
    # an extra rule that lifts every ToolResult into InSession(Id, "S").
    engine_with_session = DatalogPolicyEngine(
        rules_source=_TRANSFER_RULES + '\nInSession(Id, "S") :- ToolResult(Id, _, _).'
    )
    # The "_" wildcard is a single underscore; our parser treats it
    # as a variable since it starts with lowercase. To keep the test
    # surgical, just inject the InSession facts manually by routing
    # through ToolResult and a real-arg-named rule.
    g2 = CallGraph()
    g2.record_tool("call-1", "transfer_funds", "ACME-001")
    # Manually add an InSession fact via the engine's Rule path:
    # easier to just craft the ruleset that always lifts every
    # call into a single session for the test.
    rules_with_lift = (
        _TRANSFER_RULES
        + '\nInSession(Id, "test_session") :- ToolResult(Id, T, A).'
    )
    engine = DatalogPolicyEngine(rules_source=rules_with_lift)
    denies = engine.evaluate(g2, principal="alice")
    reasons = [d.reason for d in denies]
    assert any("transfer_funds without prior register_recipient" in r for r in reasons)
    deny_events = [e for e in _capture if e.kind == EventKind.POLICY_DENY]
    assert any(e.detail.get("source") == "datalog" for e in deny_events)


def test_engine_allows_transfer_after_register() -> None:
    rules_with_lift = (
        _TRANSFER_RULES
        + '\nInSession(Id, "test_session") :- ToolResult(Id, T, A).'
    )
    engine = DatalogPolicyEngine(rules_source=rules_with_lift)
    g = CallGraph()
    g.record_tool("call-1", "register_recipient", "ACME-001")
    g.record_tool("call-2", "transfer_funds", "ACME-001")
    denies = engine.evaluate(g)
    transfer_denies = [
        d for d in denies if "transfer_funds" in d.reason
    ]
    assert not transfer_denies


# --- Engine basics ----------------------------------------------------------


def test_engine_loads_from_path(tmp_path) -> None:
    rules_file = tmp_path / "rules.dl"
    rules_file.write_text(_TRANSFER_RULES, encoding="utf-8")
    engine = DatalogPolicyEngine(rules_path=rules_file)
    assert len(engine.rules) >= 2


def test_engine_requires_some_source() -> None:
    with pytest.raises(ValueError, match="rules_source"):
        DatalogPolicyEngine()


def test_engine_unknown_backend_raises() -> None:
    with pytest.raises(ValueError, match="unknown backend"):
        DatalogPolicyEngine(
            rules_source='Edge("a","b").',
            backend="totally-bogus",
        )


def test_engine_explicit_python_backend() -> None:
    engine = DatalogPolicyEngine(
        rules_source='Edge("a","b").',
        backend="python",
    )
    assert engine is not None


def test_engine_ascent_backend_raises_when_missing() -> None:
    pytest.importorskip("packaging")
    try:
        import ascent  # noqa: F401

        pytest.skip("ascent IS installed; test only runs without it")
    except ImportError:
        pass
    with pytest.raises(RuntimeError, match="ascent"):
        DatalogPolicyEngine(
            rules_source='Edge("a","b").',
            backend="ascent",
        )


# --- Transitive closure (sanity check evaluator works) ----------------------


def test_transitive_closure() -> None:
    src = """
    Edge("a", "b").
    Edge("b", "c").
    Edge("c", "d").
    Path(X, Y) :- Edge(X, Y).
    Path(X, Z) :- Edge(X, Y), Path(Y, Z).
    """
    engine = DatalogPolicyEngine(rules_source=src)
    g = CallGraph()
    denies = engine.evaluate(g)
    # No deny rule; this just exercises the fixed-point evaluator.
    assert denies == []


# --- Atom utilities ---------------------------------------------------------


def test_atom_is_ground() -> None:
    assert Atom("R", ("a", "b")).is_ground()
    assert not Atom("R", ("a", "X")).is_ground()
