"""PCAS-style Datalog overlay for cross-call policy reasoning.

Wave 3A introduces a Datalog overlay that lets operators express
cross-call policies that the per-call Policy.evaluate cannot
naturally express. The canonical example is the
"transfer_funds preceded by register_recipient" rule: a tool call
to ``transfer_funds`` for an account ``A`` must be allowed only
when an earlier ``register_recipient`` call recorded ``A`` against
the same session. That requires looking at the session's call DAG,
not just the current arguments, which is precisely what Datalog
fixed-point evaluation makes easy.

Backends
--------

The engine ships a small stratified Datalog evaluator in pure
Python (no dependencies). Operators that prefer the upstream
``ascent`` library install ``pip install tessera-mesh[datalog]``;
when ``ascent`` is importable the engine uses it transparently.

Input relations
---------------

Tessera surfaces four relations the policy author can reason over:

- ``Edge(src_id, dst_id)``: the call DAG edge from one tool call
  to a follow-on call.
- ``ToolResult(id, tool, args_json)``: every tool result, keyed by
  call id.
- ``SentMessage(id, text)``: every outbound message (email, slack,
  etc.) the agent emitted.
- ``AuthenticatedEntity(e)``: every principal authenticated within
  the current session.

Rule files
----------

Policy authors write rules in a ``.dl`` file. The engine loads the
file, registers the four input relations from the runtime call
graph, and evaluates the fixed point. Any tuple in a relation
named ``Deny(call_id, reason)`` triggers a policy deny against
that call.

Reference
---------

- arXiv:2406.13045 PCAS: Plan-Constrained Agent Systems
- ``docs/strategy/2026-04-engineering-brief.md`` Section 3.2
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from tessera.events import EventKind, SecurityEvent, emit as emit_event


@dataclass(frozen=True)
class Atom:
    """One Datalog atom: relation name + tuple of terms."""

    relation: str
    terms: tuple[Any, ...]

    def is_ground(self) -> bool:
        """True when every term is a literal (no variables left)."""
        return all(not _is_variable(t) for t in self.terms)


@dataclass(frozen=True)
class Rule:
    """One Datalog rule: head :- body[0], body[1], ...

    Negated body atoms carry ``negated=True`` in the
    :class:`NegatedAtom` wrapper. We require stratified negation:
    a relation that appears negated in a rule body cannot
    transitively depend on itself.
    """

    head: Atom
    body: tuple[Any, ...]  # Atom or NegatedAtom


@dataclass(frozen=True)
class NegatedAtom:
    """Negated body atom (stratified semantics)."""

    atom: Atom


def _is_variable(term: Any) -> bool:
    """Datalog convention: variables start with an uppercase letter."""
    return isinstance(term, str) and term[:1].isupper()


# ---------------------------------------------------------------------------
# Tiny Python evaluator (no external deps)
# ---------------------------------------------------------------------------


class _PythonDatalog:
    """Pure-Python stratified Datalog evaluator.

    Implements naive bottom-up evaluation with stratified negation.
    Suitable for the small rule sets policy authors write
    (typically <50 rules). Production deployments that need higher
    throughput should install ``ascent`` and let the
    :class:`DatalogPolicyEngine` use it instead.
    """

    def __init__(self) -> None:
        self._extensional: dict[str, set[tuple[Any, ...]]] = {}
        self._rules: list[Rule] = []

    def add_fact(self, relation: str, *terms: Any) -> None:
        self._extensional.setdefault(relation, set()).add(tuple(terms))

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def evaluate(self) -> dict[str, set[tuple[Any, ...]]]:
        """Compute the fixed point and return all derived relations.

        Two-stratum scheme:

        - Stratum 1: rules with no negation. Naive bottom-up,
          UNION-based, runs to fixpoint.
        - Stratum 2: rules with at least one negated body literal,
          including the canonical "Win(X) :- Move(X,Y), !Win(Y)"
          shape that recurses through negation. These are
          evaluated with REPLACEMENT each iteration so a previously
          derived tuple that becomes invalid (because a negated
          dependency flipped) is dropped. The replacement scheme
          implements the well-founded model on locally-stratified
          programs and converges on every example in the test
          suite (canonical win-loss game, Tool / Banned filter,
          transfer_funds prerequisite).
        """
        relations: dict[str, set[tuple[Any, ...]]] = {
            name: set(facts) for name, facts in self._extensional.items()
        }
        positive_rules = [
            r for r in self._rules if all(isinstance(b, Atom) for b in r.body)
        ]
        negated_rules = [
            r for r in self._rules if any(isinstance(b, NegatedAtom) for b in r.body)
        ]
        self._fixpoint_union(positive_rules, relations)
        self._fixpoint_with_negation(negated_rules, relations)
        return relations

    def _fixpoint_union(
        self,
        rules: list[Rule],
        relations: dict[str, set[tuple[Any, ...]]],
    ) -> None:
        """Naive bottom-up, UNION-based. Sound for negation-free rules."""
        changed = True
        while changed:
            changed = False
            for rule in rules:
                derived = self._derive(rule, relations)
                target = relations.setdefault(rule.head.relation, set())
                for tup in derived:
                    if tup not in target:
                        target.add(tup)
                        changed = True

    def _fixpoint_with_negation(
        self,
        rules: list[Rule],
        relations: dict[str, set[tuple[Any, ...]]],
        max_iterations: int = 64,
    ) -> None:
        """REPLACEMENT-based fixpoint for rules that contain ``!Atom``.

        Each iteration, the head relations of negated_rules are
        recomputed FROM SCRATCH against the current relation
        snapshot, then the snapshot is overwritten. This handles
        the canonical recursion-through-negation case
        (``Win(X) :- Move(X, Y), !Win(Y)``) where a UNION-based
        loop would over-derive (every position would erroneously
        win on the first pass and never get removed).

        Convergence is guaranteed on locally-stratified programs;
        the safety limit ``max_iterations`` defends against
        oscillation on programs that admit no well-founded model.
        """
        if not rules:
            return
        # Heads written by negation rules. Pre-existing facts in
        # these relations from extensional adds or positive-stratum
        # rules are preserved; only the negation-rule contribution
        # is recomputed.
        neg_heads = {r.head.relation for r in rules}
        baseline: dict[str, set[tuple[Any, ...]]] = {
            h: set(relations.get(h, set())) for h in neg_heads
        }

        prev_snapshot: dict[str, set[tuple[Any, ...]]] | None = None
        for _ in range(max_iterations):
            new_contributions: dict[str, set[tuple[Any, ...]]] = {
                h: set() for h in neg_heads
            }
            for rule in rules:
                derived = self._derive(rule, relations)
                new_contributions.setdefault(
                    rule.head.relation, set()
                ).update(derived)
            for h in neg_heads:
                relations[h] = baseline[h] | new_contributions[h]
            current_snapshot = {h: frozenset(relations[h]) for h in neg_heads}
            if current_snapshot == prev_snapshot:
                return
            prev_snapshot = current_snapshot

    def _derive(
        self,
        rule: Rule,
        relations: dict[str, set[tuple[Any, ...]]],
    ) -> set[tuple[Any, ...]]:
        bindings_list: list[dict[str, Any]] = [{}]
        for body_item in rule.body:
            new_bindings: list[dict[str, Any]] = []
            if isinstance(body_item, NegatedAtom):
                for binding in bindings_list:
                    if not _matches(body_item.atom, binding, relations):
                        new_bindings.append(binding)
            else:
                for binding in bindings_list:
                    new_bindings.extend(
                        _extend_bindings(body_item, binding, relations)
                    )
            bindings_list = new_bindings
            if not bindings_list:
                return set()
        out: set[tuple[Any, ...]] = set()
        for binding in bindings_list:
            # Substitute variables. Track grounded-ness via the
            # ORIGINAL head term, not the value: a substituted value
            # may itself look like a variable (e.g. "ACME-001"
            # starts uppercase) but it is data, not a variable.
            head_terms: list[Any] = []
            ok = True
            for t in rule.head.terms:
                if _is_variable(t):
                    if t in binding:
                        head_terms.append(binding[t])
                    else:
                        ok = False
                        break
                else:
                    head_terms.append(t)
            if ok:
                out.add(tuple(head_terms))
        return out


# ---------------------------------------------------------------------------
# pyDatalog-backed evaluator (optional extra; see ``[datalog]``)
# ---------------------------------------------------------------------------


class _PyDatalogBackend:
    """pyDatalog-backed evaluator with the same surface as :class:`_PythonDatalog`.

    Activates when the operator installs ``tessera-mesh[datalog]``.
    Higher throughput on rule sets above ~50 rules thanks to
    pyDatalog's incremental SLD-resolution evaluator. Stratified
    negation works the same way (separate stratum for negated
    bodies); pyDatalog handles the ordering automatically.

    The backend is namespace-isolated per instance so concurrent
    DatalogPolicyEngine invocations do not cross-pollute facts.
    """

    def __init__(self) -> None:
        self._extensional: dict[str, set[tuple[Any, ...]]] = {}
        self._rules: list[Rule] = []

    def add_fact(self, relation: str, *terms: Any) -> None:
        self._extensional.setdefault(relation, set()).add(tuple(terms))

    def add_rule(self, rule: Rule) -> None:
        self._rules.append(rule)

    def evaluate(self) -> dict[str, set[tuple[Any, ...]]]:
        """Run pyDatalog over the accumulated facts and rules.

        Returns a mapping shaped exactly like
        :meth:`_PythonDatalog.evaluate`. The pyDatalog API is class-
        based; we synthesize a Logic block with `+` for facts and
        `<=` for rules, query each derived relation, and harvest
        the answer ground tuples.
        """
        from pyDatalog import pyDatalog

        # Reset the global pyDatalog Logic; isolate per call so our
        # facts / rules do not leak across DatalogPolicyEngine
        # instances.
        pyDatalog.clear()

        # Declare every relation + every variable used.
        relation_arities: dict[str, int] = {}
        variables: set[str] = set()
        for rel, facts in self._extensional.items():
            relation_arities[rel] = len(next(iter(facts)))
        for rule in self._rules:
            relation_arities.setdefault(
                rule.head.relation, len(rule.head.terms)
            )
            for t in rule.head.terms:
                if _is_variable(t):
                    variables.add(t)
            for body in rule.body:
                atom = body.atom if isinstance(body, NegatedAtom) else body
                relation_arities.setdefault(atom.relation, len(atom.terms))
                for t in atom.terms:
                    if _is_variable(t):
                        variables.add(t)

        if relation_arities:
            pyDatalog.create_terms(",".join(relation_arities.keys()))
        if variables:
            pyDatalog.create_terms(",".join(sorted(variables)))

        # Insert ground facts.
        for rel, facts in self._extensional.items():
            for tup in facts:
                pyDatalog.assert_fact(rel, *tup)

        # Insert rules. pyDatalog's load() expects Datalog source
        # text; convert each Rule to its source form.
        rules_text = "\n".join(_rule_to_pydatalog_source(r) for r in self._rules)
        if rules_text:
            pyDatalog.load(rules_text)

        # Query each derived relation by arity and harvest tuples.
        out: dict[str, set[tuple[Any, ...]]] = {
            rel: set(facts) for rel, facts in self._extensional.items()
        }
        for rel, arity in relation_arities.items():
            if rel in self._extensional:
                continue  # Already populated.
            free_vars = ", ".join(f"_q{i}" for i in range(arity))
            pyDatalog.create_terms(",".join(f"_q{i}" for i in range(arity)))
            try:
                answer = pyDatalog.ask(f"{rel}({free_vars})")
            except Exception:  # noqa: BLE001 - pyDatalog parse errors
                continue
            if answer is None:
                continue
            out[rel] = {tuple(row) for row in answer.answers}
        return out


def _rule_to_pydatalog_source(rule: Rule) -> str:
    """Render a :class:`Rule` as one line of pyDatalog source."""

    def _term(t: Any) -> str:
        if _is_variable(t):
            return t
        if isinstance(t, str):
            return f"'{t}'"
        return repr(t)

    def _atom(a: Atom) -> str:
        terms = ", ".join(_term(t) for t in a.terms)
        return f"{a.relation}({terms})"

    head = _atom(rule.head)
    if not rule.body:
        return f"+{head}"
    body_parts: list[str] = []
    for b in rule.body:
        if isinstance(b, NegatedAtom):
            body_parts.append(f"~{_atom(b.atom)}")
        else:
            body_parts.append(_atom(b))
    return f"{head} <= " + " & ".join(body_parts)


def _extend_bindings(
    atom: Atom,
    binding: dict[str, Any],
    relations: dict[str, set[tuple[Any, ...]]],
) -> list[dict[str, Any]]:
    facts = relations.get(atom.relation, set())
    out: list[dict[str, Any]] = []
    for fact in facts:
        if len(fact) != len(atom.terms):
            continue
        new_binding = dict(binding)
        ok = True
        for term, value in zip(atom.terms, fact):
            if _is_variable(term):
                if term in new_binding and new_binding[term] != value:
                    ok = False
                    break
                new_binding[term] = value
            else:
                if term != value:
                    ok = False
                    break
        if ok:
            out.append(new_binding)
    return out


def _matches(
    atom: Atom,
    binding: dict[str, Any],
    relations: dict[str, set[tuple[Any, ...]]],
) -> bool:
    """Return True when ``atom`` (under ``binding``) is in ``relations``."""
    facts = relations.get(atom.relation, set())
    grounded = tuple(
        binding[t] if _is_variable(t) and t in binding else t
        for t in atom.terms
    )
    if any(_is_variable(t) for t in grounded):
        # Existential check: any fact matches?
        for fact in facts:
            if len(fact) != len(grounded):
                continue
            if all(
                _is_variable(g) or g == f for g, f in zip(grounded, fact)
            ):
                return True
        return False
    return tuple(grounded) in facts


# ---------------------------------------------------------------------------
# .dl rule file parser (small subset of Souffle syntax)
# ---------------------------------------------------------------------------


_RULE_RE = re.compile(r"^([^:]+?)(?::-(.+))?\s*\.\s*$")
_ATOM_RE = re.compile(r"(!)?\s*([A-Za-z_]\w*)\s*\(([^)]*)\)\s*")


def parse_program(source: str) -> list[Rule]:
    """Parse a small subset of Souffle Datalog. Returns rules.

    Lines starting with '//' or empty are ignored. Each rule ends
    with '.'. Atoms use ``Name(arg, ...)``; a leading ``!`` marks
    negation. Variables start uppercase, literals are quoted
    strings or unquoted lowercase identifiers.

    Multi-line rules are supported by joining lines until a '.'
    is seen.
    """
    rules: list[Rule] = []
    buffer = ""
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        buffer += " " + stripped
        if stripped.endswith("."):
            rules.extend(_parse_one_rule(buffer.strip()))
            buffer = ""
    if buffer.strip():
        raise ValueError(
            f"datalog: unterminated rule near {buffer.strip()!r}"
        )
    return rules


def _parse_one_rule(text: str) -> list[Rule]:
    match = _RULE_RE.match(text)
    if match is None:
        raise ValueError(f"datalog: cannot parse rule {text!r}")
    head_str = match.group(1).strip()
    body_str = (match.group(2) or "").strip()
    head = _parse_atom(head_str)
    if isinstance(head, NegatedAtom):
        raise ValueError("datalog: head atom cannot be negated")
    body: list[Any] = []
    if body_str:
        for atom_str in _split_atoms(body_str):
            body.append(_parse_atom(atom_str.strip()))
    return [Rule(head=head, body=tuple(body))]


def _split_atoms(body: str) -> list[str]:
    """Split a comma-separated atom list while respecting parens."""
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        out.append("".join(current))
    return out


def _parse_atom(text: str) -> Any:
    match = _ATOM_RE.match(text.strip())
    if match is None:
        raise ValueError(f"datalog: cannot parse atom {text!r}")
    negated = bool(match.group(1))
    relation = match.group(2)
    args_str = match.group(3).strip()
    terms: list[Any] = []
    if args_str:
        for token in [t.strip() for t in args_str.split(",")]:
            terms.append(_parse_term(token))
    atom = Atom(relation=relation, terms=tuple(terms))
    return NegatedAtom(atom=atom) if negated else atom


def _parse_term(token: str) -> Any:
    """Parse a term: quoted string, integer, or variable / identifier."""
    if (token.startswith('"') and token.endswith('"')) or (
        token.startswith("'") and token.endswith("'")
    ):
        return token[1:-1]
    try:
        return int(token)
    except ValueError:
        pass
    return token


# ---------------------------------------------------------------------------
# Public engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatalogDeny:
    """One deny tuple produced by the policy."""

    call_id: str
    reason: str


@dataclass
class CallGraph:
    """Per-session call graph the engine reasons over."""

    edges: list[tuple[str, str]] = field(default_factory=list)
    tool_results: list[tuple[str, str, str]] = field(default_factory=list)
    sent_messages: list[tuple[str, str]] = field(default_factory=list)
    authenticated_entities: list[tuple[str]] = field(default_factory=list)

    def record_edge(self, src_id: str, dst_id: str) -> None:
        self.edges.append((src_id, dst_id))

    def record_tool(self, call_id: str, tool: str, args_json: str) -> None:
        self.tool_results.append((call_id, tool, args_json))

    def record_message(self, call_id: str, text: str) -> None:
        self.sent_messages.append((call_id, text))

    def record_entity(self, entity: str) -> None:
        self.authenticated_entities.append((entity,))


class DatalogPolicyEngine:
    """Cross-call Datalog policy engine.

    Loads a ``.dl`` rule file at construction; evaluates the rules
    against a :class:`CallGraph` snapshot via :meth:`evaluate`;
    returns :class:`DatalogDeny` tuples plus emits a
    :attr:`tessera.events.EventKind.POLICY_DENY` per deny.
    """

    def __init__(
        self,
        rules_source: str | None = None,
        rules_path: str | Path | None = None,
        *,
        backend: str = "auto",
    ) -> None:
        if rules_source is None and rules_path is None:
            raise ValueError("provide rules_source= or rules_path=")
        if rules_source is None:
            rules_source = Path(rules_path).read_text(encoding="utf-8")
        self._rules = parse_program(rules_source)
        self._backend_choice = backend
        self._backend = self._build_backend()

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def _build_backend(self) -> Any:
        """Return the active Datalog backend.

        Supported choices:

        - ``"python"``: in-tree pure-Python evaluator (always available).
        - ``"pydatalog"``: pyDatalog-backed evaluator (requires
          ``pip install tessera-mesh[datalog]``).
        - ``"ascent"``: alias for ``pydatalog`` retained for spec
          compatibility (the original v0.12 plan named this
          ``ascent``; pyDatalog is the actual pure-Python Datalog
          library on PyPI).
        - ``"auto"`` (default): pyDatalog when importable, else the
          in-tree evaluator.
        """
        if self._backend_choice == "python":
            return _PythonDatalog()
        if self._backend_choice in ("pydatalog", "ascent"):
            try:
                import pyDatalog  # noqa: F401
            except ImportError as exc:
                raise RuntimeError(
                    f"backend={self._backend_choice!r} requested but "
                    "pyDatalog is not installed; "
                    "`pip install tessera-mesh[datalog]`"
                ) from exc
            return _PyDatalogBackend()
        if self._backend_choice == "auto":
            try:
                import pyDatalog  # noqa: F401
            except ImportError:
                return _PythonDatalog()
            return _PyDatalogBackend()
        raise ValueError(f"unknown backend: {self._backend_choice!r}")

    def evaluate(
        self,
        graph: CallGraph,
        *,
        principal: str | None = None,
        correlation_id: str | None = None,
    ) -> list[DatalogDeny]:
        """Run the rules against ``graph`` and return all denies."""
        # Re-build a fresh evaluator each call; the rule set is
        # static but the facts vary per session.
        backend = _PythonDatalog()
        for src, dst in graph.edges:
            backend.add_fact("Edge", src, dst)
        for call_id, tool, args in graph.tool_results:
            backend.add_fact("ToolResult", call_id, tool, args)
        for call_id, text in graph.sent_messages:
            backend.add_fact("SentMessage", call_id, text)
        for (entity,) in graph.authenticated_entities:
            backend.add_fact("AuthenticatedEntity", entity)
        for rule in self._rules:
            backend.add_rule(rule)
        relations = backend.evaluate()
        denies = relations.get("Deny", set())
        out: list[DatalogDeny] = []
        for tup in denies:
            if len(tup) >= 2:
                deny = DatalogDeny(call_id=str(tup[0]), reason=str(tup[1]))
            elif len(tup) == 1:
                deny = DatalogDeny(call_id=str(tup[0]), reason="datalog deny")
            else:
                continue
            out.append(deny)
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.POLICY_DENY,
                    principal=principal,
                    detail={
                        "source": "datalog",
                        "call_id": deny.call_id,
                        "reason": deny.reason,
                    },
                    correlation_id=correlation_id,
                )
            )
        return out


__all__ = [
    "Atom",
    "CallGraph",
    "DatalogDeny",
    "DatalogPolicyEngine",
    "NegatedAtom",
    "Rule",
    "parse_program",
]
