"""Static URL pattern rules: a fast deterministic gate before any LLM judge.

A two-tier outbound flow looks like this:

    1. URLRules.evaluate(url, method)
        -> ALLOW (allowlist hit)   -> short-circuit, skip everything below
        -> DENY  (denylist hit)    -> short-circuit, return rule_id
        -> NO_MATCH                -> fall through to the rest of the pipeline

    2. SSRFGuard.check_url(url)         (defense for "ALLOW" wasn't enough)
    3. LLMGuardrail / scanners          (semantic analysis on the body)

The point of this layer is to skip the expensive scanners and LLM judge
on the high-traffic predictable URLs: known-good API endpoints get an
immediate ALLOW, known-bad domains get an immediate DENY with a stable
rule_id in the audit log. Everything ambiguous falls through.

Pattern shapes
--------------
Three pattern types, evaluated in order: ``exact`` > ``prefix`` > ``glob``.
This ordering is meaningful: it gives the operator a way to carve out
exceptions from broad rules. Within each tier deny-wins-over-allow, so
adding a deny rule for ``/admin`` cannot be silently overridden by a
permissive ``/`` allow.

* ``exact``: string equality on the full URL.
* ``prefix``: the rule's pattern is a prefix of the URL.
* ``glob``: ``fnmatch``-style ``*`` and ``?`` wildcards on the full URL.

Method filter
-------------
Each rule may carry a method allowlist (``methods=["GET", "POST"]``).
If set, the rule only applies when the request's HTTP method is in the
list. ``methods=None`` (default) matches any method.

Why this is not a regex engine
------------------------------
Regex authoring is a footgun for security policy: catastrophic
backtracking, accidental anchoring, escaping mistakes. The three
shapes above cover everything operators reliably want to express
without giving them a way to ship a denial-of-service rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Iterable


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class RuleVerdict(StrEnum):
    """The gate's outcome on a single URL+method check."""

    ALLOW = "allow"
    DENY = "deny"
    NO_MATCH = "no_match"


class PatternKind(StrEnum):
    EXACT = "exact"
    PREFIX = "prefix"
    GLOB = "glob"


@dataclass(frozen=True)
class URLRule:
    """One static rule.

    Attributes:
        rule_id: Stable identifier for audit logs (``url.allow.github.api``,
            ``url.deny.internal.admin``, etc.). Operators choose the
            namespace.
        pattern: The string the rule matches against.
        kind: How to interpret ``pattern`` (exact / prefix / glob).
        action: ALLOW or DENY when this rule fires.
        methods: Optional uppercase HTTP method allowlist; None = any.
        description: Human-readable note for the audit log.
    """

    rule_id: str
    pattern: str
    kind: PatternKind = PatternKind.EXACT
    action: RuleAction = RuleAction.ALLOW
    methods: tuple[str, ...] | None = None
    description: str = ""

    def matches_method(self, method: str) -> bool:
        if self.methods is None:
            return True
        return method.upper() in self.methods

    def matches_url(self, url: str) -> bool:
        if self.kind == PatternKind.EXACT:
            return url == self.pattern
        if self.kind == PatternKind.PREFIX:
            return url.startswith(self.pattern)
        if self.kind == PatternKind.GLOB:
            return fnmatchcase(url, self.pattern)
        return False


@dataclass(frozen=True)
class URLDecision:
    """The gate's full response: verdict plus the rule that produced it."""

    verdict: RuleVerdict
    rule_id: str = ""
    description: str = ""
    method: str = ""
    url: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == RuleVerdict.ALLOW


class URLRulesEngine:
    """Evaluate URLs against a list of static rules.

    Args:
        rules: Iterable of :class:`URLRule`. Order within a kind tier
            does not change the outcome (deny always wins within a tier);
            exact > prefix > glob across tiers.

    Behavior:
        * Empty rule set returns NO_MATCH for every URL.
        * Within a tier, if any DENY rule matches, the verdict is DENY.
        * Within a tier, if no DENY but at least one ALLOW matches, the
          verdict is ALLOW.
        * If no rule in the tier matches, fall through to the next tier.
        * If no tier matches, return NO_MATCH so the caller can run the
          slower checks.
    """

    name = "tessera.url_rules"

    def __init__(self, rules: Iterable[URLRule] = ()) -> None:
        self._exact: list[URLRule] = []
        self._prefix: list[URLRule] = []
        self._glob: list[URLRule] = []
        for rule in rules:
            self.add(rule)

    def add(self, rule: URLRule) -> None:
        if rule.kind == PatternKind.EXACT:
            self._exact.append(rule)
        elif rule.kind == PatternKind.PREFIX:
            self._prefix.append(rule)
        elif rule.kind == PatternKind.GLOB:
            self._glob.append(rule)

    def evaluate(self, url: str, method: str = "GET") -> URLDecision:
        """Walk the tiers and return the first decisive verdict."""
        for tier in (self._exact, self._prefix, self._glob):
            verdict = self._evaluate_tier(tier, url, method)
            if verdict is not None:
                return verdict
        return URLDecision(verdict=RuleVerdict.NO_MATCH, url=url, method=method)

    def _evaluate_tier(
        self,
        tier: list[URLRule],
        url: str,
        method: str,
    ) -> URLDecision | None:
        """Apply deny-wins-over-allow within a tier.

        Returns:
            A URLDecision when at least one rule in the tier matched
            both the URL and the method. None when no rule in the tier
            matched, signaling fall-through.
        """
        deny_hit: URLRule | None = None
        allow_hit: URLRule | None = None
        for rule in tier:
            if not rule.matches_url(url):
                continue
            if not rule.matches_method(method):
                continue
            if rule.action == RuleAction.DENY:
                deny_hit = rule
                break  # Deny wins; no need to look further in this tier.
            if rule.action == RuleAction.ALLOW and allow_hit is None:
                allow_hit = rule
        chosen = deny_hit or allow_hit
        if chosen is None:
            return None
        verdict = (
            RuleVerdict.DENY if chosen.action == RuleAction.DENY
            else RuleVerdict.ALLOW
        )
        return URLDecision(
            verdict=verdict,
            rule_id=chosen.rule_id,
            description=chosen.description,
            method=method.upper(),
            url=url,
        )

    @property
    def rule_count(self) -> int:
        return len(self._exact) + len(self._prefix) + len(self._glob)


__all__ = [
    "PatternKind",
    "RuleAction",
    "RuleVerdict",
    "URLDecision",
    "URLRule",
    "URLRulesEngine",
]
