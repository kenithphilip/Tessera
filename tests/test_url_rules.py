"""Tests for tessera.url_rules: deterministic URL allowlist/denylist gate."""

from __future__ import annotations

import pytest

from tessera.url_rules import (
    PatternKind,
    RuleAction,
    RuleVerdict,
    URLRule,
    URLRulesEngine,
)


def _exact(rule_id, pattern, action=RuleAction.ALLOW, methods=None):
    return URLRule(
        rule_id=rule_id, pattern=pattern,
        kind=PatternKind.EXACT, action=action, methods=methods,
    )


def _prefix(rule_id, pattern, action=RuleAction.ALLOW, methods=None):
    return URLRule(
        rule_id=rule_id, pattern=pattern,
        kind=PatternKind.PREFIX, action=action, methods=methods,
    )


def _glob(rule_id, pattern, action=RuleAction.ALLOW, methods=None):
    return URLRule(
        rule_id=rule_id, pattern=pattern,
        kind=PatternKind.GLOB, action=action, methods=methods,
    )


class TestEmptyEngine:
    def test_no_match_with_no_rules(self) -> None:
        engine = URLRulesEngine()
        d = engine.evaluate("https://example.com/")
        assert d.verdict == RuleVerdict.NO_MATCH
        assert d.rule_id == ""


class TestExactTier:
    def test_exact_allow_hit(self) -> None:
        engine = URLRulesEngine([
            _exact("ok.api", "https://api.example.com/v1/health"),
        ])
        d = engine.evaluate("https://api.example.com/v1/health")
        assert d.verdict == RuleVerdict.ALLOW
        assert d.rule_id == "ok.api"

    def test_exact_no_partial_match(self) -> None:
        engine = URLRulesEngine([
            _exact("only.this", "https://api.example.com/v1/health"),
        ])
        d = engine.evaluate("https://api.example.com/v1/health/extra")
        assert d.verdict == RuleVerdict.NO_MATCH

    def test_exact_deny_wins_in_tier(self) -> None:
        engine = URLRulesEngine([
            _exact("good", "https://api.example.com/v1", action=RuleAction.ALLOW),
            _exact("bad", "https://api.example.com/v1", action=RuleAction.DENY),
        ])
        d = engine.evaluate("https://api.example.com/v1")
        assert d.verdict == RuleVerdict.DENY
        assert d.rule_id == "bad"


class TestPrefixTier:
    def test_prefix_match(self) -> None:
        engine = URLRulesEngine([
            _prefix("github", "https://api.github.com/"),
        ])
        d = engine.evaluate("https://api.github.com/repos/foo/bar")
        assert d.verdict == RuleVerdict.ALLOW
        assert d.rule_id == "github"

    def test_prefix_deny_wins_in_tier(self) -> None:
        engine = URLRulesEngine([
            _prefix("github.all", "https://api.github.com/"),
            _prefix("github.admin", "https://api.github.com/admin/",
                    action=RuleAction.DENY),
        ])
        d = engine.evaluate("https://api.github.com/admin/users")
        assert d.verdict == RuleVerdict.DENY
        assert d.rule_id == "github.admin"


class TestGlobTier:
    def test_glob_wildcard(self) -> None:
        engine = URLRulesEngine([
            _glob("any.cdn", "https://*.cdn.example.com/*"),
        ])
        assert engine.evaluate(
            "https://images.cdn.example.com/banner.png",
        ).verdict == RuleVerdict.ALLOW
        # Wildcard does not match cross-domain.
        assert engine.evaluate(
            "https://example.com/banner.png",
        ).verdict == RuleVerdict.NO_MATCH


class TestTierPrecedence:
    def test_exact_beats_prefix_with_no_decisive_match(self) -> None:
        # Tier walk is exact, then prefix, then glob. An exact rule that
        # matches takes the tier; the prefix rule never gets consulted.
        engine = URLRulesEngine([
            _exact("specific", "https://api.example.com/v1/health",
                   action=RuleAction.ALLOW),
            _prefix("broad.deny", "https://api.example.com/",
                    action=RuleAction.DENY),
        ])
        d = engine.evaluate("https://api.example.com/v1/health")
        assert d.verdict == RuleVerdict.ALLOW
        assert d.rule_id == "specific"

    def test_prefix_falls_through_to_glob(self) -> None:
        # Prefix tier has rules but none match; should fall through to
        # the glob tier where the rule matches.
        engine = URLRulesEngine([
            _prefix("other", "https://other.com/"),
            _glob("cdn.match", "https://*.cdn.example.com/*",
                  action=RuleAction.ALLOW),
        ])
        d = engine.evaluate("https://images.cdn.example.com/x")
        assert d.verdict == RuleVerdict.ALLOW
        assert d.rule_id == "cdn.match"


class TestMethodFilter:
    def test_method_filter_only_allows_listed(self) -> None:
        engine = URLRulesEngine([
            _prefix("github.read", "https://api.github.com/",
                    methods=("GET",)),
        ])
        assert engine.evaluate(
            "https://api.github.com/x", method="GET",
        ).verdict == RuleVerdict.ALLOW
        # POST does not match -> rule is skipped -> NO_MATCH.
        assert engine.evaluate(
            "https://api.github.com/x", method="POST",
        ).verdict == RuleVerdict.NO_MATCH

    def test_method_case_insensitive(self) -> None:
        engine = URLRulesEngine([
            _prefix("ok", "https://x/", methods=("GET",)),
        ])
        assert engine.evaluate(
            "https://x/y", method="get",
        ).verdict == RuleVerdict.ALLOW


class TestDecisionShape:
    def test_decision_carries_metadata(self) -> None:
        engine = URLRulesEngine([
            URLRule(
                rule_id="github.deny",
                pattern="https://api.github.com/admin/",
                kind=PatternKind.PREFIX,
                action=RuleAction.DENY,
                description="block GitHub admin endpoints",
            ),
        ])
        d = engine.evaluate(
            "https://api.github.com/admin/users", method="DELETE",
        )
        assert d.verdict == RuleVerdict.DENY
        assert d.rule_id == "github.deny"
        assert d.description == "block GitHub admin endpoints"
        assert d.method == "DELETE"
        assert d.url == "https://api.github.com/admin/users"
        assert d.allowed is False


class TestEngineProperties:
    def test_rule_count(self) -> None:
        engine = URLRulesEngine([
            _exact("a", "https://x/a"),
            _prefix("b", "https://y/"),
            _glob("c", "https://*/c"),
            _exact("d", "https://x/d"),
        ])
        assert engine.rule_count == 4

    def test_add_after_construction(self) -> None:
        engine = URLRulesEngine([_prefix("a", "https://a/")])
        engine.add(_exact("b", "https://b/exact"))
        assert engine.rule_count == 2
        assert engine.evaluate(
            "https://b/exact",
        ).rule_id == "b"
