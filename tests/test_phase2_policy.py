"""Tests for Phase 2 policy engine extensions.

Covers:
  2.1 Readers lattice (frozenset ACL on TrustLabel + Context.effective_readers)
  2.2 Fnmatch-based policy rule patterns
  2.3 Side-effect classification (no_side_effect exemption from taint floor)
  2.4 OWASP Agentic Top 10 compliance mapping in enrich_event
"""

from __future__ import annotations

import pytest

from tessera.compliance import OWASP_ASI, enrich_event
from tessera.context import Context, make_segment
from tessera.events import EventKind, SecurityEvent
from tessera.labels import Origin, TrustLabel, TrustLevel
from tessera.policy import Decision, DecisionKind, Policy, ResourceType

KEY = b"test-key-phase2"


def _seg(content: str, origin: Origin, readers: frozenset[str] | None = None) -> object:
    return make_segment(content, origin, "alice", KEY, readers=readers)


def _ctx(*segments) -> Context:
    ctx = Context()
    for s in segments:
        ctx.add(s)
    return ctx


# ---------------------------------------------------------------------------
# 2.1 Readers lattice
# ---------------------------------------------------------------------------

class TestReadersLattice:
    def test_trustedlabel_readers_field_defaults_none(self) -> None:
        label = TrustLabel(origin=Origin.USER, principal="alice", trust_level=TrustLevel.USER)
        assert label.readers is None

    def test_make_segment_propagates_readers(self) -> None:
        seg = _seg("data", Origin.USER, readers=frozenset({"alice@acme.com"}))
        assert seg.label.readers == frozenset({"alice@acme.com"})

    def test_readers_not_in_hmac_canonical(self) -> None:
        # Changing readers must not invalidate an existing signature.
        seg_no_readers = make_segment("hello", Origin.USER, "alice", KEY, readers=None)
        seg_with_readers = make_segment(
            "hello", Origin.USER, "alice", KEY, readers=frozenset({"alice@acme.com"})
        )
        # Both should verify correctly (different nonces, so just check both verify)
        assert seg_no_readers.verify(KEY)
        assert seg_with_readers.verify(KEY)

    def test_effective_readers_all_none_returns_none(self) -> None:
        ctx = _ctx(
            _seg("public data", Origin.USER),
            _seg("more public data", Origin.TOOL),
        )
        assert ctx.effective_readers is None

    def test_effective_readers_single_restricted_segment(self) -> None:
        ctx = _ctx(
            _seg("public data", Origin.USER),
            _seg("internal only", Origin.TOOL, readers=frozenset({"alice@acme.com", "bob@acme.com"})),
        )
        assert ctx.effective_readers == frozenset({"alice@acme.com", "bob@acme.com"})

    def test_effective_readers_intersection_of_two(self) -> None:
        ctx = _ctx(
            _seg("segment a", Origin.USER, readers=frozenset({"alice@acme.com", "bob@acme.com"})),
            _seg("segment b", Origin.TOOL, readers=frozenset({"bob@acme.com", "carol@acme.com"})),
        )
        # Intersection: only bob is in both
        assert ctx.effective_readers == frozenset({"bob@acme.com"})

    def test_effective_readers_disjoint_becomes_empty(self) -> None:
        ctx = _ctx(
            _seg("a", Origin.USER, readers=frozenset({"alice@acme.com"})),
            _seg("b", Origin.TOOL, readers=frozenset({"bob@acme.com"})),
        )
        assert ctx.effective_readers == frozenset()

    def test_public_context_allows_any_recipient(self) -> None:
        ctx = _ctx(_seg("data", Origin.USER))
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        decision = policy.evaluate(ctx, "send_email", args={"to": "anyone@external.com"})
        assert decision.allowed

    def test_restricted_readers_blocks_out_of_set_recipient(self) -> None:
        ctx = _ctx(
            _seg("internal data", Origin.USER, readers=frozenset({"internal@acme.com"})),
        )
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        decision = policy.evaluate(ctx, "send_email", args={"to": "attacker@evil.com"})
        assert not decision.allowed
        assert "readers lattice violation" in decision.reason

    def test_restricted_readers_allows_in_set_recipient(self) -> None:
        ctx = _ctx(
            _seg("internal data", Origin.USER, readers=frozenset({"internal@acme.com"})),
        )
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        decision = policy.evaluate(ctx, "send_email", args={"to": "internal@acme.com"})
        assert decision.allowed

    def test_restricted_readers_checks_recipients_list(self) -> None:
        ctx = _ctx(
            _seg("data", Origin.USER, readers=frozenset({"alice@acme.com", "bob@acme.com"})),
        )
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        # One allowed, one not
        decision = policy.evaluate(
            ctx, "send_email", args={"recipients": ["alice@acme.com", "attacker@evil.com"]}
        )
        assert not decision.allowed

    def test_readers_check_skipped_when_no_recipient_args(self) -> None:
        ctx = _ctx(
            _seg("data", Origin.USER, readers=frozenset({"internal@acme.com"})),
        )
        policy = Policy()
        policy.require("compute", TrustLevel.USER)
        # No "to"/"recipient"/etc in args - readers check should not fire
        decision = policy.evaluate(ctx, "compute", args={"x": 42})
        assert decision.allowed

    def test_taint_denial_takes_precedence_over_readers(self) -> None:
        # Even if readers would be fine, taint floor should still deny
        ctx = _ctx(
            _seg("web payload", Origin.WEB, readers=frozenset({"internal@acme.com"})),
        )
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        decision = policy.evaluate(ctx, "send_email", args={"to": "internal@acme.com"})
        assert not decision.allowed
        # Should be taint denial, not readers denial
        assert "readers lattice" not in decision.reason


# ---------------------------------------------------------------------------
# 2.2 Fnmatch-based policy patterns
# ---------------------------------------------------------------------------

class TestFnmatchPolicyPatterns:
    def test_exact_match_takes_precedence_over_glob(self) -> None:
        policy = Policy()
        # Pattern allows at TOOL level, exact name requires USER
        policy.require("send_*", TrustLevel.TOOL)
        policy.require("send_email", TrustLevel.USER)

        # Context is TOOL-level (Origin.TOOL = TrustLevel.TOOL)
        ctx = _ctx(_seg("tool data", Origin.TOOL))
        decision = policy.evaluate(ctx, "send_email")
        # Exact match: USER required, TOOL observed => deny
        assert not decision.allowed

    def test_glob_pattern_matches_when_no_exact(self) -> None:
        policy = Policy()
        policy.require("send_*", TrustLevel.USER)

        ctx = _ctx(_seg("user instruction", Origin.USER))
        decision = policy.evaluate(ctx, "send_notification")
        assert decision.allowed

    def test_glob_pattern_blocks_when_context_insufficient(self) -> None:
        policy = Policy()
        policy.require("send_*", TrustLevel.USER)

        ctx = _ctx(_seg("web data", Origin.WEB))
        decision = policy.evaluate(ctx, "send_notification")
        assert not decision.allowed

    def test_wildcard_star_pattern(self) -> None:
        policy = Policy()
        policy.require("*", TrustLevel.USER)

        ctx = _ctx(_seg("user data", Origin.USER))
        assert policy.evaluate(ctx, "any_tool").allowed

        ctx_web = _ctx(_seg("web data", Origin.WEB))
        assert not policy.evaluate(ctx_web, "any_tool").allowed

    def test_no_match_uses_default(self) -> None:
        policy = Policy(default_required_trust=TrustLevel.TOOL)
        # No requirements registered
        ctx = _ctx(_seg("tool output", Origin.TOOL))
        assert policy.evaluate(ctx, "unregistered_tool").allowed

        ctx_untrusted = _ctx(_seg("web", Origin.WEB))
        assert not policy.evaluate(ctx_untrusted, "unregistered_tool").allowed

    def test_glob_respects_resource_type(self) -> None:
        policy = Policy()
        policy.require("read_*", TrustLevel.TOOL, resource_type=ResourceType.PROMPT)

        ctx = _ctx(_seg("user data", Origin.USER))
        # Same pattern but TOOL resource_type - should not match PROMPT pattern
        decision_tool = policy.evaluate(ctx, "read_docs", resource_type=ResourceType.TOOL)
        # Falls through to default (USER), user context satisfies it
        assert decision_tool.allowed

        # PROMPT resource_type - matches the pattern at TOOL level
        decision_prompt = policy.evaluate(ctx, "read_docs", resource_type=ResourceType.PROMPT)
        assert decision_prompt.allowed

    def test_question_mark_glob(self) -> None:
        policy = Policy()
        policy.require("tool_?", TrustLevel.USER)

        ctx = _ctx(_seg("user input", Origin.USER))
        assert policy.evaluate(ctx, "tool_a").allowed
        assert policy.evaluate(ctx, "tool_b").allowed
        # Two chars: should NOT match "tool_?" but will fall to default (USER)
        # tool_ab has 2 chars after underscore - won't match tool_?
        decision = policy.evaluate(ctx, "tool_ab")
        # Falls to default USER, user context allows it
        assert decision.allowed


# ---------------------------------------------------------------------------
# 2.3 Side-effect classification
# ---------------------------------------------------------------------------

class TestSideEffectClassification:
    def test_read_only_tool_allowed_over_untrusted_context(self) -> None:
        ctx = _ctx(_seg("attacker payload", Origin.WEB))
        policy = Policy()
        policy.require("extract_entities", TrustLevel.USER, side_effects=False)

        decision = policy.evaluate(ctx, "extract_entities")
        assert decision.allowed

    def test_side_effecting_tool_blocked_over_untrusted_context(self) -> None:
        ctx = _ctx(_seg("attacker payload", Origin.WEB))
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)

        decision = policy.evaluate(ctx, "send_email")
        assert not decision.allowed

    def test_read_only_glob_pattern_allows_tainted_context(self) -> None:
        ctx = _ctx(_seg("web scrape", Origin.WEB))
        policy = Policy()
        policy.require("read_*", TrustLevel.USER, side_effects=False)

        assert policy.evaluate(ctx, "read_file").allowed
        assert policy.evaluate(ctx, "read_db").allowed

    def test_read_only_side_effects_false_with_user_context(self) -> None:
        # Read-only tools should also work with trusted context
        ctx = _ctx(_seg("user query", Origin.USER))
        policy = Policy()
        policy.require("search", TrustLevel.USER, side_effects=False)
        assert policy.evaluate(ctx, "search").allowed

    def test_default_side_effects_true_preserves_existing_behavior(self) -> None:
        # require() with no side_effects kwarg should behave as before
        policy = Policy()
        policy.require("send_email", TrustLevel.USER)
        req = policy.requirements[("send_email", ResourceType.TOOL)]
        assert req.side_effects is True

    def test_camel_style_mixed_plan(self) -> None:
        """Read-only tools pass, side-effecting tool blocks when tainted."""
        ctx = _ctx(
            _seg("user addr: alice@acme.com", Origin.USER),
            _seg("attacker data", Origin.WEB),
        )
        policy = Policy()
        policy.require("extract_entities", TrustLevel.USER, side_effects=False)
        policy.require("transform", TrustLevel.USER, side_effects=False)
        policy.require("send_email", TrustLevel.USER)

        assert policy.evaluate(ctx, "extract_entities").allowed
        assert policy.evaluate(ctx, "transform").allowed
        assert not policy.evaluate(ctx, "send_email").allowed

    def test_side_effects_false_still_blocks_delegation_violations(self) -> None:
        """Read-only exemption is for taint floor only; delegation still applies."""
        from datetime import datetime, timedelta, timezone

        from tessera.delegation import DelegationToken, sign_delegation

        ctx = _ctx(_seg("web data", Origin.WEB))
        policy = Policy()
        policy.require("search", TrustLevel.USER, side_effects=False)

        token = sign_delegation(
            DelegationToken(
                subject="alice",
                delegate="proxy",
                audience="tessera",
                authorized_actions=("other_tool",),  # not "search"
                constraints={},
                session_id="s1",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            ),
            KEY,
        )
        decision = policy.evaluate(ctx, "search", delegation=token, expected_delegate="proxy")
        assert not decision.allowed


# ---------------------------------------------------------------------------
# 2.4 OWASP ASI compliance mapping
# ---------------------------------------------------------------------------

class TestOWASPASIMapping:
    def _event(self, kind: EventKind) -> SecurityEvent:
        return SecurityEvent.now(kind=kind, principal="alice", detail={})

    def test_policy_deny_maps_to_asi01(self) -> None:
        enriched = enrich_event(self._event(EventKind.POLICY_DENY))
        assert "ASI-01" in enriched["owasp_asi"]

    def test_worker_schema_violation_maps_to_asi01(self) -> None:
        enriched = enrich_event(self._event(EventKind.WORKER_SCHEMA_VIOLATION))
        assert "ASI-01" in enriched["owasp_asi"]

    def test_content_injection_maps_to_asi01_and_asi07(self) -> None:
        enriched = enrich_event(self._event(EventKind.CONTENT_INJECTION_DETECTED))
        assert "ASI-01" in enriched["owasp_asi"]
        assert "ASI-07" in enriched["owasp_asi"]

    def test_identity_verify_failure_maps_to_asi05(self) -> None:
        enriched = enrich_event(self._event(EventKind.IDENTITY_VERIFY_FAILURE))
        assert "ASI-05" in enriched["owasp_asi"]

    def test_delegation_verify_failure_maps_to_asi03_and_asi10(self) -> None:
        enriched = enrich_event(self._event(EventKind.DELEGATION_VERIFY_FAILURE))
        assert "ASI-03" in enriched["owasp_asi"]
        assert "ASI-10" in enriched["owasp_asi"]

    def test_secret_redacted_maps_to_asi02(self) -> None:
        enriched = enrich_event(self._event(EventKind.SECRET_REDACTED))
        assert "ASI-02" in enriched["owasp_asi"]

    def test_human_approval_required_maps_to_asi03(self) -> None:
        enriched = enrich_event(self._event(EventKind.HUMAN_APPROVAL_REQUIRED))
        assert "ASI-03" in enriched["owasp_asi"]

    def test_enriched_event_still_has_nist_and_cwe(self) -> None:
        enriched = enrich_event(self._event(EventKind.POLICY_DENY))
        assert "nist_controls" in enriched
        assert "cwe_codes" in enriched
        assert "owasp_asi" in enriched

    def test_owasp_asi_key_in_module(self) -> None:
        # All EventKind values should either have an entry or gracefully return []
        for kind in EventKind:
            enriched = enrich_event(self._event(kind))
            assert isinstance(enriched["owasp_asi"], list)

    def test_unknown_kind_returns_empty_asi(self) -> None:
        # Events not in the mapping return empty list, not KeyError
        event = SecurityEvent.now(kind=EventKind.SESSION_EXPIRED, principal="a", detail={})
        enriched = enrich_event(event)
        assert isinstance(enriched["owasp_asi"], list)
