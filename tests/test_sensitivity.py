"""Tests for tessera.sensitivity: classifier, HWM, outbound policy."""

from __future__ import annotations

import pytest

from tessera.sensitivity import (
    Classification,
    ClassificationRule,
    HighWaterMark,
    InMemoryHWMStore,
    OutboundDecision,
    OutboundPolicy,
    SensitivityClassifier,
    SensitivityLabel,
    ToolClassification,
)


class TestSensitivityLabel:
    def test_lattice_ordering(self) -> None:
        assert SensitivityLabel.PUBLIC < SensitivityLabel.INTERNAL
        assert SensitivityLabel.INTERNAL < SensitivityLabel.CONFIDENTIAL
        assert SensitivityLabel.CONFIDENTIAL < SensitivityLabel.RESTRICTED

    def test_from_str(self) -> None:
        assert SensitivityLabel.from_str("PUBLIC") is SensitivityLabel.PUBLIC
        assert SensitivityLabel.from_str(" confidential ") is SensitivityLabel.CONFIDENTIAL

    def test_from_str_unknown_raises(self) -> None:
        with pytest.raises(ValueError):
            SensitivityLabel.from_str("SECRET")


class TestClassifier:
    def test_public_default(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("hello world").label is SensitivityLabel.PUBLIC

    def test_secret_confidential(self) -> None:
        c = SensitivityClassifier()
        r = c.classify("Our key is AKIAIOSFODNN7EXAMPLE, rotate it")
        assert r.label is SensitivityLabel.CONFIDENTIAL
        assert "secret.aws_access_key" in r.matched_rule_ids

    def test_pem_key_confidential(self) -> None:
        c = SensitivityClassifier()
        blob = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        assert c.classify(blob).label is SensitivityLabel.CONFIDENTIAL

    def test_ssn_restricted(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("SSN: 123-45-6789").label is SensitivityLabel.RESTRICTED

    def test_credit_card_restricted(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("card 4111 1111 1111 1111").label is SensitivityLabel.RESTRICTED

    def test_github_token(self) -> None:
        c = SensitivityClassifier()
        text = "token = ghp_abcdefghijABCDEFGHIJabcdefghijABCDEF"
        assert c.classify(text).label is SensitivityLabel.CONFIDENTIAL

    def test_slack_token(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("slack xoxb-1234567890-abcdefghij").label is SensitivityLabel.CONFIDENTIAL

    def test_internal_marker(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("INTERNAL ONLY: Q4 plans").label is SensitivityLabel.INTERNAL

    def test_confidential_marker(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("CONFIDENTIAL: details").label is SensitivityLabel.CONFIDENTIAL

    def test_highest_wins(self) -> None:
        c = SensitivityClassifier()
        text = "AKIAIOSFODNN7EXAMPLE and SSN 123-45-6789"
        r = c.classify(text)
        assert r.label is SensitivityLabel.RESTRICTED
        assert "secret.aws_access_key" in r.matched_rule_ids
        assert "pii.ssn" in r.matched_rule_ids

    def test_register_custom_rule(self) -> None:
        import re
        c = SensitivityClassifier()
        c.register(ClassificationRule(
            id="custom.project_alpha",
            label=SensitivityLabel.CONFIDENTIAL,
            pattern=re.compile(r"project-alpha-\d+"),
            description="internal project codename",
        ))
        r = c.classify("see ticket project-alpha-123")
        assert r.label is SensitivityLabel.CONFIDENTIAL

    def test_rules_without_defaults(self) -> None:
        c = SensitivityClassifier(include_defaults=False)
        assert c.classify("SSN: 123-45-6789").label is SensitivityLabel.PUBLIC

    def test_coerce_bytes(self) -> None:
        c = SensitivityClassifier()
        assert c.classify(b"SSN: 123-45-6789").label is SensitivityLabel.RESTRICTED

    def test_coerce_dict(self) -> None:
        c = SensitivityClassifier()
        assert c.classify({"token": "AKIAIOSFODNN7EXAMPLE"}).label is SensitivityLabel.CONFIDENTIAL

    def test_empty_content_public(self) -> None:
        c = SensitivityClassifier()
        assert c.classify("").label is SensitivityLabel.PUBLIC
        assert c.classify(None).label is SensitivityLabel.PUBLIC


class TestHighWaterMark:
    def test_monotonic(self) -> None:
        hwm = HighWaterMark()
        assert hwm.get("t1") is SensitivityLabel.PUBLIC
        hwm.observe("t1", SensitivityLabel.INTERNAL)
        hwm.observe("t1", SensitivityLabel.CONFIDENTIAL)
        hwm.observe("t1", SensitivityLabel.INTERNAL)  # does not lower
        assert hwm.get("t1") is SensitivityLabel.CONFIDENTIAL

    def test_observe_returns_current(self) -> None:
        hwm = HighWaterMark()
        result = hwm.observe("t1", SensitivityLabel.INTERNAL)
        assert result is SensitivityLabel.INTERNAL
        result = hwm.observe("t1", SensitivityLabel.PUBLIC)
        assert result is SensitivityLabel.INTERNAL  # no lowering

    def test_reset(self) -> None:
        hwm = HighWaterMark()
        hwm.observe("t1", SensitivityLabel.RESTRICTED)
        hwm.reset("t1")
        assert hwm.get("t1") is SensitivityLabel.PUBLIC

    def test_isolated_per_trajectory(self) -> None:
        hwm = HighWaterMark()
        hwm.observe("a", SensitivityLabel.CONFIDENTIAL)
        assert hwm.get("b") is SensitivityLabel.PUBLIC

    def test_custom_store(self) -> None:
        store = InMemoryHWMStore()
        hwm = HighWaterMark(store=store)
        hwm.observe("t1", SensitivityLabel.INTERNAL)
        assert store.get("t1") is SensitivityLabel.INTERNAL


class TestOutboundPolicy:
    def test_inbound_always_ok(self) -> None:
        p = OutboundPolicy(
            registry={"fs.read": ToolClassification(outbound=False)},
        )
        d = p.check("fs.read", SensitivityLabel.RESTRICTED)
        assert d.allowed
        assert d.hwm is SensitivityLabel.RESTRICTED

    def test_outbound_within_envelope_ok(self) -> None:
        p = OutboundPolicy(
            registry={
                "http.post": ToolClassification(
                    outbound=True, max_sensitivity=SensitivityLabel.INTERNAL,
                ),
            },
        )
        assert p.check("http.post", SensitivityLabel.INTERNAL).allowed
        assert p.check("http.post", SensitivityLabel.PUBLIC).allowed

    def test_outbound_blocks_above_envelope(self) -> None:
        p = OutboundPolicy(
            registry={
                "http.post": ToolClassification(
                    outbound=True, max_sensitivity=SensitivityLabel.INTERNAL,
                ),
            },
        )
        d = p.check("http.post", SensitivityLabel.CONFIDENTIAL)
        assert not d.allowed
        assert "CONFIDENTIAL" in d.reason
        assert "INTERNAL" in d.reason

    def test_unknown_tool_default_inbound(self) -> None:
        p = OutboundPolicy()
        assert p.check("unknown.tool", SensitivityLabel.CONFIDENTIAL).allowed

    def test_unknown_tool_default_outbound(self) -> None:
        p = OutboundPolicy(
            default_outbound=True,
            default_max_sensitivity=SensitivityLabel.PUBLIC,
        )
        assert p.check("unknown.tool", SensitivityLabel.PUBLIC).allowed
        assert not p.check("unknown.tool", SensitivityLabel.INTERNAL).allowed

    def test_register_tool(self) -> None:
        p = OutboundPolicy()
        p.register(
            "email.send",
            ToolClassification(outbound=True, max_sensitivity=SensitivityLabel.PUBLIC),
        )
        assert not p.check("email.send", SensitivityLabel.INTERNAL).allowed

    def test_decision_carries_hwm_and_tool_max(self) -> None:
        p = OutboundPolicy(
            registry={
                "http.post": ToolClassification(
                    outbound=True, max_sensitivity=SensitivityLabel.INTERNAL,
                ),
            },
        )
        d = p.check("http.post", SensitivityLabel.CONFIDENTIAL)
        assert d.hwm is SensitivityLabel.CONFIDENTIAL
        assert d.tool_max is SensitivityLabel.INTERNAL
        assert d.source == "tessera.sensitivity"
