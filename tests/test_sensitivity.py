"""Tests for tessera.sensitivity: Bell-LaPadula IFC primitive."""

from __future__ import annotations

import pytest

from tessera.sensitivity import (
    IFCDecision,
    SensitivityClassification,
    SensitivityContext,
    SensitivityLabel,
    check_outbound,
    classify,
    is_outbound_tool,
)


class TestClassify:
    def test_empty_is_public(self) -> None:
        r = classify("")
        assert r.label == SensitivityLabel.PUBLIC

    def test_plain_text_is_public(self) -> None:
        r = classify("The weather in Paris is nice.")
        assert r.label == SensitivityLabel.PUBLIC
        assert r.matched_patterns == ()

    def test_ssn_is_highly_confidential(self) -> None:
        r = classify("Employee SSN: 123-45-6789")
        assert r.label == SensitivityLabel.HIGHLY_CONFIDENTIAL
        assert "ssn" in r.matched_patterns

    def test_aws_key_is_highly_confidential(self) -> None:
        r = classify("AWS key: AKIAIOSFODNN7EXAMPLE")
        assert r.label == SensitivityLabel.HIGHLY_CONFIDENTIAL
        assert "aws_access_key" in r.matched_patterns

    def test_private_key_is_highly_confidential(self) -> None:
        r = classify("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...")
        assert r.label == SensitivityLabel.HIGHLY_CONFIDENTIAL

    def test_credit_card_is_highly_confidential(self) -> None:
        r = classify("Card on file: 4111 1111 1111 1111")
        assert r.label == SensitivityLabel.HIGHLY_CONFIDENTIAL

    def test_password_field_is_confidential(self) -> None:
        r = classify("username: admin\npassword: hunter2")
        assert r.label == SensitivityLabel.CONFIDENTIAL

    def test_confidential_marker(self) -> None:
        r = classify("CONFIDENTIAL: Q4 roadmap discussion")
        assert r.label == SensitivityLabel.CONFIDENTIAL

    def test_internal_marker(self) -> None:
        r = classify("INTERNAL ONLY: team restructuring plans")
        assert r.label == SensitivityLabel.INTERNAL

    def test_financial_term_is_internal(self) -> None:
        r = classify("Our ARR grew 40% this quarter")
        assert r.label == SensitivityLabel.INTERNAL

    def test_highest_label_wins(self) -> None:
        # Text has both a CONFIDENTIAL marker and a HIGHLY_CONFIDENTIAL SSN
        r = classify("CONFIDENTIAL: John's SSN is 123-45-6789")
        assert r.label == SensitivityLabel.HIGHLY_CONFIDENTIAL


class TestSensitivityContext:
    def test_starts_public(self) -> None:
        ctx = SensitivityContext()
        assert ctx.max_sensitivity == SensitivityLabel.PUBLIC

    def test_observe_raises_label(self) -> None:
        ctx = SensitivityContext()
        ctx.observe("Plain public text")
        assert ctx.max_sensitivity == SensitivityLabel.PUBLIC
        ctx.observe("SSN: 987-65-4321")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL

    def test_high_water_mark_never_lowers(self) -> None:
        ctx = SensitivityContext()
        ctx.observe("SSN: 123-45-6789")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL
        # Adding public content after cannot lower the watermark
        ctx.observe("The weather is nice.")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL

    def test_reset_clears(self) -> None:
        ctx = SensitivityContext()
        ctx.observe("AKIAIOSFODNN7EXAMPLE")
        assert ctx.max_sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL
        ctx.reset()
        assert ctx.max_sensitivity == SensitivityLabel.PUBLIC
        assert ctx.classifications == []

    def test_custom_classifier(self) -> None:
        """Users can plug in their own classifier (e.g., LLM-based)."""
        def always_internal(text: str) -> SensitivityClassification:
            return SensitivityClassification(
                label=SensitivityLabel.INTERNAL,
                matched_patterns=("custom",),
                score=0.8,
            )
        ctx = SensitivityContext(classifier=always_internal)
        ctx.observe("anything")
        assert ctx.max_sensitivity == SensitivityLabel.INTERNAL


class TestIsOutboundTool:
    def test_send_email_is_outbound(self) -> None:
        assert is_outbound_tool("send_email")

    def test_web_fetch_is_outbound(self) -> None:
        assert is_outbound_tool("web_fetch")
        assert is_outbound_tool("fetch_url")

    def test_post_request_is_outbound(self) -> None:
        assert is_outbound_tool("post_webhook")
        assert is_outbound_tool("http_post")

    def test_read_file_is_not_outbound(self) -> None:
        assert not is_outbound_tool("read_file")
        assert not is_outbound_tool("list_directory")

    def test_search_is_not_outbound(self) -> None:
        # search_hotels is a read-only internal tool, not a network egress
        assert not is_outbound_tool("search_hotels")


class TestCheckOutbound:
    def test_non_outbound_always_allowed(self) -> None:
        d = check_outbound("read_file", SensitivityLabel.HIGHLY_CONFIDENTIAL)
        assert d.allowed
        assert "not an outbound" in d.reason

    def test_public_outbound_allowed(self) -> None:
        d = check_outbound("send_email", SensitivityLabel.PUBLIC)
        assert d.allowed

    def test_internal_outbound_allowed(self) -> None:
        d = check_outbound("send_email", SensitivityLabel.INTERNAL)
        assert d.allowed

    def test_confidential_outbound_allowed_without_injection(self) -> None:
        d = check_outbound("send_email", SensitivityLabel.CONFIDENTIAL)
        assert d.allowed

    def test_confidential_outbound_blocked_with_injection(self) -> None:
        d = check_outbound(
            "send_email",
            SensitivityLabel.CONFIDENTIAL,
            has_injection=True,
        )
        assert not d.allowed
        assert "injection" in d.reason.lower()

    def test_highly_confidential_blocks_all_outbound(self) -> None:
        d = check_outbound("send_email", SensitivityLabel.HIGHLY_CONFIDENTIAL)
        assert not d.allowed
        d = check_outbound("web_fetch", SensitivityLabel.HIGHLY_CONFIDENTIAL)
        assert not d.allowed
        d = check_outbound("post_webhook", SensitivityLabel.HIGHLY_CONFIDENTIAL)
        assert not d.allowed

    def test_highly_confidential_with_injection_still_blocked(self) -> None:
        # No path through: HC + injection is even more obviously blocked
        d = check_outbound(
            "send_email",
            SensitivityLabel.HIGHLY_CONFIDENTIAL,
            has_injection=True,
        )
        assert not d.allowed


class TestFullFlowIntegration:
    """End-to-end: classify -> track -> gate outbound."""

    def test_ssn_blocks_subsequent_email(self) -> None:
        ctx = SensitivityContext()
        # Agent reads a file containing an SSN
        ctx.observe("Employee record: SSN 123-45-6789")
        # Agent then tries to send an email
        decision = check_outbound("send_email", ctx.max_sensitivity)
        assert not decision.allowed
        assert decision.sensitivity == SensitivityLabel.HIGHLY_CONFIDENTIAL

    def test_public_conversation_no_restrictions(self) -> None:
        ctx = SensitivityContext()
        ctx.observe("The weather in Paris is nice")
        ctx.observe("Hotels with good reviews")
        decision = check_outbound("send_email", ctx.max_sensitivity)
        assert decision.allowed

    def test_internal_data_allows_outbound(self) -> None:
        """INTERNAL is below the CONFIDENTIAL threshold for outbound gating."""
        ctx = SensitivityContext()
        ctx.observe("INTERNAL: Q4 planning meeting notes")
        decision = check_outbound("send_email", ctx.max_sensitivity)
        assert decision.allowed
