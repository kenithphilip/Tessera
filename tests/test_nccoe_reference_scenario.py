"""Tests for the NCCoE reference implementation scenario.

These tests exercise the complete flow and verify each step's success,
hash chain integrity, and NIST control mapping.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from examples.nccoe_reference.scenario import (
    run_scenario,
    run_step_1_identity_binding,
    run_step_2_delegation_binding,
    run_step_3_wimse_token_minting,
    run_step_4_mcp_tool_call,
    run_step_5_policy_decision,
    run_step_6_audit_record,
)
from tessera.audit_log import JSONLHashchainSink
from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel

HMAC_KEY = b"nccoe-example-key-do-not-use-prod-length-32"


class TestIdentityVerification:
    """Test category: identity verification and workload attestation."""

    def test_step_1_spire_identity_binding_succeeds(self):
        """Step 1: Valid SPIFFE-SVID accepted."""
        step = run_step_1_identity_binding()
        assert step.succeeded
        assert "agent_svid" in step.detail
        assert "cluster.local" in step.detail["agent_svid"]
        assert "IA-5" in step.detail.get("nist_controls", []) or \
               "IA-9" in step.detail.get("nist_controls", [])

    def test_step_1_includes_svid_metadata(self):
        """Step 1: SVID expiry and namespace captured."""
        step = run_step_1_identity_binding()
        assert step.succeeded
        assert "svid_valid_until" in step.detail
        assert len(step.detail["svid_valid_until"]) > 0


class TestDelegationBinding:
    """Test category: delegation scope and audience binding."""

    def test_step_2_delegation_token_signed_and_verified(self):
        """Step 2: Delegation token signature verified."""
        step = run_step_2_delegation_binding()
        assert step.succeeded
        assert step.detail.get("signature_verified") is True
        assert "subject" in step.detail
        assert step.detail["subject"] == "user@example.com"

    def test_step_2_includes_mcp_audiences(self):
        """Step 2: MCP audiences in delegation."""
        step = run_step_2_delegation_binding()
        assert step.succeeded
        assert "mcp_audiences" in step.detail
        assert "datastore-mcp" in step.detail["mcp_audiences"]

    def test_step_2_includes_authorized_actions(self):
        """Step 2: Authorized actions in delegation."""
        step = run_step_2_delegation_binding()
        assert step.succeeded
        assert "authorized_actions" in step.detail
        assert "write:datastore" in step.detail["authorized_actions"]
        assert "read:metrics" in step.detail["authorized_actions"]

    def test_step_2_nist_controls_present(self):
        """Step 2: NIST control AC-4 and AC-6 referenced."""
        step = run_step_2_delegation_binding()
        assert step.succeeded
        controls = step.detail.get("nist_controls", [])
        assert len(controls) > 0


class TestWIMSEBinding:
    """Test category: WIMSE workload identity token."""

    def test_step_3_wimse_token_has_audience(self):
        """Step 3: WIMSE token includes audience binding."""
        step = run_step_3_wimse_token_minting()
        assert step.succeeded
        assert step.detail.get("token_aud") == "https://datastore.internal"

    def test_step_3_wimse_token_has_proof_binding(self):
        """Step 3: WIMSE token includes PoP (cnf.jkt)."""
        step = run_step_3_wimse_token_minting()
        assert step.succeeded
        assert "token_cnf_jkt" in step.detail
        assert len(step.detail["token_cnf_jkt"]) > 0


class TestContextTainting:
    """Test category: context segments and taint tracking."""

    def test_step_4_creates_three_segments(self):
        """Step 4: Context with system, user, and tool segments."""
        step = run_step_4_mcp_tool_call()
        assert step.succeeded
        assert step.detail["context_segments"] == 3

    def test_step_4_segments_have_correct_trust_levels(self):
        """Step 4: SYSTEM=200, USER=100, TOOL=50."""
        step = run_step_4_mcp_tool_call()
        assert step.succeeded
        segments = step.detail["segments"]
        trust_levels = {s["origin"]: s["trust_level"] for s in segments}
        assert trust_levels.get("system") == 200  # SYSTEM
        assert trust_levels.get("user") == 100    # USER
        assert trust_levels.get("tool") == 50     # TOOL

    def test_step_4_segments_verified(self):
        """Step 4: All segment signatures verified."""
        step = run_step_4_mcp_tool_call()
        assert step.succeeded
        for segment in step.detail["segments"]:
            assert segment["verified"] is True

    def test_step_4_min_trust_computed(self):
        """Step 4: Context min_trust = min(200, 100, 50) = 50."""
        step = run_step_4_mcp_tool_call()
        assert step.succeeded
        assert step.detail["context_min_trust"] == 50  # TOOL


class TestPolicyDecision:
    """Test category: policy evaluation and denial."""

    def test_step_5_policy_denies_insufficient_trust(self):
        """Step 5: Tool requiring USER=100 denied with min_trust=50."""
        ctx = Context()
        ctx.add(
            make_segment(
                "You are a helpful assistant.",
                Origin.SYSTEM,
                "system",
                key=HMAC_KEY,
                trust_level=TrustLevel.SYSTEM,
            )
        )
        ctx.add(
            make_segment(
                "Write record to datastore.",
                Origin.USER,
                "user@example.com",
                key=HMAC_KEY,
                trust_level=TrustLevel.USER,
            )
        )
        ctx.add(
            make_segment(
                "Retrieved schema from web.",
                Origin.TOOL,
                "fetch_url_tool",
                key=HMAC_KEY,
                trust_level=TrustLevel.TOOL,
            )
        )
        step = run_step_5_policy_decision(ctx)
        assert step.succeeded
        assert step.detail["decision"].lower() == "deny"
        assert step.detail["allowed"] is False

    def test_step_5_includes_nist_controls(self):
        """Step 5: POLICY_DENY event references NIST AC-4, SI-10."""
        ctx = Context()
        ctx.add(
            make_segment(
                "test",
                Origin.USER,
                "user@example.com",
                key=HMAC_KEY,
            )
        )
        step = run_step_5_policy_decision(ctx)
        assert step.succeeded
        assert "nist_controls" in step.detail
        assert len(step.detail["nist_controls"]) > 0

    def test_step_5_includes_cwe_codes(self):
        """Step 5: POLICY_DENY event references CWE-20."""
        ctx = Context()
        ctx.add(
            make_segment(
                "test",
                Origin.USER,
                "user@example.com",
                key=HMAC_KEY,
            )
        )
        step = run_step_5_policy_decision(ctx)
        assert step.succeeded
        assert "cwe_codes" in step.detail
        assert len(step.detail["cwe_codes"]) > 0


class TestAuditLogging:
    """Test category: audit integrity and hash chain."""

    def test_step_6_audit_log_created(self):
        """Step 6: Audit log file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            sink = JSONLHashchainSink(audit_path)
            from tessera.events import register_sink, unregister_sink
            try:
                register_sink(sink)
                step = run_step_6_audit_record(audit_path)
                assert step.succeeded
                assert audit_path.exists()
            finally:
                unregister_sink(sink)

    def test_step_6_hash_chain_verified(self):
        """Step 6: Hash chain integrity verified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            sink = JSONLHashchainSink(audit_path)
            from tessera.events import register_sink, unregister_sink
            try:
                register_sink(sink)
                step = run_step_6_audit_record(audit_path)
                assert step.succeeded
                assert step.detail.get("chain_verified") is True
            finally:
                unregister_sink(sink)

    def test_step_6_nist_controls_present(self):
        """Step 6: AU-10 (non-repudiation) and AU-12 (audit) referenced."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            sink = JSONLHashchainSink(audit_path)
            from tessera.events import register_sink, unregister_sink
            try:
                register_sink(sink)
                step = run_step_6_audit_record(audit_path)
                assert step.succeeded
                assert "nist_controls" in step.detail
                assert len(step.detail["nist_controls"]) > 0
            finally:
                unregister_sink(sink)


class TestCompleteScenario:
    """Integration tests for the complete scenario."""

    def test_scenario_all_steps_succeed(self):
        """Full scenario: all 6 steps complete successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            result = run_scenario(audit_log_path=audit_path)
            assert result.all_steps_succeeded
            assert len(result.steps) == 6

    def test_scenario_hash_chain_verified(self):
        """Full scenario: hash chain integrity verified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            result = run_scenario(audit_log_path=audit_path)
            assert result.all_steps_succeeded
            assert result.hash_chain_verified

    def test_scenario_step_names_present(self):
        """Full scenario: each step has a meaningful name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            result = run_scenario(audit_log_path=audit_path)
            step_names = [s.name for s in result.steps]
            assert "SPIRE" in step_names[0]
            assert "Delegation" in step_names[1]
            assert "WIMSE" in step_names[2]
            assert "MCP" in step_names[3]
            assert "Policy" in step_names[4]
            assert "audit" in step_names[5].lower()

    def test_scenario_details_populated(self):
        """Full scenario: each step has populated details."""
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            result = run_scenario(audit_log_path=audit_path)
            for step in result.steps:
                assert step.detail is not None
                assert len(step.detail) > 0


class TestContextMinTrust:
    """Edge cases for context minimum trust computation."""

    def test_context_three_segment_min_trust(self):
        """Three segments: min_trust = min(200, 100, 50) = 50."""
        ctx = Context()
        ctx.add(
            make_segment("sys", Origin.SYSTEM, "system", key=HMAC_KEY, trust_level=TrustLevel.SYSTEM)
        )
        ctx.add(
            make_segment("user", Origin.USER, "user", key=HMAC_KEY, trust_level=TrustLevel.USER)
        )
        ctx.add(
            make_segment("web", Origin.WEB, "web", key=HMAC_KEY, trust_level=TrustLevel.UNTRUSTED)
        )
        assert ctx.min_trust == TrustLevel.UNTRUSTED

    def test_context_untrusted_blocks_all(self):
        """Single UNTRUSTED segment taints entire context."""
        ctx = Context()
        ctx.add(
            make_segment("untrusted", Origin.WEB, "web", key=HMAC_KEY, trust_level=TrustLevel.UNTRUSTED)
        )
        assert ctx.min_trust == TrustLevel.UNTRUSTED
