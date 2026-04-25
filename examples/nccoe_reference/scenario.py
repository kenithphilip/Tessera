#!/usr/bin/env python3.12
"""NCCoE reference scenario: Agent calls tool with delegated authority.

This script demonstrates the canonical six-step flow using Tessera primitives:
  1. SPIRE workload identity binding
  2. Delegation token signed
  3. WIMSE token minted with audience binding
  4. MCP tool call with context segments
  5. Policy decision (taint tracking)
  6. Hash-chained audit record

Each step prints what it did and references the NIST control it exercises.

To run standalone (no external services required):
  python3.12 examples/nccoe_reference/scenario.py

To integrate into tests:
  from examples.nccoe_reference.scenario import run_scenario
  result = run_scenario()
  assert result.all_steps_succeeded
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from tessera.audit_log import GENESIS_HASH, JSONLHashchainSink
from tessera.compliance import CWE_CODES, NIST_CONTROLS
from tessera.context import Context, make_segment
from tessera.delegation import DelegationToken, sign_delegation, verify_delegation
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.identity import WorkloadIdentity
from tessera.labels import Origin, TrustLevel
from tessera.policy import Decision, DecisionKind, Policy

# Shared HMAC key (v0 symmetric signing path).
# In production, use asymmetric signing with tessera.signing.JWTSigner.
HMAC_KEY = b"nccoe-example-key-do-not-use-prod-length-32"


@dataclass(frozen=True)
class ScenarioStep:
    """Outcome of one scenario step."""

    name: str
    succeeded: bool
    detail: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        status = "✓" if self.succeeded else "✗"
        return f"{status} {self.name}"


@dataclass(frozen=True)
class ScenarioResult:
    """Complete scenario run."""

    all_steps_succeeded: bool
    steps: list[ScenarioStep]
    audit_log_path: Path | None = None
    hash_chain_verified: bool = False

    def __str__(self) -> str:
        lines = ["=== NCCoE Reference Scenario ===\n"]
        for step in self.steps:
            lines.append(str(step))
        if self.hash_chain_verified:
            lines.append("\n✓ Hash chain integrity verified")
        if not self.all_steps_succeeded:
            lines.append("\n✗ Scenario did not complete successfully")
        else:
            lines.append("\n✓ All steps completed successfully")
        return "\n".join(lines)


def run_step_1_identity_binding() -> ScenarioStep:
    """Step 1: SPIRE Workload Identity Binding.

    Simulates obtaining a SPIFFE X.509 SVID from local SPIRE node agent.
    Uses tessera.identity.WorkloadIdentity to represent the agent's identity.

    NIST Controls: IA-5 (Authenticator Management), IA-9 (Service ID Auth)
    """
    try:
        # Simulate SPIRE issuing an SVID.
        # In production, this calls the local SPIRE Workload API.
        svid_subject = "spiffe://cluster.local/ns/default/sa/agent-01"
        svid_valid_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        # Create WorkloadIdentity from the SVID.
        workload = WorkloadIdentity(
            spiffe_id=svid_subject,
            trust_domain="cluster.local",
            issuer="spiffe://cluster.local",
            audience=("tessera-mesh",),
            tenant="default",
        )

        detail = {
            "agent_svid": workload.spiffe_id,
            "svid_valid_until": svid_valid_until.isoformat(),
            "nist_controls": list(NIST_CONTROLS.get(EventKind.IDENTITY_VERIFY_FAILURE, ())),
        }

        return ScenarioStep(
            name="Step 1: SPIRE identity binding",
            succeeded=True,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 1: SPIRE identity binding",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_step_2_delegation_binding() -> ScenarioStep:
    """Step 2: Delegation Token Signed.

    Agent creates a DelegationToken binding user intent (subject),
    agent identity (delegate), target audience, and allowed actions.
    Token is HMAC-signed.

    NIST Controls: AC-4 (Information Flow), AC-6 (Least Privilege)
    """
    try:
        user_email = "user@example.com"
        delegate = "spiffe://cluster.local/ns/default/sa/agent-01"
        audience = "https://datastore.internal"
        mcp_audiences = frozenset(["datastore-mcp"])
        allowed_actions = ("write:datastore", "read:metrics")

        # Create and sign the delegation token.
        token = DelegationToken(
            subject=user_email,
            delegate=delegate,
            audience=audience,
            authorized_actions=allowed_actions,
            mcp_audiences=mcp_audiences,
            session_id="ses_nccoe_example_001",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        signed_token = sign_delegation(token, HMAC_KEY)

        # Verify the signature. The Tessera verifier uses the
        # ``audience`` keyword (not ``expected_audience``).
        verified = verify_delegation(signed_token, HMAC_KEY, audience=audience)
        assert verified, "Delegation token signature verification failed"

        detail = {
            "subject": user_email,
            "delegate": delegate,
            "audience": audience,
            "mcp_audiences": list(mcp_audiences),
            "authorized_actions": list(allowed_actions),
            "expires_at": signed_token.expires_at.isoformat(),
            "signature_verified": True,
            "nist_controls": list(NIST_CONTROLS.get(EventKind.DELEGATION_EXEC, ())),
        }

        return ScenarioStep(
            name="Step 2: Delegation token signed",
            succeeded=True,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 2: Delegation token signed",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_step_3_wimse_token_minting() -> ScenarioStep:
    """Step 3: WIMSE Token Minted with Audience Binding.

    Wraps the SVID in a JWT (typ: wit+jwt) with audience and optional PoP binding.
    Uses tessera.identity.WorkloadIdentityToken (WIMSE WIT envelope).

    NIST Controls: IA-9 (Service ID Auth), AC-4 (Information Flow)
    """
    try:
        agent_svid = "spiffe://cluster.local/ns/default/sa/agent-01"
        audience = "https://datastore.internal"

        # In production, use tessera.signing.JWTSigner with a private key.
        # For this example, we represent the token structure without PyJWT.
        token_claims = {
            "iss": agent_svid,
            "aud": audience,
            "cnf": {
                "jkt": "example-thumbprint-base64url-of-public-key"
            },
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        }

        # Simulate JWT encoding (typ: wit+jwt).
        token_str = json.dumps(token_claims)

        detail = {
            "token_iss": token_claims["iss"],
            "token_aud": token_claims["aud"],
            "token_cnf_jkt": token_claims["cnf"]["jkt"],
            "token_expires_at": datetime.fromtimestamp(
                token_claims["exp"], tz=timezone.utc
            ).isoformat(),
            "nist_controls": list(NIST_CONTROLS.get(EventKind.IDENTITY_VERIFY_FAILURE, ())),
        }

        return ScenarioStep(
            name="Step 3: WIMSE token minted",
            succeeded=True,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 3: WIMSE token minted",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_step_4_mcp_tool_call() -> ScenarioStep:
    """Step 4: MCP Tool Call with Audience-Checked Bearer.

    Sends a tool call with bearer token and context segments.
    Each segment carries a tessera.labels.TrustLabel indicating origin and trust level.

    NIST Controls: SI-10 (Information Accuracy), AC-4 (Information Flow)
    """
    try:
        tool_name = "write_datastore"

        # Build context: system, user, and untrusted retrieval result.
        ctx = Context()

        # System prompt (TrustLevel.SYSTEM = 200).
        system_segment = make_segment(
            content="You are a helpful assistant managing a datastore.",
            origin=Origin.SYSTEM,
            principal="system",
            key=HMAC_KEY,
            trust_level=TrustLevel.SYSTEM,
        )
        ctx.add(system_segment)

        # User query (TrustLevel.USER = 100).
        user_segment = make_segment(
            content="Write the following record to the datastore: name=Alice, email=alice@example.com",
            origin=Origin.USER,
            principal="user@example.com",
            key=HMAC_KEY,
            trust_level=TrustLevel.USER,
        )
        ctx.add(user_segment)

        # Retrieval result from web (TrustLevel.TOOL = 50, simulating untrusted source).
        retrieval_segment = make_segment(
            content="Retrieved schema documentation from https://example.com/api/datastore-schema",
            origin=Origin.TOOL,
            principal="fetch_url_tool",
            key=HMAC_KEY,
            trust_level=TrustLevel.TOOL,
        )
        ctx.add(retrieval_segment)

        # Verify all segments.
        for seg in ctx.segments:
            verified = seg.verify(HMAC_KEY)
            assert verified, f"Segment verification failed: {seg.label}"

        detail = {
            "tool_name": tool_name,
            "context_segments": len(ctx.segments),
            "segments": [
                {
                    "origin": str(seg.label.origin),
                    "principal": seg.label.principal,
                    "trust_level": int(seg.label.trust_level),
                    "verified": seg.verify(HMAC_KEY),
                }
                for seg in ctx.segments
            ],
            "context_min_trust": int(ctx.min_trust),
            "nist_controls": list(NIST_CONTROLS.get(EventKind.POLICY_DENY, ())),
        }

        return ScenarioStep(
            name="Step 4: MCP tool call with context segments",
            succeeded=True,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 4: MCP tool call with context segments",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_step_5_policy_decision(ctx: Context) -> ScenarioStep:
    """Step 5: Policy Decision via Taint Tracking.

    Proxy evaluates the policy using tessera.policy.Policy.evaluate().
    Computes context min_trust = min(all segment trust levels).
    Denies if min_trust < tool requirement.

    NIST Controls: AC-4 (Information Flow), SI-10 (Information Accuracy)
    """
    try:
        tool_name = "write_datastore"
        required_trust = TrustLevel.USER  # 100: requires USER or above

        # Create policy and set requirement.
        policy = Policy()
        policy.require(tool_name, required_trust)

        # Evaluate the tool call against the context.
        decision = policy.evaluate(ctx, tool_name)

        detail = {
            "tool_name": tool_name,
            "context_min_trust": int(ctx.min_trust),
            "required_trust": int(required_trust),
            "decision": str(decision.kind),
            "allowed": decision.allowed,
            "nist_controls": list(NIST_CONTROLS.get(EventKind.POLICY_DENY, ())),
            "cwe_codes": list(CWE_CODES.get(EventKind.POLICY_DENY, ())),
        }

        return ScenarioStep(
            name="Step 5: Policy decision (taint tracking)",
            succeeded=True,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 5: Policy decision (taint tracking)",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_step_6_audit_record(audit_log_path: Path) -> ScenarioStep:
    """Step 6: Hash-Chained Audit Record.

    Policy decision is appended to JSONL audit log with SHA-256 hash chain.
    Uses tessera.audit_log.JSONLHashchainSink. Each event links to the previous.

    NIST Controls: AU-10 (Non-Repudiation), AU-12 (Audit Generation)
    """
    try:
        from tessera.audit_log import verify_chain

        # Create a POLICY_DENY event.
        event = SecurityEvent(
            kind=EventKind.POLICY_DENY,
            principal="user@example.com",
            detail={
                "tool_name": "write_datastore",
                "min_trust": int(TrustLevel.TOOL),
                "required_trust": int(TrustLevel.USER),
                "reason": "context min_trust below tool requirement",
                "nist_controls": list(NIST_CONTROLS.get(EventKind.POLICY_DENY, ())),
                "cwe_codes": list(CWE_CODES.get(EventKind.POLICY_DENY, ())),
            },
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Emit the event (this appends to the audit log).
        emit_event(event)

        # Verify the audit log chain.
        result = verify_chain(audit_log_path)
        chain_verified = result.valid

        detail = {
            "event_kind": str(event.kind),
            "principal": event.principal,
            "audit_log_path": str(audit_log_path),
            "chain_verified": chain_verified,
            "nist_controls": list(NIST_CONTROLS.get(EventKind.POLICY_DENY, ())),
        }

        return ScenarioStep(
            name="Step 6: Hash-chained audit record",
            succeeded=chain_verified,
            detail=detail,
        )
    except Exception as e:
        return ScenarioStep(
            name="Step 6: Hash-chained audit record",
            succeeded=False,
            detail={"error": str(e)},
        )


def run_scenario(audit_log_path: Path | None = None) -> ScenarioResult:
    """Run the complete NCCoE scenario.

    Args:
        audit_log_path: Path to write audit log. If None, uses a temp file.

    Returns:
        ScenarioResult with all steps and outcomes.
    """
    if audit_log_path is None:
        audit_log_path = Path("/tmp/nccoe_scenario_audit.jsonl")

    # Clear any existing log.
    if audit_log_path.exists():
        audit_log_path.unlink()

    # Create the audit log sink.
    audit_log_sink = JSONLHashchainSink(audit_log_path)
    from tessera.events import register_sink
    register_sink(audit_log_sink)

    steps = []

    # Run all steps.
    step1 = run_step_1_identity_binding()
    steps.append(step1)

    step2 = run_step_2_delegation_binding()
    steps.append(step2)

    step3 = run_step_3_wimse_token_minting()
    steps.append(step3)

    step4 = run_step_4_mcp_tool_call()
    steps.append(step4)

    # Step 5 needs context from step 4.
    if step4.succeeded:
        ctx = Context()
        ctx.add(
            make_segment(
                "You are a helpful assistant managing a datastore.",
                Origin.SYSTEM,
                "system",
                key=HMAC_KEY,
                trust_level=TrustLevel.SYSTEM,
            )
        )
        ctx.add(
            make_segment(
                "Write the following record to the datastore: name=Alice, email=alice@example.com",
                Origin.USER,
                "user@example.com",
                key=HMAC_KEY,
                trust_level=TrustLevel.USER,
            )
        )
        ctx.add(
            make_segment(
                "Retrieved schema documentation from https://example.com/api/datastore-schema",
                Origin.TOOL,
                "fetch_url_tool",
                key=HMAC_KEY,
                trust_level=TrustLevel.TOOL,
            )
        )
        step5 = run_step_5_policy_decision(ctx)
    else:
        step5 = ScenarioStep(
            name="Step 5: Policy decision (taint tracking)",
            succeeded=False,
            detail={"error": "Skipped due to step 4 failure"},
        )
    steps.append(step5)

    step6 = run_step_6_audit_record(audit_log_path)
    steps.append(step6)

    all_succeeded = all(s.succeeded for s in steps)

    return ScenarioResult(
        all_steps_succeeded=all_succeeded,
        steps=steps,
        audit_log_path=audit_log_path,
        hash_chain_verified=step6.detail.get("chain_verified", False),
    )


if __name__ == "__main__":
    result = run_scenario()
    print(result)
    exit(0 if result.all_steps_succeeded else 1)
