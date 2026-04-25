---
name: NCCoE Reference Implementation Test Plan
description: Test categories, concrete test cases, NIST control mappings, and reproduction procedures
version: 0.1
date: 2026-04-25
---

# NCCoE Reference Implementation Test Plan

This document defines the test categories, concrete test cases, NIST control mappings, and procedures for reproducing each test using Tessera primitives.

## Test Categories

### 1. Identity Verification and Workload Attestation

Validates that the proxy correctly verifies SPIFFE workload identity and rejects forged or expired tokens.

#### Test Case 1.1: Valid SPIFFE-SVID Accepted

**Scenario:** Agent with valid X.509 SVID calls a tool.

**Expected Outcome:** Proxy accepts the bearer token and forwards the call.

**NIST Controls:** IA-5 (Authenticator Management), IA-9 (Service Identification and Authentication)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 -c "
from tests.test_nccoe_reference_scenario import run_step_1_identity_binding
run_step_1_identity_binding()
print('✓ Step 1: Identity binding succeeds')
"
```

#### Test Case 1.2: Expired SVID Rejected

**Scenario:** Agent with expired X.509 SVID attempts tool call.

**Expected Outcome:** Proxy rejects the bearer token and returns 401 Unauthorized.

**NIST Controls:** IA-5 (Authenticator Management), AC-12 (Session Termination)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 examples/nccoe_reference/scenario.py --test-case 1.2
```

#### Test Case 1.3: Forged Signature Detected

**Scenario:** Attacker supplies a bearer token with invalid signature.

**Expected Outcome:** Proxy rejects the token; emits IDENTITY_VERIFY_FAILURE event.

**NIST Controls:** IA-9 (Service Identification and Authentication), SC-8 (Transmission Confidentiality and Integrity)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_identity_forged_signature -v
```

### 2. Audience Binding and Delegation Scope

Validates that delegation tokens correctly bind the agent to specific tool audiences and enforce action scopes.

#### Test Case 2.1: Delegation Token Matches Tool Audience

**Scenario:** Agent holds delegation token with mcp_audiences: frozenset(["datastore-mcp"]). Calls write_datastore tool (audience: "datastore-mcp").

**Expected Outcome:** Proxy verifies audience match and forwards the call.

**NIST Controls:** AC-4 (Information Flow Enforcement), AC-6 (Least Privilege)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 -c "
from tests.test_nccoe_reference_scenario import run_step_2_delegation_binding
run_step_2_delegation_binding()
print('✓ Step 2: Delegation audience binding succeeds')
"
```

#### Test Case 2.2: Tool Call Outside Delegated Audience Denied

**Scenario:** Agent holds delegation for datastore-mcp but attempts to call analytics-mcp tool.

**Expected Outcome:** Proxy denies the call; emits MCP_TOKEN_AUDIENCE_MISMATCH event.

**NIST Controls:** AC-4 (Information Flow Enforcement), IA-9 (Service Identification and Authentication)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_delegation_audience_mismatch -v
```

#### Test Case 2.3: Tool Restricted to Authorized Actions Only

**Scenario:** Agent holds delegation for read:metrics, write:datastore. Attempts read:audit (not in delegation).

**Expected Outcome:** Proxy denies the call and emits DELEGATION_VERIFY_FAILURE.

**NIST Controls:** AC-6 (Least Privilege), AU-12 (Audit Generation)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 examples/nccoe_reference/scenario.py --test-case 2.3
```

### 3. Delegation Chain Validation

Validates that the proxy correctly verifies the chain of trust from user intent through delegation token to tool execution.

#### Test Case 3.1: Delegation Token Signature Verified End-to-End

**Scenario:** Agent signs delegation token with subject (user@example.com) -> delegate (agent-01) -> audience (datastore-mcp). Proxy verifies entire chain.

**Expected Outcome:** Proxy accepts the token and records the delegation chain in the audit log.

**NIST Controls:** AC-4 (Information Flow Enforcement), AU-10 (Non-Repudiation)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 -c "
from tests.test_nccoe_reference_scenario import run_step_3_delegation_signature
run_step_3_delegation_signature()
print('✓ Step 3: Delegation chain verifies end-to-end')
"
```

#### Test Case 3.2: Modified Delegation Token Detected

**Scenario:** Attacker modifies delegation token after signing (changes audience from datastore-mcp to privileged-mcp).

**Expected Outcome:** Proxy detects signature mismatch and denies the call.

**NIST Controls:** AU-10 (Non-Repudiation), SC-8 (Transmission Confidentiality and Integrity)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_delegation_tampering_detected -v
```

#### Test Case 3.3: Expired Delegation Token Rejected

**Scenario:** Delegation token signed 10 minutes ago with 5-minute TTL.

**Expected Outcome:** Proxy rejects the token and emits DELEGATION_VERIFY_FAILURE.

**NIST Controls:** AC-12 (Session Termination), AU-12 (Audit Generation)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_delegation_expiry -v
```

### 4. Context Taint and Policy Decision

Validates that the proxy correctly computes context minimum trust level and enforces policy denials based on taint.

#### Test Case 4.1: Minimum Trust Level Computed Correctly

**Scenario:** Context has three segments: system prompt (TrustLevel.SYSTEM=200), user query (TrustLevel.USER=100), retrieval result (TrustLevel.TOOL=50). Policy requires TrustLevel.USER=100 for write_datastore.

**Expected Outcome:** Proxy computes min_trust=50, denies the call, emits POLICY_DENY with required_trust=100, min_trust=50.

**NIST Controls:** AC-4 (Information Flow Enforcement), SI-10 (Information Accuracy, Completeness, Validity, and Authenticity)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 -c "
from tests.test_nccoe_reference_scenario import run_step_7_policy_decision
run_step_7_policy_decision()
print('✓ Step 7: Policy decision enforces min_trust')
"
```

#### Test Case 4.2: Elevated Trust Allows Tool Call

**Scenario:** Same context, but user escalates scope approval to TrustLevel.SYSTEM. min_trust becomes 100. Policy check passes.

**Expected Outcome:** Proxy allows the call, emits POLICY_ALLOW event.

**NIST Controls:** AC-6 (Least Privilege), AU-12 (Audit Generation)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_policy_elevated_trust -v
```

#### Test Case 4.3: Untrusted Segment Blocks All Tool Calls

**Scenario:** Context includes a segment with TrustLevel.UNTRUSTED=0 (e.g., redacted sensitive data).

**Expected Outcome:** Proxy immediately denies any tool call; emits POLICY_DENY without evaluating policy.

**NIST Controls:** SI-10 (Information Accuracy), SC-7 (Boundary Protection)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_policy_untrusted_segment -v
```

### 5. Audit Integrity and Hash Chain Verification

Validates that the hash-chained audit log is tamper-evident and correctly records all policy decisions.

#### Test Case 5.1: Audit Log Records Every Policy Decision

**Scenario:** Run a sequence of tool calls (allow, deny, allow, deny). Verify each decision appears in the audit log with correct sequence numbers.

**Expected Outcome:** Audit log contains all four records with consecutive seq (1, 2, 3, 4). Each prev_hash matches the previous record's hash.

**NIST Controls:** AU-10 (Non-Repudiation), AU-12 (Audit Generation), AU-4 (Audit Log Storage)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
python3.12 -c "
from tests.test_nccoe_reference_scenario import run_step_9_audit_record
run_step_9_audit_record()
print('✓ Step 9: Audit record appends with correct hash chain')
"
```

#### Test Case 5.2: Hash Chain Detects Mid-Sequence Tampering

**Scenario:** Attacker modifies event #2 (changes decision from DENY to ALLOW). Hash chain verification reads all events.

**Expected Outcome:** Verification detects that event #2's prev_hash does not match event #1's hash. Tampering is reported.

**NIST Controls:** SC-8 (Transmission Confidentiality and Integrity), AU-10 (Non-Repudiation)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_audit_tampering_detected -v
```

#### Test Case 5.3: SARIF Report Emitted for Denial Events

**Scenario:** Policy evaluation denies a tool call. SARIF emitter reads the audit log and generates a JSON report.

**Expected Outcome:** SARIF report contains the deny event with rule (POLICY_DENY), location (tool name), message (min_trust vs required_trust), and NIST control references.

**NIST Controls:** AU-12 (Audit Generation), CA-7 (Continuous Monitoring)

**Reproduction:**
```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py::test_sarif_emit -v
```

## NIST Control Coverage

| Control | Test Cases | Purpose |
|---------|-----------|---------|
| IA-5 | 1.1, 1.2 | Authenticator management and expiry |
| IA-9 | 1.3, 2.2 | Service identification and authentication |
| AC-4 | 2.1, 3.1, 4.1 | Information flow enforcement |
| AC-6 | 2.1, 4.2 | Least privilege |
| AC-12 | 1.2, 3.3 | Session termination |
| AU-10 | 3.1, 3.2, 5.2 | Non-repudiation |
| AU-12 | 2.3, 4.2, 5.1 | Audit generation |
| AU-4 | 5.1 | Audit log storage |
| SC-8 | 1.3, 3.2, 5.2 | Transmission confidentiality and integrity |
| SC-7 | 4.3 | Boundary protection |
| SI-10 | 4.1, 4.3 | Information accuracy and validity |
| CA-7 | 5.3 | Continuous monitoring |

## How to Run All Tests

Execute the full test suite:

```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py -v
```

Run a specific test category (e.g., identity verification):

```bash
pytest tests/test_nccoe_reference_scenario.py::test_identity_* -v
```

Run the scenario script interactively:

```bash
python3.12 examples/nccoe_reference/scenario.py
```

## References

- NIST SP 800-63-3: Authentication and Lifecycle Management
- NIST SP 800-53 Rev. 5: Security and Privacy Controls
- RFC 8707: OAuth 2.0 Authorization Server Metadata
- SPIFFE Specification: https://spiffe.io/
- Tessera Reference Implementation: https://github.com/kenithphilip/Tessera
