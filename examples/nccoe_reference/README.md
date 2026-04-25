# NCCoE Reference Implementation: AI Agent Identity and Authorization

This directory contains a runnable reference implementation of the NCCoE AI Agent Identity and Authorization practice guide using Tessera primitives.

## What This Is

The `scenario.py` script demonstrates the canonical "agent calls tool with delegated authority" flow. It exercises six key Tessera primitives and records policy decisions in a hash-chained audit log.

## Quick Start

Run the scenario end-to-end:

```bash
cd /Users/kenith.philip/Tessera
python3.12 examples/nccoe_reference/scenario.py
```

Expected output:

```
=== NCCoE Reference Scenario ===
Step 1: SPIRE identity binding
  Agent SVID: spiffe://cluster.local/ns/default/sa/agent-01
  SVID valid until: 2026-04-25T10:30:00Z

Step 2: Delegation token signed
  Subject: user@example.com
  Delegate: spiffe://cluster.local/ns/default/sa/agent-01
  Audience: https://datastore.internal
  Actions: ['write:datastore', 'read:metrics']
  Expires at: 2026-04-25T10:35:00Z

Step 3: WIMSE token minted
  Bearer JWT audience: https://datastore.internal
  PoP key binding: cnf.jkt=...

Step 4: MCP tool call with audience binding
  Tool: write_datastore
  Context segments: 3
    - User prompt (TrustLevel.USER=100)
    - System context (TrustLevel.SYSTEM=200)
    - Retrieval result (TrustLevel.TOOL=50)

Step 5: Policy decision
  Context min_trust: 50 (TOOL)
  Tool requirement: 100 (USER)
  Decision: DENY (insufficient trust)
  NIST controls: AC-4, SI-10, SC-7
  CWE codes: CWE-20

Step 6: Hash-chained audit record
  Event seq: 1
  Hash: sha256(...)
  Prev hash: 0000000000000000... (genesis)
  Chain verified: True

✓ All steps completed successfully
✓ Hash chain integrity verified
```

## What Each Step Does

### Step 1: SPIRE Workload Identity Binding

Simulates obtaining a SPIFFE X.509 SVID from a local SPIRE node agent. Uses `tessera.identity.WorkloadIdentity` to create a subject.

**NIST Controls:** IA-5, IA-9

### Step 2: Delegation Token Signed

Agent creates a `tessera.delegation.DelegationToken` binding user intent (subject), agent identity (delegate), target tool (audience), and allowed actions. Token is signed with an HMAC key.

**NIST Controls:** AC-4, AC-6

### Step 3: WIMSE Token Minted

Wraps the SVID in a JWT (typ: wit+jwt) with audience binding and optional proof-of-possession (cnf.jkt). Uses `tessera.identity.WorkloadIdentityToken`.

**NIST Controls:** IA-9, AC-4

### Step 4: MCP Tool Call with Audience Checking

Sends a tool call with bearer token and context segments. Each segment carries a `tessera.labels.TrustLabel` indicating its origin and trust level.

**NIST Controls:** SI-10, AC-4

### Step 5: Policy Decision

Proxy evaluates the policy using `tessera.policy.Policy.evaluate()`. Computes context min_trust = min(all segment trust levels). Denies if min_trust < tool requirement.

**NIST Controls:** AC-4, SI-10

### Step 6: Hash-Chained Audit Record

Policy decision is appended to a JSONL audit log with SHA-256 hash chain. Uses `tessera.audit_log.JSONLHashchainSink`. Each event links to the previous via `prev_hash`.

**NIST Controls:** AU-10, AU-12

## Scenario Details

### Assumptions

- SPIRE is present (simulated with hardcoded SVID subject in this example)
- Agent and proxy share HMAC key for delegation-token signing (v0 symmetric path)
- Policy requires TrustLevel.USER (100) to invoke write_datastore
- Context contains untrusted retrieval result (TrustLevel.TOOL=50)

### Expected Outcome

Policy denies the tool call because context min_trust (50) is below the requirement (100). The denial is recorded in the audit log with NIST control enrichment.

## File Structure

```
examples/nccoe_reference/
├── README.md           (this file)
├── scenario.py         (main script)
└── __init__.py         (package marker)
```

## Running Tests

Execute the scenario within the test suite:

```bash
cd /Users/kenith.philip/Tessera
pytest tests/test_nccoe_reference_scenario.py -v
```

Run a specific test:

```bash
pytest tests/test_nccoe_reference_scenario.py::test_context_taint_blocks_sensitive_tool -v
```

## Tessera Primitives Used

| Module | Class/Function | Purpose |
|--------|----------------|---------|
| `tessera.identity` | `WorkloadIdentity` | SPIFFE SVID subject representation |
| `tessera.delegation` | `DelegationToken`, `sign_delegation` | User intent binding + signature |
| `tessera.identity` | `WorkloadIdentityToken` | WIMSE WIT envelope |
| `tessera.context` | `Context`, `make_segment` | Context builder + segment labeling |
| `tessera.labels` | `TrustLabel`, `TrustLevel` | Cryptographic label + enum |
| `tessera.policy` | `Policy`, `evaluate` | Taint-tracking policy engine |
| `tessera.events` | `SecurityEvent`, `EventKind` | Policy decision event |
| `tessera.audit_log` | `JSONLHashchainSink` | Durable tamper-evident log |
| `tessera.compliance` | `NIST_CONTROLS`, `CWE_CODES` | Standards enrichment |

## NIST Control Coverage

This scenario exercises the following NIST SP 800-53 Rev. 5 controls:

- **IA-5:** Authenticator Management (delegation token expiry)
- **IA-9:** Service Identification and Authentication (bearer token verification)
- **AC-4:** Information Flow Enforcement (min_trust computation)
- **AC-6:** Least Privilege (action scope restrictions)
- **AU-10:** Non-Repudiation (delegation signature)
- **AU-12:** Audit Generation (event logging)
- **SI-10:** Information Accuracy, Completeness, and Validity (context labeling)
- **SC-7:** Boundary Protection (untrusted input rejection)

## Extension Points

To adapt this example for a specific threat scenario:

1. **Modify context labels** in step 4 to simulate different trust sources
2. **Change policy requirement** in step 5 to test different decision branches
3. **Add new segments** (e.g., from different tools) to test min_trust recomputation
4. **Introduce tampering** in the audit log (step 6) to verify chain detection

## References

- Tessera Reference Implementation: https://github.com/kenithphilip/Tessera
- NCCoE AI Agent Identity and Authorization Practice Guide: [NCCoE URL]
- NIST SP 800-63-3: Authentication and Lifecycle Management
- RFC 8707: OAuth 2.0 Authorization Server Metadata
- SPIFFE Specification: https://spiffe.io/
