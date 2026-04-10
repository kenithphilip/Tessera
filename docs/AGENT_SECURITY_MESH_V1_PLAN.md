# Agent Security Mesh V1 Plan

**Goal:** Define a provider-neutral, enterprise-adoptable security mesh for agentic workloads, with signed prompt provenance, workload and delegation identity, policy enforcement, and ambient or gateway deployment as first-class requirements.

**Approach:** Write one canonical spec document in this repo: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`. Base it on verified current standards and projects, clearly separate what exists from what is proposed, and position Tessera as a load-bearing provenance and policy primitive inside the larger mesh rather than claiming Tessera already is the full mesh.

**Scope:** In scope are architecture, threat model, protocol surfaces, control plane, data plane, identity, provenance, policy, observability, deployment modes, conformance, and adoption path. Out of scope are implementation code, benchmark claims we cannot verify, and any statement that overclaims current provider support or production maturity.

---

### Task 1: Canonicalize The Artifact

**Files:**
- Create: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`
- Reference: `docs/ARCHITECTURE.md`
- Reference: `docs/ROADMAP.md`
- Reference: `papers/two-primitives-for-agent-security-meshes.md`

- [ ] Step 1: Create `docs/AGENT_SECURITY_MESH_V1_SPEC.md` with the fixed top-level structure:
  - Title and status
  - Executive summary
  - Problem statement
  - Design principles
  - Threat model and non-goals
  - Architecture
  - Standards mapping
  - Conformance profile
  - Adoption roadmap
- [ ] Step 2: State the document position explicitly: Tessera is two primitives that compose into the proposed mesh, not the whole mesh.
- [ ] Step 3: Run `rg -n "full mesh|complete mesh|production-ready mesh" docs/AGENT_SECURITY_MESH_V1_SPEC.md` and verify no overclaiming language survives.

### Task 2: Ground The Spec In Verified Sources

**Files:**
- Modify: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`
- Reference: `papers/two-primitives-for-agent-security-meshes.md`

- [ ] Step 1: Add a “What Exists Today” section covering SPIFFE/SPIRE, MCP, A2A, WIMSE AI agent auth draft, Spotlighting, CaMeL, and Agent Governance Toolkit.
- [ ] Step 2: Add a “What Is Missing” section covering signed prompt provenance, user-to-agent delegation standardization, cross-provider federation, and provider-native trust-separated prompt channels.
- [ ] Step 3: Add source links inline for every claim that could change over time.
- [ ] Step 4: Run `rg -n "TODO|TBD|probably|likely|maybe" docs/AGENT_SECURITY_MESH_V1_SPEC.md` and verify there are no placeholders or hedged claims where a concrete statement is required.

### Task 3: Specify The Core Primitives

**Files:**
- Modify: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`
- Reference: `src/tessera/context.py`
- Reference: `src/tessera/policy.py`
- Reference: `src/tessera/quarantine.py`

- [ ] Step 1: Define the mesh primitives explicitly:
  - Agent identity
  - Delegation token
  - Context segment envelope
  - Prompt provenance manifest
  - Tool authorization contract
  - Security event schema
- [ ] Step 2: Define required fields, trust semantics, and verification rules for the prompt provenance objects.
- [ ] Step 3: Specify deterministic enforcement points outside the model: proxy, policy engine, runtime sandbox, and audit sink.
- [ ] Step 4: Run `rg -n "min_trust|provenance|delegation|authorization contract|conformance" docs/AGENT_SECURITY_MESH_V1_SPEC.md` and verify each primitive and enforcement concept is represented.

### Task 4: Define Deployment And Adoption

**Files:**
- Modify: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`
- Reference: `docs/ROADMAP.md`

- [ ] Step 1: Add deployment profiles:
  - Ambient or gateway mesh
  - Framework SDK mode
  - High-security dual-LLM mode
- [ ] Step 2: Add an adoption matrix for enterprises, model providers, tool providers, and framework maintainers.
- [ ] Step 3: Add a conformance section with three levels:
  - Bronze: identity, authz, audit
  - Silver: signed prompt provenance and egress control
  - Gold: quarantined execution and transaction-scoped delegation
- [ ] Step 4: Run `rg -n "Bronze|Silver|Gold|ambient|gateway|dual-LLM" docs/AGENT_SECURITY_MESH_V1_SPEC.md` and verify all deployment and conformance profiles are present.

### Task 5: Review For Internal Consistency

**Files:**
- Modify: `docs/AGENT_SECURITY_MESH_V1_SPEC.md`
- Reference: `CLAUDE.md`
- Reference: `README.md`

- [ ] Step 1: Verify the spec does not weaken or contradict the current Tessera paper or CLAUDE invariants.
- [ ] Step 2: Verify the spec consistently distinguishes:
  - current-state facts
  - proposed standards
  - long-term research directions
- [ ] Step 3: Run `python3 - <<'PY'
from pathlib import Path
text = Path("docs/AGENT_SECURITY_MESH_V1_SPEC.md").read_text()
required = [
    "What Exists Today",
    "What Is Missing",
    "Context Segment Envelope",
    "Prompt Provenance Manifest",
    "Conformance",
    "Adoption Roadmap",
]
missing = [item for item in required if item not in text]
print("missing:", missing)
assert not missing
PY` and verify it prints `missing: []`.
- [ ] Step 4: Run `python3 -m py_compile src/tessera/*.py` only if any code examples copied into the spec are added to source files. Otherwise skip.

---

## Self-Review

### Coverage

- The plan covers the user's requested outcomes:
  - whether such a system is possible
  - what exists now
  - what is missing
  - a concrete, adoptable technical specification
  - a path suitable for large organizations and model providers

### Placeholder Scan

- No `TBD`, `TODO`, or “similar to Task N” placeholders are present.

### Consistency

- The canonical output is one spec file, `docs/AGENT_SECURITY_MESH_V1_SPEC.md`.
- The plan keeps Tessera’s current scope intact and avoids redefining it as the full mesh.

### Scope Check

- This is focused enough for a single drafting pass because the implementation target is one spec document, not code plus docs plus protocol implementation.
