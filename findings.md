# Tessera Gap Audit Findings

## Scope

- Code inventory against current implementation in `src/tessera/`
- Tests and exposed surfaces in `tests/`
- Project docs and roadmap
- Gap mapping against `AgentMesh.md`, `agentmesh-v2-specification.md`
- External alignment against current OWASP and NIST AI RMF guidance

## Findings

- [CRITICAL] Tessera is still a reference library, not a production agent mesh. There is no control plane, no production Rust data plane, no ambient deployment model, no hot policy distribution, no fleet registry backend, and no multi-tenant management surface. Evidence: [docs/ROADMAP.md](/Users/kenith.philip/Tessera/docs/ROADMAP.md), [README.md](/Users/kenith.philip/Tessera/README.md), [SECURITY.md](/Users/kenith.philip/Tessera/SECURITY.md).
- [HIGH] Runtime containment is absent. The codebase does not orchestrate Firecracker, gVisor, seccomp, eBPF, Tetragon, or egress enforcement, so high-risk tool execution is still protected only at the application layer. Evidence: [SECURITY.md](/Users/kenith.philip/Tessera/SECURITY.md), [docs/ROADMAP.md](/Users/kenith.philip/Tessera/docs/ROADMAP.md).
- [HIGH] Identity is partial, not enterprise-grade. Tessera has HMAC and JWT/JWKS verification plus SPIFFE-shaped IDs, but no live mTLS session enforcement, DPoP/WIMSE proof-of-possession, SPIRE-backed issuance in CI, or cross-provider federation. Evidence: [src/tessera/signing.py](/Users/kenith.philip/Tessera/src/tessera/signing.py), [src/tessera/proxy.py](/Users/kenith.philip/Tessera/src/tessera/proxy.py), [docs/ROADMAP.md](/Users/kenith.philip/Tessera/docs/ROADMAP.md).
- [HIGH] A2A and MCP are only partially infrastructural. Tessera now has secure carriage helpers, but not a live A2A gateway, MCP broker, streaming inspection layer, or federated mediation plane. Evidence: [src/tessera/a2a.py](/Users/kenith.philip/Tessera/src/tessera/a2a.py), [src/tessera/mcp.py](/Users/kenith.philip/Tessera/src/tessera/mcp.py), [src/tessera/proxy.py](/Users/kenith.philip/Tessera/src/tessera/proxy.py).
- [HIGH] Compliance posture is not audit-ready. A control matrix now exists in [docs/OWASP_NIST_CONTROL_MATRIX.md](/Users/kenith.philip/Tessera/docs/OWASP_NIST_CONTROL_MATRIX.md), but there is still no evidence export layer, approval workflow system, policy version governance, benchmark program, or formal AI RMF profile sufficient for “fully hardened” claims. Evidence: repo-wide absence plus [docs/AGENT_SECURITY_MESH_V1_SPEC.md](/Users/kenith.philip/Tessera/docs/AGENT_SECURITY_MESH_V1_SPEC.md).
- [MEDIUM] Observability is useful but incomplete. Security events and spans exist, but there are no GenAI semantic convention attributes, provenance DAG export, bounded async webhook delivery, or compliance-oriented evidence packaging. Evidence: [src/tessera/events.py](/Users/kenith.philip/Tessera/src/tessera/events.py), [src/tessera/telemetry.py](/Users/kenith.philip/Tessera/src/tessera/telemetry.py), [docs/ROADMAP.md](/Users/kenith.philip/Tessera/docs/ROADMAP.md).
- [RESOLVED] Documentation and project metadata drift at audit start has been corrected in the current tree. Current verified state is 15 source modules, about 3,237 source lines, and 125 passing tests. Evidence: [CLAUDE.md](/Users/kenith.philip/Tessera/CLAUDE.md), [README.md](/Users/kenith.philip/Tessera/README.md), [docs/ROADMAP.md](/Users/kenith.philip/Tessera/docs/ROADMAP.md), [docs/CHANGELOG.md](/Users/kenith.philip/Tessera/docs/CHANGELOG.md), verified by `wc -l` and `pytest`.
