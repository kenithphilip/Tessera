# Security Policy

## Scope

Tessera is a reference implementation of two security primitives for agent
mesh infrastructure: signed trust labels on context segments and
schema-enforced dual-LLM execution. The invariants Tessera enforces are
documented in [`papers/two-primitives-for-agent-security-meshes.md`](papers/two-primitives-for-agent-security-meshes.md).

This policy covers security vulnerabilities in the Tessera codebase
itself. The threat model and explicit out-of-scope list are in Section 2
of the paper. In particular, the following are NOT covered by this
policy and should not be reported as Tessera vulnerabilities:

- Direct prompt injection by an authenticated user of an agent built on
  Tessera. The primitives defend the agent from third-party content, not
  the system from its own user.
- Attacks against the underlying LLM (backdoors, data poisoning, weight
  extraction, adversarial inputs at the model level).
- Compromise of tool servers, MCP implementations, or the supply chain of
  model weights, system prompts, or tool manifests.
- Sandbox escape for agent-generated code. Tessera operates at the
  application layer and does not replace Firecracker, gVisor, or
  equivalent runtime isolation.
- Semantic poisoning of the agent's natural-language output to the user.
  The invariants defend the tool-call boundary, not the generation
  boundary.

A report that matches the threat model will be taken seriously. A report
outside the threat model will be politely closed with a pointer to this
document.

## Reporting a vulnerability

If you believe you have found a vulnerability in Tessera that affects one
of the invariants the paper claims, please report it privately rather
than opening a public issue.

**Preferred channel:** GitHub private vulnerability reporting at
<https://github.com/kenithphilip/Tessera/security/advisories/new>.

**Alternate channel:** email the maintainer directly. Please include
"Tessera" in the subject line. Contact details are in the repository's
`CODEOWNERS` file or the author line of the paper.

Please include in your report:

- A description of the invariant you believe is broken, with reference to
  the paper section that states the invariant.
- A minimal reproduction: ideally a failing test added to the Tessera
  test suite, or a short Python script that demonstrates the issue.
- Your assessment of severity and exploitability.
- Any proposed fix or mitigation.

## Response timeline

Tessera is currently maintained by a single author as a draft-for-discussion
reference implementation, not a commercial product. The response timelines
below are best-effort, not contractual.

- **Initial acknowledgment:** within 5 business days.
- **Triage and severity assessment:** within 10 business days.
- **Fix or public advisory:** within 90 days for most reports. Longer
  windows may apply for issues that require coordinated disclosure with
  downstream integrators, standards bodies (IETF WIMSE, OWASP Agentic
  AI), or the maintainers of underlying dependencies (SPIRE, PyJWT, the
  `mcp` package, Pydantic).

## Disclosure policy

Tessera practices coordinated disclosure with a 90-day default window.
After a report is triaged, the maintainer will:

1. Acknowledge the report and open a private security advisory.
2. Develop a fix in a private branch.
3. Coordinate disclosure timing with the reporter.
4. Publish a public advisory and patched release.
5. Credit the reporter in the advisory unless they request anonymity.

If a report is declined (for example, because it falls outside the
threat model), the maintainer will explain the reasoning and, where
possible, point to the appropriate upstream project.

## Known limitations

The following are documented limitations of the current reference
implementation, not vulnerabilities:

- **Symmetric HMAC is the default signing mode.** Multi-workload
  deployments should use JWT-SVIDs via `tessera.signing.JWTSigner`. The
  HMAC default is a single-process convenience, not a
  distributed-system primitive.
- **The FastAPI proxy is a reference, not a production artifact.**
  Production deployments should port the primitives into a Rust data
  plane. Reports of scalability or DoS issues in the FastAPI proxy will
  be accepted but are not treated as high-severity.
- **The default `WorkerReport` schema may gain new fields over time.**
  If you add a field, do not make it a free-form `str`. The safe-by-default
  property of the schema is load-bearing for Primitive 2.
- **`strict_worker` relies on Pydantic's validation being correct.**
  If a Pydantic CVE allows malformed data to pass validation, Tessera's
  Primitive 2 inherits the weakness. Pin Pydantic to a known-good
  version in high-stakes deployments.
- **The JWT verifier has a 30-second clock-skew leeway by default.**
  Deployments that want tighter bounds should override the `leeway`
  parameter on `JWTVerifier` and `JWKSVerifier`.

## Safe harbor

Tessera is maintained as a public-interest security research project.
Good-faith security research on the Tessera codebase, conducted in
accordance with this policy, will not result in legal action from the
maintainer. This safe harbor does NOT extend to:

- Research against third-party services that happen to use Tessera.
- Denial-of-service attacks against any Tessera deployment.
- Exfiltration of data from any system, including test systems.
- Social engineering of Tessera contributors or users.

If you are unsure whether your research is covered, ask before you test.
