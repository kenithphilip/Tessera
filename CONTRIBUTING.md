# Contributing to Tessera

Tessera is a Python library of composable security primitives for LLM
agent systems. Two load-bearing invariants drive the design (signed
trust labels with taint tracking, schema-enforced dual-LLM execution),
documented in
[`papers/two-primitives-for-agent-security-meshes.md`](papers/two-primitives-for-agent-security-meshes.md).
Please read the paper before contributing. The contributions most
likely to be merged are the ones that sharpen the two invariants or
extend the supporting primitives (audit, replay, policy synthesis,
SSRF and URL gating, scanners) without weakening the stated invariants.

## What we want

In rough order of priority:

1. **Benchmarks.** The paper claims that schema-enforced dual-LLM
   execution is cheaper than CaMeL's reported 6.6x latency cost, but
   does not back the claim with numbers. A controlled benchmark
   comparing `strict_worker` against both single-LLM execution and a
   CaMeL-style interpreter on the same workload would be extremely
   valuable.
2. **Policy backend integrations.** The `Decision` object composes
   with Cedar or OPA as a chained evaluator after the taint-tracking
   primitive. A reference integration that shows the composition
   (taint first, attributes second) would close an obvious gap.
3. **Rust port of the proxy.** The FastAPI proxy in `src/tessera/proxy.py`
   is a specification, not a production artifact. A port of the
   primitives into agentgateway or an equivalent Rust data plane is
   welcome. The port must pin the same invariants the Python reference
   pins, enforced by the same test names listed in Appendix A of the
   paper.
4. **MCP SEP-1913 interop.** Once the SEP lands, the MCP interceptor
   should ingest `trust_level` annotations from tool outputs directly,
   rather than relying on the per-deployment external-tool registry.
5. **Additional test coverage.** Edge cases in taint tracking,
   multi-principal contexts, high-volume label verification, and
   schema violations under adversarial Pydantic inputs are all
   welcome targets.
6. **SPIRE reference stand-up.** The compose file in
   `deployment/spire/` is correct by inspection but has not been
   exercised end-to-end in CI. A GitHub Actions workflow that brings
   up the stack, issues a JWT-SVID to a test workload, signs a
   labeled segment, and verifies it from a second workload would
   turn the reference from "documented" into "continuously verified."

## What we do not want

- **New free-form string fields in the default `WorkerReport` schema.**
  This is load-bearing for Primitive 2. If you have a use case that
  needs free-form text, define your own schema subclass and document
  how the Planner treats that field. Do not change the default.
- **Pattern-matching guardrails.** Tessera is not a WAF for LLMs. The
  whole point of the primitives is that they are deterministic and
  structural rather than pattern-based. Regex-style content filters
  belong in a different project.
- **Dependencies on specific LLM providers.** The library must stay
  provider-agnostic. Integrations with OpenAI, Anthropic, Google, or
  others belong in examples, not in the core.
- **Features that break the single-process happy path.** Distribution,
  sharding, and multi-tenant concerns are legitimate but belong in
  extensions, not in the core primitives.
- **Security theater.** Every contribution that claims to improve
  security must pin a concrete invariant in a test. "This probably
  makes things safer" is not an accepted argument.

## Development setup

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

All tests must pass before a pull request is reviewed. At the time of
writing, the suite is 991 tests and runs in under ten seconds. If your
change slows the suite significantly, document the reason.

## Pull request expectations

- **Tests first.** Every behavior change must come with a test that
  demonstrates the old behavior failing and the new behavior passing.
  For security-relevant changes, the test must pin the specific
  invariant the change affects.
- **Small PRs.** Prefer several small PRs over one large one. A PR
  that touches more than ~500 lines outside of tests and docs will
  likely be asked to split.
- **One concern per PR.** Do not mix refactors, new features, and
  bug fixes in the same PR. It makes review harder and bisect worse.
- **No silent behavior changes.** If a public API changes, the change
  must be called out in the PR description and, when appropriate, in
  the test for the new behavior.
- **Preserve docstrings.** Docstrings on public classes and functions
  are part of the contract, especially the warnings on `WorkerReport`
  and `strict_worker`. Edits that remove or weaken those warnings
  will be rejected.

## Coding style

- Python 3.12+ only. Type annotations on all public APIs.
- `from __future__ import annotations` in every module.
- Dataclasses and Pydantic `BaseModel` subclasses where appropriate;
  avoid defining new magic.
- No em dashes or en dashes in code, docstrings, comments, or
  documentation. Use commas, colons, periods, or parentheses.
- No emojis anywhere.
- Minimal comments. Explain the non-obvious "why", not the "what".

## Security-sensitive changes

Any change to the following modules is considered security-sensitive
and will be reviewed with extra care. Expect slower review turnaround
and more pushback on unclear invariants:

- `tessera.labels`
- `tessera.signing`
- `tessera.policy`
- `tessera.quarantine` (especially `strict_worker` and the default
  `WorkerReport`)
- `tessera.context` (especially the `principal` property and
  `make_segment`'s signer argument)

If you are unsure whether a change is security-sensitive, assume it is
and flag it in the PR description. It is cheaper to be told "this is
fine" than to land a subtle regression.

## Filing issues

Before filing an issue, check:

1. The paper's threat model (Section 2). Many proposed "bugs" turn out
   to be out-of-scope by design.
2. The known limitations section of [`SECURITY.md`](SECURITY.md).
3. The existing issues and pull requests.

If your issue is a security vulnerability, do not file a public issue.
Follow the disclosure process in [`SECURITY.md`](SECURITY.md) instead.

## License

Tessera is licensed under the Apache License, Version 2.0
(effective with v0.11.1 on 2026-04-24). The full text is in
[`LICENSE`](LICENSE); the rationale and historical AGPL-3.0
license that applied through v0.11.0 are in
[`NOTICE`](NOTICE) and
[`LICENSE-AGPL-historical`](LICENSE-AGPL-historical) respectively.

By contributing to Tessera, you agree that your contributions
will be licensed under the Apache License, Version 2.0, the same
license as the rest of the project.

The companion [AgentMesh](https://github.com/kenithphilip/AgentMesh)
service is separately licensed under AGPL-3.0-or-later. The split
mirrors Grafana / Mattermost / Plausible: permissive on the
library, copyleft on the service. See `docs/adr/0001-license-split.md`
for the full reasoning.

## Developer Certificate of Origin (DCO)

Tessera uses the Developer Certificate of Origin (DCO) instead of
a contributor license agreement (CLA). Every commit must be signed
off by the author, certifying that they have the right to submit
the contribution under the project's license.

To sign off a commit, add `-s` (or `--signoff`) to your `git commit`
invocation:

```bash
git commit -s -m "Your commit message"
```

This appends a `Signed-off-by: Name <email>` line to the commit
message, attesting to the DCO terms reproduced below. The
sign-off is checked by CI; commits without it are rejected at
merge time.

### The Developer Certificate of Origin

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

If you have any questions about the DCO, see
[developercertificate.org](https://developercertificate.org/)
or the contributor docs of any project that uses the DCO
(Linux kernel, Docker, GitLab, Kubernetes, the CNCF projects).
