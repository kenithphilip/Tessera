# OpenSSF #project-lifecycle Slack post

This is the pre-written solicitation message for the OpenSSF
`#project-lifecycle` Slack channel. The post-as-an-AI tool can't
authenticate to Slack on the maintainer's behalf, so this file
exists so the maintainer can paste it verbatim (or edit) when
ready.

OpenSSF Slack: https://slack.openssf.org/  
Channel: `#project-lifecycle`

---

```
Hi everyone, I'm Kenith Philip, sole maintainer of Tessera
(https://github.com/kenithphilip/Tessera). Looking for a TAC
member willing to sponsor a sandbox-tier application.

Tessera is an Apache-2.0 reference implementation of two
security primitives for LLM agent systems: signed trust labels
on context segments with taint-tracking at the tool-call
boundary, and schema-enforced dual-LLM execution. v1.0 GA
shipped 2026-04-25.

The OpenSSF alignment is direct: the MCP manifest signing
pipeline (tessera.mcp.manifest) and the registry mirror
(tessera.mcp.registry_mirror) consume Sigstore via
sigstore-python. The threat-model coverage maps to MITRE
ATLAS, NIST AI 600-1, ISO/IEC 42001 Annex A, CSA AICM 1.0,
EU AI Act Articles 9/12/14/15, OWASP Agentic ASI 1-10, and
NIST CSF.

Project state:
- 50k+ Python LOC + 21k Rust LOC across 11 crates
- 2046 passing tests, 17 environmental skips
- 1091-payload red-team corpus (~934 unique after dedup)
- Apache-2.0 with DCO sign-off (no CLA)
- Single maintainer (which is one of the reasons for filing
  now: sandbox tier creates the institutional home that lets
  us absorb additional maintainers under governance)

Filing materials are pre-drafted at:
https://github.com/kenithphilip/Tessera/blob/main/docs/governance/openssf_sandbox_application.md

Tracking issue:
https://github.com/kenithphilip/Tessera/issues/19

Happy to answer questions in-thread or on a call. Thanks!
```

---

## After posting

1. Watch the thread for TAC member volunteers (typically responds within 24-72 hours).
2. Once you have a sponsor, submit the form at https://openssf.org/projects/ with the application content from `openssf_sandbox_application.md`.
3. Reference the sponsor's name in the application's "Sponsor" field.
4. Update issue [#19](https://github.com/kenithphilip/Tessera/issues/19) with the application URL.
