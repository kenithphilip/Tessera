# 2H-1: LangChain integration docs PR

## Status

READY. Adapter exists at `src/tessera/adapters/langchain.py` (287
lines, callback-handler pattern modelled on LangKit's). License is
Apache-2.0; no collision with LangChain's MIT.

## Target

- Repo: https://github.com/langchain-ai/langchain
- Branch base: `master`
- License (upstream): MIT
- Type: docs PR (no code changes upstream)

## PR title

`docs(security): add Tessera as a recommended security callback`

## PR body

```markdown
## Summary

Adds a short section to the LangChain security/integrations docs
recommending [Tessera](https://github.com/kenithphilip/Tessera) as
a tool-call gating callback for agents that read untrusted
context (web pages, MCP server outputs, retrieved documents).

## Why this is in scope for LangChain docs

The OWASP Agentic ASI top-ten (ASI01 prompt injection, ASI03
sensitive-information disclosure, ASI09 sandbox escape) all map
to the boundary the Tessera callback gates: tool calls whose
arguments may have come from low-trust segments. LangChain users
hitting these issues have asked in
github.com/langchain-ai/langchain/issues for a recommended pattern.

## What it adds

- One short section under `docs/integrations/callbacks/` titled
  "Tessera (taint-tracking + tool-call gating)".
- A 30-line example showing a `TesseraCallbackHandler` instance
  passed via `callbacks=[...]` on `AgentExecutor`.
- A link to the Tessera invariants document so reviewers can
  inspect the security model before recommending it.

## What it does NOT add

- No new dependency in LangChain itself. Tessera is installed by
  the user via `pip install tessera-mesh[langchain]`.
- No change to LangChain's API surface.

## Test plan

- [x] Example code in the docs imports cleanly with
      `langchain-core>=0.2` and `tessera-mesh>=1.0.0`.
- [x] Integration tested in
      `tessera/tests/test_langchain_integration.py`.
- [ ] Docs preview rendered locally with `make docs_build`.
```

## Submission checklist

- [ ] Open a tracking issue in `kenithphilip/Tessera`.
- [ ] Fork `langchain-ai/langchain`.
- [ ] Branch: `docs/recommend-tessera-callback`.
- [ ] Add file `docs/integrations/callbacks/tessera.mdx` (or `.md`,
      check current convention).
- [ ] Submit PR with the body above. LangChain uses CLA-bot, not
      DCO; sign once via the bot when prompted.
