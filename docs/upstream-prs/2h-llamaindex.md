# 2H-4: LlamaIndex integration docs PR

## Status

READY. Adapter at `src/tessera/adapters/llamaindex.py` (181 lines).

## Target

- Repo: https://github.com/run-llama/llama_index
- Branch base: `main`
- License (upstream): MIT
- Type: docs PR

## PR title

`docs: add Tessera as a recommended agent guard`

## PR body

```markdown
## Summary

Adds a section to the LlamaIndex security/agents docs showing
how to wire [Tessera](https://github.com/kenithphilip/Tessera)
as an agent guard for `AgentRunner` and the new
`FunctionCallingAgent`.

## Why LlamaIndex specifically

LlamaIndex agents are commonly fed RAG-retrieved context, which
is exactly the surface most affected by indirect prompt
injection (the canonical AAILA / OWASP Agentic ASI01 vector).
Tessera's segment-level provenance gives the agent a hard
floor: tool calls denied when any retrieved chunk has UNTRUSTED
trust level.

## What it adds

- `docs/security/tessera.md`.
- A worked example wiring `MeshLlamaIndexHandler` into a
  RAG-backed agent.
- A note on the configuration hooks in
  `tessera/adapters/llamaindex.py` (LlamaIndex callback model
  vs. AgentRunner's tool dispatch).

## Test plan

- [x] Example imports cleanly with `llama-index-core>=0.10` and
      `tessera-mesh>=1.0.0`.
- [x] Tessera test:
      `tests/test_llamaindex_adapter.py`.
```

## Submission checklist

- [ ] Tracking issue in `kenithphilip/Tessera`.
- [ ] Fork `run-llama/llama_index`.
- [ ] Branch: `docs/tessera-agent-guard`.
- [ ] Add docs file + example.
- [ ] Submit PR. LlamaIndex uses DCO sign-off, so `git commit -s`
      every commit.
