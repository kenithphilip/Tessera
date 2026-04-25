# 2H-3: CrewAI integration docs PR

## Status

PARTIAL. Adapter exists at `src/tessera/adapters/crewai.py` (131
lines, smaller than the LangChain one). Before opening the PR
the adapter needs a worked example of multi-agent crew gating
because CrewAI's flow is agent-to-agent, not callback-driven.

## Target

- Repo: https://github.com/crewAIInc/crewAI
- Branch base: `main`
- License (upstream): MIT
- Type: docs PR

## PR title

`docs: add Tessera tool-call gating for crew agents`

## PR body

```markdown
## Summary

Adds a section to the CrewAI docs showing how to gate tool calls
in multi-agent crews with
[Tessera](https://github.com/kenithphilip/Tessera). CrewAI's
agent-to-agent flow is one of the canonical multi-hop scenarios
where indirect prompt injection compounds across delegations;
Tessera's per-segment provenance gives crews a built-in defence
without a per-tool wrapper.

## What it adds

- `docs/integrations/tessera.md` with a worked 2-agent crew
  example (researcher fetches web pages, planner books based on
  research). The booking tool is gated via Tessera so the planner
  cannot be tricked into a transfer when a web page contains a
  prompt-injection payload.
- A CrewAI test config under `examples/security/`.

## What's still TODO before submit

- [ ] Write the multi-agent example end-to-end.
- [ ] Verify it runs against `crewai>=0.50` (the dep pin in
      `tessera[crewai]`).
- [ ] Capture a short before/after demo (with vs without the
      Tessera gate).
```

## Submission checklist

- [ ] Finish the multi-agent example.
- [ ] Tracking issue in `kenithphilip/Tessera`.
- [ ] Fork `crewAIInc/crewAI`.
- [ ] Branch: `docs/tessera-tool-call-gating`.
- [ ] Submit PR; CrewAI also uses CLA-bot.
