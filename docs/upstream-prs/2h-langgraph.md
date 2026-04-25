# 2H-2: LangGraph integration docs PR

## Status

READY. Adapter exists at `src/tessera/adapters/langgraph.py`
(168 lines).

## Target

- Repo: https://github.com/langchain-ai/langgraph
- Branch base: `main`
- License (upstream): MIT
- Type: docs PR

## PR title

`docs: add Tessera as a recommended StateGraph guard`

## PR body

```markdown
## Summary

Adds a section to the LangGraph "Patterns" docs showing how to
gate tool nodes with [Tessera](https://github.com/kenithphilip/Tessera).
LangGraph's StateGraph model fits Tessera's per-node Context
boundaries cleanly: each tool node call evaluates against the
joined min_trust of segments produced by upstream nodes.

## Why LangGraph specifically

Multi-node graphs amplify indirect prompt injection: an
attacker-controlled output from node A can flow into a sensitive
tool call at node B, and the developer has to reason about the
whole DAG to know which boundaries need a guard. Tessera's
taint-tracking does that math automatically: if any upstream
segment is UNTRUSTED, the next sensitive tool call denies.

## What it adds

- `docs/patterns/tool-call-gating-with-tessera.md`.
- A worked example at `examples/tessera-guard.py` showing a
  3-node graph (web fetch -> summarize -> book hotel) where the
  book_hotel node is gated.

## Test plan

- [x] Example imports cleanly with `langgraph>=0.2` and
      `tessera-mesh>=1.0.0`.
- [x] Tessera test:
      `tests/test_langgraph_adapter.py::test_state_graph_gating`.
```

## Submission checklist

- [ ] Tracking issue in `kenithphilip/Tessera`.
- [ ] Fork upstream.
- [ ] Branch: `docs/tessera-state-graph-guard`.
- [ ] Add docs file + example.
- [ ] Submit PR; sign CLA when prompted.
