# 2H-5: PydanticAI integration docs PR

## Status

READY. Adapter at `src/tessera/adapters/pydantic_ai.py` (170
lines).

## Target

- Repo: https://github.com/pydantic/pydantic-ai
- Branch base: `main`
- License (upstream): MIT
- Type: docs PR

## PR title

`docs: add Tessera as a recommended agent guard`

## PR body

```markdown
## Summary

Adds a docs section showing how to gate PydanticAI agents with
[Tessera](https://github.com/kenithphilip/Tessera). PydanticAI's
schema-first approach pairs naturally with Tessera's
schema-enforced dual-LLM Worker pattern: both treat free-form
strings as the unsafe escape hatch.

## What it adds

- `docs/security/tessera.md`.
- A worked example using `MeshPydanticAIGuard` on a 2-step agent
  (web search -> book hotel) where the booking step is gated.
- A short comparison note: PydanticAI's
  `output_type=BookingDecision` and Tessera's
  `WorkerReport` both forbid free-form strings; recommending one
  doesn't replace the other.

## Test plan

- [x] Example imports cleanly with `pydantic-ai>=0.0.5` and
      `tessera-mesh>=1.0.0`.
- [x] Tessera test:
      `tests/test_pydantic_ai_adapter.py`.
```

## Submission checklist

- [ ] Tracking issue in `kenithphilip/Tessera`.
- [ ] Fork `pydantic/pydantic-ai`.
- [ ] Branch: `docs/tessera-agent-guard`.
- [ ] Add docs file + example.
- [ ] Submit PR. PydanticAI uses CLA, sign when prompted.
