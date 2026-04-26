# AgentDojo real-model benchmark: runbook + honest gap report

This is the runbook for converting the placeholder paired
scorecards (`docs/scorecard/static/paired-*.intoto.jsonl`,
which currently contain `"benchmarks": {}`) into signed
attestations carrying real measured numbers.

## Honest gap: submit.py is not wired to real models

`benchmarks/agentdojo_live/submit.py` is the matrix +
aggregator. Its `run_cell` function is **not** dispatching to a
model even with an API key:

```python
# benchmarks/agentdojo_live/submit.py:187
# Real dispatch is wired in Phase 2 wave 2A; today we record a
# SKIP so the driver verifies the matrix shape without forcing
# API keys at v0.12.
return CellResult(
    cell=cell,
    error="real-trial dispatch not wired until Phase 2 wave 2A",
    elapsed_seconds=time.monotonic() - started,
)
```

Wave 2A from the v0.12-to-v1.0 plan was supposed to land that
dispatch. It did not. So `python -m benchmarks.agentdojo_live.submit`
without `--dry-run` returns SKIP errors for every cell.

**What does work today**: `run_haiku.py`, `run_mistral.py`, and
`run_baseline.py` are real, working harnesses. Each takes its
own `--suite` flag, calls the real model API, and writes a JSON
report. They're the path to real numbers right now.

## What you need

| Requirement | Why |
| --- | --- |
| `pip install -e '.[dev,agentdojo]'` | Pulls the `agentdojo>=1.2` package the runners import. |
| `ANTHROPIC_API_KEY` env var | For Claude Haiku / Sonnet runs. |
| `OPENAI_API_KEY` env var | If extending to GPT-4 baseline. |
| 30-90 minutes of wall-clock | A full 4-suite run for one model is ~20-40 min depending on the suite. |
| Real API spend | Roughly $5-$30 per full 4-suite Claude run, dependent on retry policy. |

## Step 1: smallest possible real run (claude-3-5-haiku, travel suite only)

This proves the harness works end-to-end against a real API
without committing to the full matrix.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd /path/to/Tessera

python -m benchmarks.agentdojo_live.run_haiku \
    --suite travel \
    --max-injection-pairs 2 \
    --output benchmarks/agentdojo_live/results_haiku_smoke.json
```

Expected runtime: 3-5 minutes. Expected output: a JSON file
with per-(user_task, injection_task, attack) outcomes plus a
summary with utility-attempt and APR per suite.

## Step 2: real numbers for one model across all four suites

This is what populates the
`paired-claude-sonnet-4.5.intoto.jsonl` scorecard with real
data.

```bash
python -m benchmarks.agentdojo_live.run_haiku \
    --suite banking slack travel workspace \
    --output benchmarks/agentdojo_live/results_haiku_v1.0.json

# Optional: for sonnet-4.5 paired scorecard, change the model
# and re-run. (You'll need to also accept that the
# upstream Anthropic API recognises that model id.)
```

Expected runtime: 60-90 minutes. Expected output: a JSON file
with all four suites' results.

## Step 3: feed the results into the paired scorecard

Today the paired scorecard emitter is at
`tessera/evaluate/scorecard/emitter.py`; it expects a
`benchmarks` dict argument that's currently being passed `{}`.
Once you have the JSON from Step 2, the missing one-line
wiring in the emitter is:

```python
import json
benchmarks_input = json.loads(
    open("benchmarks/agentdojo_live/results_haiku_v1.0.json").read()
)
emit_paired_scorecard(
    paired_model="claude-sonnet-4.5",
    benchmarks=benchmarks_input,  # <-- was {} for the placeholder
    out="docs/scorecard/static/paired-claude-sonnet-4.5.intoto.jsonl",
    sign="hmac",  # or "sigstore"
)
```

## What we still owe

To make `python -m benchmarks.agentdojo_live.submit ...`
actually call models (the unified driver the plan called for),
we need:

1. A `submit_dispatcher.py` that maps `cell.model` to a
   per-model runner module (e.g. `claude-3-5-haiku` ->
   `run_haiku`, `claude-sonnet-4.5` -> a new
   `run_sonnet.py` that doesn't exist yet, etc.).
2. A subprocess wrapper or in-process import that runs one
   trial and returns a `CellResult` shaped object.
3. The emit-scorecard CLI gaining a `--from-runs <jsonl>`
   flag so the scorecard JSON pulls real numbers from disk
   rather than `{}`.

These three pieces are the actual Wave 2A work. They're a
~half-day of focused engineering, not a deferred-forever item.

## Cost / risk notes

- AgentDojo trials retry aggressively when the model produces
  malformed tool-call output. With Claude 3.5 Haiku that's
  maybe 3-5 retries per task, ~$0.01 each. With Claude Sonnet
  4.5 that's higher per-token but fewer retries.
- The injection prompts are designed to elicit unsafe
  behaviour. A real run will produce events in
  `tessera.events` that look like attempted exploits. Filter
  them out of any production SIEM ingest before running.
- For the public scorecard, the run should be reproducible
  (record the model id, the AgentDojo commit hash, and the
  Tessera commit hash in the scorecard's `claims` block).
