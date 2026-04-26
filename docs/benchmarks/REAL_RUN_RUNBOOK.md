# AgentDojo real-model benchmark: runbook

This is the runbook for converting the placeholder paired
scorecards (`docs/scorecard/static/paired-*.intoto.jsonl`,
which currently contain `"benchmarks": {}`) into signed
attestations carrying real measured numbers.

## Quick smoke (no API key required)

Verify the matrix dispatcher and Tessera defense pipeline shape
without spending API credits:

```bash
make smoke
```

Equivalent to `python -m benchmarks.agentdojo_live.submit
--models claude-haiku-4-5 --suites travel
--attacks important_instructions --seeds 0 --max-pairs 1
--dry-run`. Exits zero with deterministic placeholder metrics so
you can wire CI without exposing keys.

## What changed

`benchmarks/agentdojo_live/submit.py:run_cell` now dispatches
through `benchmarks.agentdojo_live.runners.run_provider_cell`,
which routes by model-name prefix to the per-provider standalone
runners (`run_haiku.py`, `run_openai.py`, `run_gemini.py`,
`run_cohere.py`, plus an OpenAI-compatible fallback for Llama /
Qwen / DeepSeek / Mistral via Together / Groq / OpenRouter /
DeepInfra / vLLM). The earlier "real-trial dispatch not wired"
gap closed in commit `3dccb97`.

Each per-provider runner is also reachable directly for one-off
operator harnesses without the matrix overhead; see
`benchmarks/agentdojo_live/run_*.py --help`.

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

make smoke-real
```

Equivalent to `python3 -m benchmarks.agentdojo_live.run_haiku
--suite travel --max-injection-pairs 1
--output benchmarks/agentdojo_live/results_haiku_smoke.json`.
Bump `--max-injection-pairs` past 1 by editing the Makefile
target if you want a wider sweep at smoke time.

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

## What still needs polish

The dispatcher (item-2/3/4 of the post-v1.0 plan) closed the
"submit.py doesn't dispatch" gap. Three smaller follow-ups
remain:

1. The emit-scorecard CLI still hardcodes `benchmarks={}`. It
   needs a `--from-runs <results.json>` flag so scorecards pull
   real measured numbers from a per-provider runner JSON rather
   than inheriting the placeholder.
2. `run_sonnet.py` is not a separate module; sonnet runs go
   through `run_haiku.py` with `--model claude-sonnet-4-5`. If
   sonnet ever needs sonnet-specific quirks, mirror the
   pattern from `run_openai.py`.
3. The Real Numbers Action ([RNA](#) ticket TBD) needs to land
   the run from Step 2 into `paired-claude-sonnet-4.5.intoto.jsonl`
   with the new flag, then re-sign.

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
