# AgentMesh + benchmarks: scope clarification

## Question

Should the multi-provider AgentDojo dispatcher in
`benchmarks/agentdojo_live/` (Tessera) also live in AgentMesh,
so AgentMesh deployments can run benchmarks self-contained?

## Short answer

No. The dispatcher belongs in Tessera. AgentMesh has a different
purpose for its existing benchmark + adapter footprint, and the
two should not be merged.

## What AgentMesh has today

| Path | Purpose | Lines |
| --- | --- | --- |
| `~/AgentMesh/src/agentmesh/sdk/agentdojo.py` | Reference *adapter* providing `MeshToolLabeler` and `MeshToolGuard` pipeline elements that delegate security decisions to the AgentMesh proxy via HTTP. Drop-in replacement for `tessera.adapters.agentdojo`. | 200 |
| `~/AgentMesh/benchmarks/bench_proxy.py` | Microbenchmark of the proxy itself: per-endpoint p50 / p95 / p99 / max latency across three feature configurations (Minimal / Default / Full). FastAPI TestClient in-process, excludes TCP roundtrip. | 250 |

Neither is an evaluator harness. The first is a transport
shim; the second measures proxy overhead, not model defense
quality.

## What Tessera has today

| Path | Purpose |
| --- | --- |
| `benchmarks/agentdojo_live/submit.py` | Multi-provider matrix dispatcher. Routes by model-name prefix to per-provider runners. |
| `benchmarks/agentdojo_live/runners.py` | Provider detection + the canonical `run_provider_cell` entry point. |
| `benchmarks/agentdojo_live/run_haiku.py` | Anthropic standalone runner. |
| `benchmarks/agentdojo_live/run_openai.py` | OpenAI standalone runner. |
| `benchmarks/agentdojo_live/run_gemini.py` | Google standalone runner. |
| `benchmarks/agentdojo_live/run_cohere.py` | Cohere standalone runner. |
| `benchmarks/agentdojo_live/run_mistral.py` | OpenAI-compatible fallback (Llama / Qwen / DeepSeek / Mistral via Together / Groq / OpenRouter / DeepInfra / vLLM). |

These call AgentDojo directly, route to provider SDKs, run real
trials, and emit the JSON consumed by the paired-scorecard
emitter. They live in Tessera because Tessera owns the *defense*
under evaluation; the benchmark is how Tessera's primitives are
graded.

## Why the split is deliberate

Three reasons.

1. **Test target identity.** AgentDojo measures Tessera's
   defense quality (utility-attempt, targeted-ASR, attack
   prevention rate). The system under test is the
   `tessera.adapters.agentdojo` defense, not the AgentMesh
   transport. Putting the harness in AgentMesh would conflate
   "is the proxy fast" with "does the proxy block injections".
2. **Dependency direction.** Tessera is the library; AgentMesh
   depends on Tessera (`tessera.policy`, `tessera.taint`,
   `tessera.delegation`). If the harness lived in AgentMesh,
   running the Tessera scorecard would force a transitive
   AgentMesh dependency on every Tessera consumer. The current
   direction (Tessera benchmarks Tessera; AgentMesh benchmarks
   AgentMesh's proxy) keeps the import graph clean.
3. **License posture.** Tessera library is Apache-2.0
   ([ADR-0001](../adr/0001-license-split.md)); AgentMesh
   service is AGPL-3.0-or-later. The benchmark output (a signed
   in-toto attestation) is a published artifact attached to the
   Tessera library; it must not pull AGPL into a consumer's
   dependency closure to reproduce.

## When AgentMesh would gain a benchmark harness

Only if AgentMesh starts shipping a defense that Tessera does
not (e.g. a proxy-only feature like rate-limit-aware risk
forecasting that has no Tessera-library equivalent). Even then
it would be a separate suite measuring that proxy-only feature,
not a port of the AgentDojo evaluator.

The closest plausible candidate today is the AgentMesh proxy's
end-to-end latency budget under defense load. That is what
`bench_proxy.py` already measures; no new harness needed.

## Future work (low priority)

If a downstream consumer asks for "run the AgentDojo scorecard
through the AgentMesh proxy as transport", the integration is
trivial:

```python
# pseudocode
from agentmesh.sdk.agentdojo import MeshToolLabeler, MeshToolGuard
from benchmarks.agentdojo_live.run_haiku import run_trial
# build_pipeline_with_llm but with AgentMesh proxy elements
# instead of in-process tessera.adapters.agentdojo
```

Track interest in <https://github.com/kenithphilip/Tessera/issues>
under `integration:agentmesh-as-transport`. No active work
planned.

## References

- `~/AgentMesh/src/agentmesh/sdk/agentdojo.py` (transport shim)
- `~/AgentMesh/benchmarks/bench_proxy.py` (proxy microbench)
- `benchmarks/agentdojo_live/runners.py` (Tessera dispatcher)
- [ADR-0001](../adr/0001-license-split.md) (license split)
- [ADR-0005](../adr/0005-rust-data-plane.md) (Rust workspace as
  the production data plane; AgentMesh proxy is the reference
  SDK / dev surface, not the bench target)
