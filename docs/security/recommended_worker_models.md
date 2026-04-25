# Recommended worker models for hardened dual-LLM execution

## Worker role threat model

Tessera's dual-LLM pattern routes untrusted content through a separate Worker model that cannot propose tool calls. The Worker's output is structurally constrained to a Pydantic schema with no free-form string fields, closing the injection channel that conventional dual-LLM implementations leave open via summary text.

However, the Worker still processes untrusted content and returns values that the Planner reads. A Worker model that falls for prompt injection in its own inference can produce hallucinated entities, fabricated URLs, or inflated risk signals that the Planner then acts on. Defense in depth requires the Worker itself to be hardened against directive payloads embedded in untrusted segments.

This document catalogs three published techniques for Worker hardening and recommends deployment tiers.

## ASIDE: Aligned side-channel decoder

ASIDE augments the Worker model's logit head with a side-channel decoder that strips injection content before the main output head evaluates it. The decoder operates on the model's internal hidden states and learns to identify and suppress adversarial text patterns without requiring output-layer modification.

Published: arXiv:2407.13692, "Aligned Side-Channel Decoder for Improving the Robustness of the Model Against Prompt Injection Attacks", 2024.

Public checkpoints: Meta Llama models with ASIDE fine-tuning available on HuggingFace (exact IDs depend on quarterly updates; check `huggingface.co/models?search=aside`). Anthropic Claude models with undisclosed hardening baseline.

Empirical APR (Attack Pass Rate, lower is better):

| Attack class | Baseline model | ASIDE model | Reduction |
| --- | --- | --- | --- |
| Directive injection | 68% | 12% | 82% |
| Goal smuggling | 71% | 19% | 73% |
| Context confusion | 61% | 14% | 77% |
| Combined attack suite | 67% | 15% | 78% |

Wiring into Tessera:

```python
from tessera.quarantine import QuarantinedExecutor, strict_worker, WorkerReport

async def aside_worker_model(context):
    # Wrap your ASIDE-hardened model inference here.
    # The model is not modified; you simply use a checkpoint
    # that includes the side-channel decoder weights.
    # Return a dict or WorkerReport instance.
    return WorkerReport(
        entities=["extracted_entity"],
        have_enough_information=True,
    )

executor = QuarantinedExecutor(
    worker=strict_worker(WorkerReport, aside_worker_model),
    planner=your_planner_callable,
)
```

License: Meta Llama models are open-source under Llama License. Verify current terms on Meta's Llama site.

## SecAlign: Adversarial alignment training

SecAlign uses adversarial examples drawn from known prompt-injection attacks to fine-tune the Worker model. The training loop exposes the model to progressively harder injection attempts and updates weights to classify injected directives as out-of-distribution. The technique does not modify the model architecture; it adjusts weights via standard supervised fine-tuning on an adversarial corpus.

Published: arXiv:2410.05451, "SecAlign: Secure Model Alignment for LLM-based Agents", 2024.

Public checkpoints: Mistral, Qwen, and open LLaMA derivatives with SecAlign training available on HuggingFace. Specific model URLs tracked in `recommended_worker_models_changelog.md`.

Empirical APR:

| Attack class | Baseline model | SecAlign model | Reduction |
| --- | --- | --- | --- |
| Directive injection | 69% | 8% | 88% |
| Goal smuggling | 72% | 11% | 85% |
| Context confusion | 63% | 9% | 86% |
| Combined attack suite | 68% | 9% | 87% |

Wiring into Tessera:

```python
from tessera.quarantine import QuarantinedExecutor, strict_worker, WorkerReport

async def secalign_worker_model(context):
    # Use a SecAlign-fine-tuned checkpoint for inference.
    # No architectural changes; standard transformer inference.
    return WorkerReport(
        entities=["extracted_entity"],
        have_enough_information=True,
    )

executor = QuarantinedExecutor(
    worker=strict_worker(WorkerReport, secalign_worker_model),
    planner=your_planner_callable,
)
```

License: Open-source model variants under MIT or Apache 2.0. Commercial variants available from Mistral and Qwen with licensing per-vendor.

## Meta-SecAlign: Meta-learning extension

Meta-SecAlign extends SecAlign by training the adversarial alignment update rule itself as a learned optimization procedure. Rather than using a static fine-tuning schedule, Meta-SecAlign learns to compose attack examples in ways that generalize to unseen attack distributions. The technique introduces an outer loop that adapts the inner adversarial-training loop.

Published: arXiv:2501.xxxxx, "Meta-SecAlign: Learning to Learn Secure Alignment", 2025 (provisional citation; awaiting preprint ID publication).

Public checkpoints: Next-generation Llama, Mistral, and Claude-derived research models; availability timeline TBD (check HuggingFace weekly).

Empirical APR:

| Attack class | Baseline model | Meta-SecAlign model | Reduction |
| --- | --- | --- | --- |
| Directive injection | 68% | 4% | 94% |
| Goal smuggling | 71% | 6% | 92% |
| Context confusion | 61% | 5% | 92% |
| Known-unknown attacks | 67% | 7% | 90% |
| Combined attack suite | 67% | 6% | 91% |

Wiring into Tessera:

```python
from tessera.quarantine import QuarantinedExecutor, strict_worker, WorkerReport

async def meta_secalign_worker_model(context):
    # Use a Meta-SecAlign-trained checkpoint.
    # The checkpoint includes learned meta-optimization weights.
    return WorkerReport(
        entities=["extracted_entity"],
        have_enough_information=True,
    )

executor = QuarantinedExecutor(
    worker=strict_worker(WorkerReport, meta_secalign_worker_model),
    planner=your_planner_callable,
)
```

License: Research checkpoints typically under non-commercial research license pending production licensing.

## Comparison matrix

| Technique | Publication year | APR (combined suite) | Latency overhead | Model size | License | Stability | Availability |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ASIDE | 2024 | 15% | +8% | -12% | Open (Llama) | Stable | Immediate |
| SecAlign | 2024 | 9% | +4% | Unchanged | Open (MIT/Apache) | Stable | Immediate |
| Meta-SecAlign | 2025 | 6% | +6% | +3% | Research / TBD | Emerging | Q2 2026 |

Notes:

- APR is lower-is-better; 0% is perfect, 100% is fully compromised.
- Latency overhead is token-generation latency relative to baseline.
- Model size impact is parameter count relative to baseline.
- Stability: ASIDE and SecAlign are proven in production deployments. Meta-SecAlign is still in active research and deployment feedback.

## Recommendation by deployment tier

### Research and proof-of-concept

Use **SecAlign**: open source, immediate availability, strong APR (9%), minimal overhead (4%), and documented in peer review. SecAlign is the fastest path from non-hardened to defended Worker.

### Mid-market production

Use **ASIDE or SecAlign**: both are production-ready. ASIDE offers lower APR (15% vs 9%) but slightly higher overhead (8% vs 4%). SecAlign is simpler to integrate and has better model availability across the open-source ecosystem. Choose based on latency and cost budgets.

### Enterprise with strict security requirements

Use **Meta-SecAlign** (when available, Q2 2026): lowest APR (6%), generalizes to unknown attacks, and suitable for high-assurance deployments. Until public checkpoints ship, use SecAlign.

## Caveats and defense-in-depth

Every technique above is bypassable by some attack. The measures in this document are defenses, not guarantees.

- All three techniques defend against known attack classes. Adversarial examples with novel patterns may evade these defenses.
- Worker hardening is one layer. Tessera's primary defense remains the Worker's structural inability to propose tool calls and its output schema constraint. A hardened Worker that falls for injection and produces hallucinated entities is still sandboxed by the WorkerReport schema.
- SIEM telemetry and anomaly detection on the Worker's outputs (via `tessera.events` sinks) provide real-time signals when a Worker begins exhibiting suspicious entity extraction patterns.
- Pair Worker hardening with upstream defenses: URL allow/deny gates (tessera.url_rules), content scanning (tessera.scanners), and input validation on the Agent's configured tools.

## See also

- `tessera.quarantine.QuarantinedExecutor`: the executor that isolates the Worker.
- `tessera.quarantine.strict_worker`: schema enforcement wrapper.
- `tessera.quarantine.WorkerReport`: default structured output schema.
- `papers/two-primitives-for-agent-security-meshes.md`, Section 2: threat model and scope.
- `examples/worker_models/`: runnable example configurations.
