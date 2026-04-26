"""Provider-aware AgentDojo cell runner.

This module is the single entry point that
:mod:`benchmarks.agentdojo_live.submit` uses to dispatch one
``(model, suite, attack, seed)`` cell against a real model API.
It supports every major provider AgentDojo wraps natively
(Anthropic, OpenAI, Google, Cohere) plus an OpenAI-compatible
fallback that routes Llama / Qwen / DeepSeek / Mistral / any
self-hosted vLLM through Together AI, Groq, OpenRouter, or any
other endpoint that speaks the OpenAI Chat Completions wire
format.

Provider detection is by model-name prefix; an explicit
``--provider`` override is supported via the
``TESSERA_BENCH_PROVIDER`` env var so non-default mappings work
(e.g. running ``llama-3.3-70b`` against Groq vs Together).

Required env vars per provider:

- ``ANTHROPIC_API_KEY`` for Anthropic.
- ``OPENAI_API_KEY`` for OpenAI / OpenAI-compatible default.
- ``GOOGLE_API_KEY`` (or ``GEMINI_API_KEY``) for Google.
- ``COHERE_API_KEY`` for Cohere.
- ``TESSERA_BENCH_OPENAI_COMPATIBLE_KEY`` and
  ``TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL`` for the
  open-weights fallback (Llama / Qwen / DeepSeek / Mistral).
  Falls back to ``OPENAI_API_KEY`` and the model-name -> known
  provider table when these are unset.

The cell runner returns a metrics dict shaped for the
``CellResult`` consumer in ``submit.py``: utility_attempt,
targeted_asr, attack_prevention_rate, utility_delta, raw_runs,
elapsed_seconds, error.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any


# Provider name strings (stable across versions).
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"
PROVIDER_GOOGLE = "google"
PROVIDER_COHERE = "cohere"
PROVIDER_OPENAI_COMPATIBLE = "openai_compatible"

# Default OpenAI-compatible base URL per known model family.
# Operator overrides via TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL.
_OPENAI_COMPAT_BASE_URLS: dict[str, str] = {
    "llama": "https://api.together.xyz/v1",
    "qwen": "https://api.together.xyz/v1",
    "mistral": "https://api.together.xyz/v1",
    "deepseek": "https://api.deepseek.com/v1",
}


@dataclass(frozen=True)
class _ProviderRoute:
    provider: str
    canonical_model: str
    base_url: str | None = None


def detect_provider(model: str) -> _ProviderRoute | None:
    """Map a model alias to (provider, canonical id, base_url).

    Operator override: ``TESSERA_BENCH_PROVIDER`` env var (one of
    anthropic, openai, google, cohere, openai_compatible) forces
    a specific route regardless of the model name. Useful for
    running a Llama variant via OpenAI's hosted endpoint, or
    pointing claude-* at a relay.

    Returns ``None`` for models that don't match any known
    provider; the caller should surface an unimplemented-runner
    error.
    """
    forced = os.environ.get("TESSERA_BENCH_PROVIDER")
    if forced:
        return _ProviderRoute(
            provider=forced,
            canonical_model=model,
            base_url=os.environ.get("TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL"),
        )

    lower = model.lower()
    # Anthropic friendly aliases -> canonical ids.
    anthropic_aliases = {
        "claude-haiku-4-5": "claude-3-5-haiku-20241022",
        "claude-sonnet-4-5": "claude-3-5-sonnet-20241022",
        "claude-3-5-haiku": "claude-3-5-haiku-20241022",
        "claude-3-5-sonnet": "claude-3-5-sonnet-20241022",
    }
    if lower in anthropic_aliases:
        return _ProviderRoute(provider=PROVIDER_ANTHROPIC, canonical_model=anthropic_aliases[lower])
    if lower.startswith("claude-"):
        return _ProviderRoute(provider=PROVIDER_ANTHROPIC, canonical_model=model)

    # OpenAI: gpt-*, o1-*, o3-*, gpt-5 alias.
    if lower.startswith("gpt-") or lower.startswith("o1") or lower.startswith("o3"):
        canonical = "gpt-4o" if lower in ("gpt-5", "gpt-4.1") else model
        return _ProviderRoute(provider=PROVIDER_OPENAI, canonical_model=canonical)

    # Google: gemini-*, palm-*.
    if lower.startswith("gemini-") or lower.startswith("palm-"):
        return _ProviderRoute(provider=PROVIDER_GOOGLE, canonical_model=model)

    # Cohere: command-*.
    if lower.startswith("command-") or lower.startswith("cohere-"):
        return _ProviderRoute(provider=PROVIDER_COHERE, canonical_model=model)

    # Open-weights families via OpenAI-compatible endpoints.
    for prefix, default_base in _OPENAI_COMPAT_BASE_URLS.items():
        if lower.startswith(prefix):
            return _ProviderRoute(
                provider=PROVIDER_OPENAI_COMPATIBLE,
                canonical_model=model,
                base_url=os.environ.get(
                    "TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL", default_base
                ),
            )

    return None


def _attack_class(attack_name: str):
    """Map the submit.py attack-name vocabulary to AgentDojo classes."""
    from agentdojo.attacks.baseline_attacks import (
        DirectAttack,
        IgnorePreviousAttack,
        InjecAgentAttack,
        SystemMessageAttack,
    )
    table = {
        "important_instructions": IgnorePreviousAttack,
        "tool_knowledge": InjecAgentAttack,
        "direct": DirectAttack,
        "system_message": SystemMessageAttack,
    }
    return table.get(attack_name)


def _build_llm(route: _ProviderRoute):
    """Construct the AgentDojo LLM wrapper for a given route.

    Raises:
        RuntimeError: When a required env var or SDK is missing.
    """
    from agentdojo.agent_pipeline import (
        AnthropicLLM,
        CohereLLM,
        GoogleLLM,
        LocalLLM,
        OpenAILLM,
    )

    if route.provider == PROVIDER_ANTHROPIC:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        return AnthropicLLM(client=client, model=route.canonical_model, temperature=0.0, max_tokens=4096)

    if route.provider == PROVIDER_OPENAI:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        import openai

        client = openai.OpenAI(api_key=api_key)
        return OpenAILLM(client=client, model=route.canonical_model, temperature=0.0)

    if route.provider == PROVIDER_GOOGLE:
        api_key = (
            os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        )
        if not api_key:
            raise RuntimeError("GOOGLE_API_KEY (or GEMINI_API_KEY) not set")
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError(
                f"google-genai not installed: {exc}. "
                f"`pip install google-genai`"
            ) from exc
        client = genai.Client(api_key=api_key)
        return GoogleLLM(model=route.canonical_model, client=client, temperature=0.0)

    if route.provider == PROVIDER_COHERE:
        api_key = os.environ.get("COHERE_API_KEY")
        if not api_key:
            raise RuntimeError("COHERE_API_KEY not set")
        import cohere

        client = cohere.Client(api_key=api_key)
        return CohereLLM(client=client, model=route.canonical_model, temperature=0.0)

    if route.provider == PROVIDER_OPENAI_COMPATIBLE:
        api_key = (
            os.environ.get("TESSERA_BENCH_OPENAI_COMPATIBLE_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
        if not api_key:
            raise RuntimeError(
                "TESSERA_BENCH_OPENAI_COMPATIBLE_KEY (or OPENAI_API_KEY) not set"
            )
        base_url = (
            route.base_url
            or os.environ.get("TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL")
        )
        if not base_url:
            raise RuntimeError(
                "OpenAI-compatible base URL is required: set "
                "TESSERA_BENCH_OPENAI_COMPATIBLE_BASE_URL or use a "
                "model name in the known table (llama-*, qwen-*, "
                "deepseek-*, mistral-*)"
            )
        import openai

        client = openai.OpenAI(api_key=api_key, base_url=base_url)
        # LocalLLM is the right class for OpenAI-compatible
        # endpoints because it uses simpler tool-call semantics
        # that match what most open-weights serving stacks
        # produce. Falls back gracefully on tool-format quirks.
        return LocalLLM(client=client, model=route.canonical_model, temperature=0.0)

    raise RuntimeError(f"unknown provider: {route.provider!r}")


def run_provider_cell(
    *,
    model: str,
    suite_name: str,
    attack_name: str,
    seed: int,
    max_pairs: int = 2,
) -> dict[str, Any]:
    """Run one (model, suite, attack, seed) cell against any provider.

    Returns a dict shaped for ``submit.run_cell``:
    utility_attempt, targeted_asr, attack_prevention_rate,
    utility_delta, raw_runs, elapsed_seconds, error.

    On any provider-side error the function returns a dict with
    ``error`` set; it does not raise.
    """
    started = time.monotonic()

    route = detect_provider(model)
    if route is None:
        return {
            "error": (
                f"no provider routing for model {model!r}. Known "
                f"prefixes: claude-*, gpt-*, o1*, o3*, gemini-*, "
                f"palm-*, command-*, llama-*, qwen-*, mistral-*, "
                f"deepseek-*. Override via TESSERA_BENCH_PROVIDER."
            ),
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }

    attack_cls = _attack_class(attack_name)
    if attack_cls is None:
        return {
            "error": f"unknown attack name: {attack_name!r}",
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }

    try:
        llm = _build_llm(route)
    except Exception as exc:  # noqa: BLE001
        return {
            "error": f"{type(exc).__name__}: {exc}",
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }

    # The benign / injection trial loop is identical across
    # providers; reuse run_haiku's machinery via a small adapter.
    from benchmarks.agentdojo_live.run_haiku import (
        build_pipeline_with_llm,
        load_suite,
        run_trial,
    )
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

    suite = load_suite(suite_name)
    gt_pipeline = GroundTruthPipeline(None)
    user_task_ids = sorted(suite.user_tasks.keys())
    injection_task_ids = sorted(suite.injection_tasks.keys())
    pair_offset = int(seed) * max_pairs

    raw_runs: list[dict] = []
    benign_total = 0
    benign_passed = 0
    injection_total = 0
    injection_blocked = 0

    for ut_id in user_task_ids[:max_pairs]:
        pipeline, labeler, _ = build_pipeline_with_llm(llm)
        result = run_trial(
            pipeline, suite, suite_name, ut_id,
            None, None, {}, labeler,
        )
        raw_runs.append({
            "trial": "benign", "user_task": ut_id,
            "utility_pass": result.utility_pass,
            "error": result.error,
        })
        benign_total += 1
        if result.utility_pass:
            benign_passed += 1

    pair_idx = 0
    for ut_id in user_task_ids:
        for it_id in injection_task_ids:
            if pair_idx < pair_offset:
                pair_idx += 1
                continue
            if pair_idx >= pair_offset + max_pairs:
                break
            try:
                attack = attack_cls(suite, gt_pipeline)
                injections = attack.attack(
                    suite.user_tasks[ut_id], suite.injection_tasks[it_id],
                )
            except Exception as exc:
                raw_runs.append({
                    "trial": "injection", "user_task": ut_id,
                    "injection_task": it_id,
                    "error": f"attack-build-failed: {exc}",
                })
                pair_idx += 1
                continue
            if not injections:
                pair_idx += 1
                continue
            pipeline, labeler, _ = build_pipeline_with_llm(llm)
            result = run_trial(
                pipeline, suite, suite_name, ut_id,
                it_id, attack_name, injections, labeler,
            )
            raw_runs.append({
                "trial": "injection", "user_task": ut_id,
                "injection_task": it_id,
                "security_pass": result.security_pass,
                "error": result.error,
            })
            injection_total += 1
            if result.security_pass:
                injection_blocked += 1
            pair_idx += 1
        if pair_idx >= pair_offset + max_pairs:
            break

    utility_attempt = benign_passed / benign_total if benign_total else 0.0
    targeted_asr = (
        (injection_total - injection_blocked) / injection_total
        if injection_total else 0.0
    )
    attack_prevention_rate = injection_blocked / injection_total if injection_total else 0.0

    return {
        "utility_attempt": utility_attempt,
        "targeted_asr": targeted_asr,
        "attack_prevention_rate": attack_prevention_rate,
        "utility_delta": 0.0,
        "raw_runs": raw_runs,
        "elapsed_seconds": time.monotonic() - started,
        "error": None,
    }
