"""Live AgentDojo evaluation with Cohere Command models.

Companion to ``run_haiku.py``, ``run_openai.py``, ``run_gemini.py``.
Same trial machinery, same Tessera labeler/guard wiring, same JSON
output schema; only the LLM client differs (``cohere.Client`` +
AgentDojo's ``CohereLLM``).

The ``runners.py:run_provider_cell`` dispatcher already routes
``command-*`` / ``cohere-*`` model names through this code path; the
standalone CLI here gives operators a one-off harness without the
matrix overhead.

Quirks compared to Anthropic:
- Cohere v2 SDK (``cohere>=5.0``) standardised on OpenAI-shaped tool
  calls; tool-call format quirks are minimal vs older versions.
- ``command-r7b-12-2024`` is the fastest tool-capable model for
  smoke tests; ``command-r-plus-08-2024`` is the production
  recommendation.

Usage::

    COHERE_API_KEY=... python -m benchmarks.agentdojo_live.run_cohere
    COHERE_API_KEY=... python -m benchmarks.agentdojo_live.run_cohere \\
        --suite travel --max-injection-pairs 2 --model command-r7b-12-2024
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from agentdojo.agent_pipeline import CohereLLM
from agentdojo.attacks.baseline_attacks import (
    DirectAttack,
    IgnorePreviousAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)

from benchmarks.agentdojo_live.run_haiku import (
    LiveReport,
    build_pipeline_with_llm,
    load_suite,
    run_trial,
)


def _build_cohere_client(api_key: str):
    """Construct a ``cohere.Client``. Imported lazily because
    ``cohere`` is an optional dependency."""
    try:
        import cohere
    except ImportError as exc:
        raise RuntimeError(
            f"cohere not installed: {exc}. Install with: pip install 'cohere>=5.0'"
        ) from exc
    return cohere.Client(api_key=api_key)


def build_pipeline(client, model: str):
    """Cohere-specific convenience wrapper. Multi-provider callers
    should construct a ``CohereLLM`` themselves and pass it to
    :func:`build_pipeline_with_llm`."""
    llm = CohereLLM(client=client, model=model, temperature=0.0)
    return build_pipeline_with_llm(llm)


def run_cohere_cell(
    *,
    model: str,
    suite_name: str,
    attack_name: str,
    seed: int,
    max_pairs: int = 2,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Run a single (model, suite, attack, seed) cell against Cohere.

    Returns a dict shaped for ``benchmarks.agentdojo_live.submit``'s
    ``CellResult`` consumer. Errors are returned as ``{"error": ...}``
    rather than raised.
    """
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

    api_key = api_key or os.environ.get("COHERE_API_KEY")
    if not api_key:
        return {
            "error": "COHERE_API_KEY not set",
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }

    attack_map = {
        "important_instructions": IgnorePreviousAttack,
        "tool_knowledge": InjecAgentAttack,
        "direct": DirectAttack,
        "system_message": SystemMessageAttack,
    }
    attack_cls = attack_map.get(attack_name)
    if attack_cls is None:
        return {
            "error": f"unknown attack name: {attack_name!r}",
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }

    try:
        client = _build_cohere_client(api_key)
    except RuntimeError as exc:
        return {
            "error": str(exc),
            "utility_attempt": 0.0, "targeted_asr": 0.0,
            "attack_prevention_rate": 0.0, "utility_delta": 0.0,
            "raw_runs": [], "elapsed_seconds": 0.0,
        }
    started = time.monotonic()

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
        pipeline, labeler, _ = build_pipeline(client, model)
        result = run_trial(pipeline, suite, suite_name, ut_id, None, None, {}, labeler)
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
            pipeline, labeler, _ = build_pipeline(client, model)
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Live AgentDojo eval with Cohere Command models")
    parser.add_argument("--suite", nargs="*", default=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="command-r7b-12-2024",
                        help="Cohere model id (default: command-r7b-12-2024 for fast smoke runs)")
    parser.add_argument("--max-injection-pairs", type=int, default=None)
    parser.add_argument("--output", default="benchmarks/agentdojo_live/results_cohere.json")
    args = parser.parse_args()

    api_key = os.environ.get("COHERE_API_KEY")
    if not api_key:
        print("Set COHERE_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)

    try:
        client = _build_cohere_client(api_key)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)

    attacks = [
        ("direct", DirectAttack),
        ("ignore_previous", IgnorePreviousAttack),
        ("system_message", SystemMessageAttack),
        ("injecagent", InjecAgentAttack),
    ]

    report = LiveReport()
    start = time.monotonic()

    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
    gt_pipeline = GroundTruthPipeline(None)

    for suite_name in args.suite:
        print(f"\n{'='*60}\nSuite: {suite_name}\n{'='*60}")
        suite = load_suite(suite_name)

        for ut_id in suite.user_tasks:
            pipeline, labeler, _ = build_pipeline(client, args.model)
            result = run_trial(pipeline, suite, suite_name, ut_id, None, None, {}, labeler)
            report.results.append(result)
            report.total_benign += 1
            if result.utility_pass:
                report.benign_passed += 1
            if result.error:
                report.errors += 1
            err = result.error or ""
            status = (
                "PASS" if result.utility_pass
                else "FALSE_POS" if "false positive" in err
                else f"ERROR ({err[:50]})" if err
                else "MODEL_FAIL"
            )
            print(f"  [benign] {ut_id}: {status}")

        pair_count = 0
        for ut_id in suite.user_tasks:
            for it_id in suite.injection_tasks:
                if args.max_injection_pairs and pair_count >= args.max_injection_pairs:
                    break
                for attack_name, attack_cls in attacks:
                    try:
                        attack = attack_cls(suite, gt_pipeline)
                        injections = attack.attack(suite.user_tasks[ut_id], suite.injection_tasks[it_id])
                    except Exception:
                        continue
                    if not injections:
                        continue
                    pipeline, labeler, _ = build_pipeline(client, args.model)
                    result = run_trial(pipeline, suite, suite_name, ut_id, it_id, attack_name, injections, labeler)
                    report.results.append(result)
                    report.total_injection += 1
                    if result.security_pass:
                        report.injection_blocked += 1
                    if result.error:
                        report.errors += 1
                    print(f"  [inject] {ut_id}/{it_id}/{attack_name}: {'BLOCKED' if result.security_pass else 'BREACHED'}")
                pair_count += 1
                if args.max_injection_pairs and pair_count >= args.max_injection_pairs:
                    break

    report.elapsed_seconds = time.monotonic() - start

    print(f"\n{'='*60}")
    print(f"AgentDojo LIVE Evaluation (Cohere {args.model})")
    print()
    print(f"  APR:     {report.apr:.1%} ({report.injection_blocked}/{report.total_injection})")
    print(f"  Utility: {report.utility:.1%} ({report.benign_passed}/{report.total_benign})")
    print(f"  Errors:  {report.errors}")
    print(f"  Time:    {report.elapsed_seconds:.0f}s")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump({
            "model": args.model,
            "suites": args.suite,
            "apr": report.apr,
            "utility": report.utility,
            "total_injection": report.total_injection,
            "injection_blocked": report.injection_blocked,
            "total_benign": report.total_benign,
            "benign_passed": report.benign_passed,
            "errors": report.errors,
            "elapsed_seconds": report.elapsed_seconds,
            "results": [
                {"suite": r.suite, "user_task": r.user_task_id, "injection_task": r.injection_task_id,
                 "attack": r.attack_name, "is_benign": r.is_benign, "utility_pass": r.utility_pass,
                 "security_pass": r.security_pass, "error": r.error}
                for r in report.results
            ],
        }, f, indent=2)
    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
