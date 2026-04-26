"""Live AgentDojo evaluation with OpenAI models (gpt-4o, gpt-4o-mini, gpt-5, o1, etc.).

Companion to ``run_haiku.py``. Same trial machinery, same Tessera
labeler/guard wiring, same JSON output schema; only the LLM client
differs. The ``runners.py:run_provider_cell`` dispatcher already
routes ``gpt-*`` / ``o1*`` / ``o3*`` model names through this code
path; the standalone CLI here gives operators a one-off harness
without the matrix overhead.

Usage::

    OPENAI_API_KEY=... python -m benchmarks.agentdojo_live.run_openai
    OPENAI_API_KEY=... python -m benchmarks.agentdojo_live.run_openai \\
        --suite travel --max-injection-pairs 2 --model gpt-4o
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import openai

from agentdojo.agent_pipeline import AgentPipeline, OpenAILLM
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.attacks.baseline_attacks import (
    DirectAttack,
    IgnorePreviousAttack,
    InjecAgentAttack,
    SystemMessageAttack,
)

# Reuse provider-agnostic plumbing from run_haiku to avoid drift.
from benchmarks.agentdojo_live.run_haiku import (
    LiveReport,
    LiveResult,
    build_pipeline_with_llm,
    load_suite,
    run_trial,
)


# Friendly aliases mirror the dispatcher's `runners.detect_provider`
# table so operators can pass `gpt-5` (alias) or `gpt-4o` (canonical)
# interchangeably.
_OPENAI_MODEL_ALIASES: dict[str, str] = {
    "gpt-5": "gpt-4o",
    "gpt-4.1": "gpt-4o",
}


def _canonical_model(model: str) -> str:
    """Resolve aliases. Pass-through for unknown ``gpt-*`` / ``o*`` ids."""
    return _OPENAI_MODEL_ALIASES.get(model, model)


def build_pipeline(client: openai.OpenAI, model: str):
    """OpenAI-specific convenience wrapper.

    Multi-provider callers should construct an ``OpenAILLM`` themselves
    and pass it to :func:`build_pipeline_with_llm` instead.
    """
    llm = OpenAILLM(client=client, model=_canonical_model(model), temperature=0.0)
    return build_pipeline_with_llm(llm)


def run_openai_cell(
    *,
    model: str,
    suite_name: str,
    attack_name: str,
    seed: int,
    max_pairs: int = 2,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Run a single (model, suite, attack, seed) cell against OpenAI.

    Returns a dict shaped for ``benchmarks.agentdojo_live.submit``'s
    ``CellResult`` consumer (see ``run_haiku.run_anthropic_cell``
    docstring for the field-by-field contract). Errors are returned
    as ``{"error": "..."}`` rather than raised.
    """
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return {
            "error": "OPENAI_API_KEY not set",
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

    client = openai.OpenAI(api_key=api_key)
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

    # Benign trials (same window across seeds for utility comparability).
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

    # Injection trials: stride disjoint windows by seed.
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
    parser = argparse.ArgumentParser(description="Live AgentDojo eval with OpenAI models")
    parser.add_argument("--suite", nargs="*", default=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="gpt-4o-mini",
                        help="OpenAI model id (default: gpt-4o-mini for fast smoke runs)")
    parser.add_argument("--max-injection-pairs", type=int, default=None)
    parser.add_argument("--output", default="benchmarks/agentdojo_live/results_openai.json")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Set OPENAI_API_KEY environment variable", file=sys.stderr)
        sys.exit(1)

    client = openai.OpenAI(api_key=api_key)
    canonical = _canonical_model(args.model)
    if canonical != args.model:
        print(f"Resolving model alias: {args.model} -> {canonical}")

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

        # Benign trials
        for ut_id in suite.user_tasks:
            pipeline, labeler, _ = build_pipeline(client, canonical)
            result = run_trial(pipeline, suite, suite_name, ut_id, None, None, {}, labeler)
            report.results.append(result)
            report.total_benign += 1
            if result.utility_pass:
                report.benign_passed += 1
            if result.error:
                report.errors += 1
            err = result.error or ""
            if result.utility_pass:
                status = "PASS"
            elif "false positive" in err:
                status = "FALSE_POS"
            elif err:
                status = f"ERROR ({err[:50]})"
            else:
                status = "MODEL_FAIL"
            print(f"  [benign] {ut_id}: {status}")

        # Injection trials (bounded by --max-injection-pairs).
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

                    pipeline, labeler, _ = build_pipeline(client, canonical)
                    result = run_trial(pipeline, suite, suite_name, ut_id, it_id, attack_name, injections, labeler)
                    report.results.append(result)
                    report.total_injection += 1
                    if result.security_pass:
                        report.injection_blocked += 1
                    if result.error:
                        report.errors += 1
                    status = "BLOCKED" if result.security_pass else "BREACHED"
                    print(f"  [inject] {ut_id}/{it_id}/{attack_name}: {status}")

                pair_count += 1
                if args.max_injection_pairs and pair_count >= args.max_injection_pairs:
                    break

    report.elapsed_seconds = time.monotonic() - start

    # LiveReport.summary() is hard-coded to the Haiku string; print
    # the OpenAI-flavoured equivalent.
    print(f"\n{'='*60}")
    print(f"AgentDojo LIVE Evaluation (OpenAI {canonical})")
    print()
    print(f"  APR:     {report.apr:.1%} ({report.injection_blocked}/{report.total_injection})")
    print(f"  Utility: {report.utility:.1%} ({report.benign_passed}/{report.total_benign})")
    print(f"  Errors:  {report.errors}")
    print(f"  Time:    {report.elapsed_seconds:.0f}s")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump({
            "model": canonical,
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
