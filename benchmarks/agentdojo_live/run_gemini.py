"""Live AgentDojo evaluation with Google Gemini models.

Companion to ``run_haiku.py`` and ``run_openai.py``. Same trial
machinery, same Tessera labeler/guard wiring, same JSON output
schema; only the LLM client differs (``google.genai.Client`` +
AgentDojo's ``GoogleLLM``).

The ``runners.py:run_provider_cell`` dispatcher already routes
``gemini-*`` / ``palm-*`` model names through this code path; the
standalone CLI here gives operators a one-off harness without the
matrix overhead.

Quirks compared to Anthropic:
- Google's ``genai`` SDK (``google-genai`` package) wraps the
  Vertex / AI Studio APIs. Authenticated via ``GOOGLE_API_KEY`` or
  the legacy ``GEMINI_API_KEY`` env var.
- Tool-call parts arrive as ``function_call`` objects (not
  OpenAI-style ``tool_calls`` arrays). AgentDojo's ``GoogleLLM``
  flattens these internally; ``run_trial`` only inspects the final
  assistant message text, so the existing extractor already handles
  the dict-vs-string-vs-list-of-Parts cases.

Usage::

    GOOGLE_API_KEY=... python -m benchmarks.agentdojo_live.run_gemini
    GOOGLE_API_KEY=... python -m benchmarks.agentdojo_live.run_gemini \\
        --suite travel --max-injection-pairs 2 --model gemini-2.5-pro
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from agentdojo.agent_pipeline import GoogleLLM
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


def _build_genai_client(api_key: str):
    """Construct a ``google.genai.Client``. Imported lazily because
    ``google-genai`` is an optional extra and many operators will only
    install one provider's SDK at a time."""
    try:
        from google import genai
    except ImportError as exc:
        raise RuntimeError(
            f"google-genai not installed: {exc}. "
            f"Install with: pip install google-genai"
        ) from exc
    return genai.Client(api_key=api_key)


def build_pipeline(client, model: str):
    """Gemini-specific convenience wrapper. Multi-provider callers
    should construct a ``GoogleLLM`` themselves and pass it to
    :func:`build_pipeline_with_llm`."""
    llm = GoogleLLM(model=model, client=client, temperature=0.0)
    return build_pipeline_with_llm(llm)


def run_gemini_cell(
    *,
    model: str,
    suite_name: str,
    attack_name: str,
    seed: int,
    max_pairs: int = 2,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Run a single (model, suite, attack, seed) cell against Gemini.

    Returns a dict shaped for ``benchmarks.agentdojo_live.submit``'s
    ``CellResult`` consumer. Errors are returned as ``{"error": ...}``
    rather than raised.
    """
    from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline

    api_key = (
        api_key
        or os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
    )
    if not api_key:
        return {
            "error": "GOOGLE_API_KEY (or GEMINI_API_KEY) not set",
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
        client = _build_genai_client(api_key)
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
    parser = argparse.ArgumentParser(description="Live AgentDojo eval with Google Gemini")
    parser.add_argument("--suite", nargs="*", default=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="gemini-2.5-pro",
                        help="Gemini model id (default: gemini-2.5-pro)")
    parser.add_argument("--max-injection-pairs", type=int, default=None)
    parser.add_argument("--output", default="benchmarks/agentdojo_live/results_gemini.json")
    args = parser.parse_args()

    api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Set GOOGLE_API_KEY (or GEMINI_API_KEY) environment variable", file=sys.stderr)
        sys.exit(1)

    try:
        client = _build_genai_client(api_key)
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
    print(f"AgentDojo LIVE Evaluation (Gemini {args.model})")
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
