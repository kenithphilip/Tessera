"""Baseline AgentDojo evaluation WITHOUT Tessera.

Runs the exact same pipeline, same model, same prompts, but with
NO Tessera defense in the loop. This isolates model capability from
Tessera's impact on utility.

Compare results against run_haiku.py to determine whether utility
gaps are caused by Tessera or by model capability.

Usage:
    ANTHROPIC_API_KEY=... python -m benchmarks.agentdojo_live.run_baseline
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import anthropic

from agentdojo.agent_pipeline import AgentPipeline, AnthropicLLM
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
from agentdojo.functions_runtime import FunctionsRuntime


@dataclass
class BaselineResult:
    suite: str
    user_task_id: str
    utility_pass: bool
    error: str | None = None


def load_suite(name: str):
    # Use the same import path as run_haiku.py to avoid circular imports
    from benchmarks.agentdojo_live.run_haiku import load_suite as _load
    return _load(name)


def build_baseline_pipeline(client, model):
    """Build a VANILLA pipeline with NO Tessera defense."""
    llm = AnthropicLLM(client=client, model=model, temperature=0.0, max_tokens=4096)
    system_msg = "You are a helpful assistant. Use the provided tools to accomplish the task."

    # Standard AgentDojo pipeline, NO guard, NO labeler
    pipeline = AgentPipeline([
        SystemMessage(system_msg),
        InitQuery(),
        llm,
        ToolsExecutionLoop([ToolsExecutor(), llm]),
    ])
    return pipeline


def run_baseline_trial(pipeline, suite, suite_name, user_task_id):
    ut = suite.user_tasks[user_task_id]
    env = suite.load_and_inject_default_environment({})
    pre_env = ut.init_environment(env)
    runtime = FunctionsRuntime(suite.tools)

    try:
        _, _, post_env, messages, _ = pipeline.query(ut.PROMPT, runtime, pre_env)

        model_output = ""
        for msg in reversed(messages):
            if msg.get("role") == "assistant":
                content = msg.get("content")
                if isinstance(content, str):
                    model_output = content
                elif isinstance(content, list):
                    parts = [b.get("content", "") if isinstance(b, dict) else str(b) for b in content]
                    model_output = " ".join(str(p) for p in parts if p)
                break

        utility_pass = ut.utility(model_output, pre_env, post_env)
        return BaselineResult(
            suite=suite_name, user_task_id=user_task_id,
            utility_pass=utility_pass,
        )

    except Exception as e:
        return BaselineResult(
            suite=suite_name, user_task_id=user_task_id,
            utility_pass=False,
            error=f"{type(e).__name__}: {str(e)[:150]}",
        )


def main():
    parser = argparse.ArgumentParser(description="Baseline AgentDojo eval WITHOUT Tessera")
    parser.add_argument("--suite", nargs="*", default=["banking", "slack", "travel", "workspace"])
    parser.add_argument("--model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--output", default="/tmp/tessera-baseline.json")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Set ANTHROPIC_API_KEY", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    results: list[BaselineResult] = []
    start = time.monotonic()

    for suite_name in args.suite:
        print(f"\n{'='*60}")
        print(f"Suite: {suite_name} (NO TESSERA)")
        print(f"{'='*60}")

        suite = load_suite(suite_name)
        pipeline = build_baseline_pipeline(client, args.model)

        for ut_id in suite.user_tasks:
            result = run_baseline_trial(pipeline, suite, suite_name, ut_id)
            results.append(result)
            err = result.error or ""
            if result.utility_pass:
                status = "PASS"
            elif err:
                status = f"ERROR ({err[:50]})"
            else:
                status = "MODEL_FAIL"
            print(f"  {ut_id}: {status}")

    elapsed = time.monotonic() - start

    total = len(results)
    passed = sum(1 for r in results if r.utility_pass)
    errors = sum(1 for r in results if r.error)

    print(f"\n{'='*60}")
    print(f"Baseline (NO Tessera) - {args.model}")
    print(f"  Utility: {passed}/{total} ({passed/total*100:.1f}%)")
    print(f"  Errors:  {errors}")
    print(f"  Time:    {elapsed:.0f}s")

    with open(args.output, "w") as f:
        json.dump({
            "model": args.model,
            "defense": "none",
            "suites": args.suite,
            "utility": passed / total if total else 0,
            "total": total,
            "passed": passed,
            "errors": errors,
            "elapsed_seconds": elapsed,
            "results": [
                {"suite": r.suite, "user_task": r.user_task_id,
                 "utility_pass": r.utility_pass, "error": r.error}
                for r in results
            ],
        }, f, indent=2)
    print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
