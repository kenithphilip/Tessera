"""ASIDE-hardened worker model example.

This example demonstrates how to wire an ASIDE-hardened model as the
Worker in a QuarantinedExecutor. ASIDE (Aligned Side-Channel Decoder)
augments the worker model with a side-channel decoder that strips
injection content before the main output head evaluates it.

See: arXiv:2407.13692, "Aligned Side-Channel Decoder for Improving
the Robustness of the Model Against Prompt Injection Attacks", 2024.

No HuggingFace downloads occur; this example uses a mock model handle
for demonstration.
"""

from __future__ import annotations

import asyncio
from typing import Any

from tessera.context import Context, make_segment
from tessera.labels import Origin, TrustLevel
from tessera.quarantine import (
    QuarantinedExecutor,
    WorkerReport,
    strict_worker,
)


# Mock ASIDE-hardened model. In production, this would be a real
# inference call to a hardened checkpoint.
class AsideMockModel:
    """Simulates an ASIDE-hardened worker model.

    In production, this would wrap:
    - HuggingFace model loading from a Meta Llama checkpoint
      with ASIDE weights included.
    - Token generation with the side-channel decoder active.
    - Output parsing and structured extraction.
    """

    async def __call__(self, context: Context) -> dict[str, Any]:
        """Extract entities from context using ASIDE inference.

        Args:
            context: Untrusted context segments to process.

        Returns:
            Dict suitable for WorkerReport coercion.
        """
        # Simulate ASIDE hardened inference: extract entities
        # from the context, resistant to injection.
        entities = []
        urls = []

        for segment in context.segments:
            if "http" in segment.content.lower():
                urls.append("https://example.com")
            if "entity" in segment.content.lower():
                entities.append("extracted_entity")

        return {
            "entities": entities,
            "urls": urls,
            "numbers": {},
            "flags": {},
            "have_enough_information": True,
        }


async def example_planner(
    trusted: Context, report: WorkerReport
) -> dict[str, Any]:
    """Mock planner callable (always sees trusted segments only).

    Args:
        trusted: Context containing only USER, SYSTEM, and vetted
                 TOOL segments.
        report: Structured output from the worker.

    Returns:
        Decision dict with tool calls and reasoning.
    """
    return {
        "decision": "approve",
        "tool_call": None,
        "worker_entities": report.entities,
        "worker_urls": report.urls,
    }


async def main():
    """Demonstrate ASIDE worker in a QuarantinedExecutor."""
    print("Step 1: Initialize ASIDE-hardened worker model mock.")
    aside_model = AsideMockModel()

    print("Step 2: Wrap worker with strict_worker schema enforcement.")
    wrapped_worker = strict_worker(WorkerReport, aside_model)

    print("Step 3: Create QuarantinedExecutor with planner and worker.")
    executor = QuarantinedExecutor(
        planner=example_planner,
        worker=wrapped_worker,
        threshold=TrustLevel.TOOL,
    )

    print("Step 4: Build a context with trusted and untrusted segments.")
    key = b"example-hmac-key"
    context = Context()
    context.add(
        make_segment(
            "Extract entities from this page.",
            Origin.USER,
            "alice",
            key,
        )
    )
    context.add(
        make_segment(
            "This page contains a link to http://example.com and "
            "mentions entity extraction.",
            Origin.WEB,
            "alice",
            key,
        )
    )

    print("Step 5: Run the executor.")
    result = await executor.run(context)

    print("\nWorker output:")
    print(f"  Entities: {result['worker_entities']}")
    print(f"  URLs: {result['worker_urls']}")
    print(f"  Decision: {result['decision']}")
    print("\nASIDE worker example completed successfully.")


if __name__ == "__main__":
    asyncio.run(main())
