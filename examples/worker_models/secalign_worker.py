"""SecAlign-hardened worker model example.

This example demonstrates how to wire a SecAlign-hardened model as
the Worker in a QuarantinedExecutor. SecAlign uses adversarial
alignment training to harden the model against directive payloads in
untrusted segments.

See: arXiv:2410.05451, "SecAlign: Secure Model Alignment for
LLM-based Agents", 2024.

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


# Mock SecAlign-hardened model. In production, this would be a real
# inference call to a hardened checkpoint.
class SecalignMockModel:
    """Simulates a SecAlign-hardened worker model.

    In production, this would wrap:
    - HuggingFace model loading from a Mistral, Qwen, or LLaMA
      checkpoint fine-tuned with SecAlign adversarial training.
    - Token generation with adversarial-alignment weights applied.
    - Output parsing and structured extraction.
    """

    async def __call__(self, context: Context) -> dict[str, Any]:
        """Extract entities from context using SecAlign inference.

        Args:
            context: Untrusted context segments to process.

        Returns:
            Dict suitable for WorkerReport coercion.
        """
        # Simulate SecAlign hardened inference: extract entities
        # from the context, resistant to adversarial injection.
        entities = []
        numbers = {}

        for segment in context.segments:
            if "entity" in segment.content.lower():
                entities.append("extracted_entity")
            if "count" in segment.content.lower():
                numbers["item_count"] = 42.0

        return {
            "entities": entities,
            "urls": [],
            "numbers": numbers,
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
        "worker_numbers": report.numbers,
    }


async def main():
    """Demonstrate SecAlign worker in a QuarantinedExecutor."""
    print("Step 1: Initialize SecAlign-hardened worker model mock.")
    secalign_model = SecalignMockModel()

    print("Step 2: Wrap worker with strict_worker schema enforcement.")
    wrapped_worker = strict_worker(WorkerReport, secalign_model)

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
            "Extract all entities and counts.",
            Origin.USER,
            "alice",
            key,
        )
    )
    context.add(
        make_segment(
            "The document discusses entity recognition with a count of items "
            "and demonstrates the SecAlign approach.",
            Origin.WEB,
            "alice",
            key,
        )
    )

    print("Step 5: Run the executor.")
    result = await executor.run(context)

    print("\nWorker output:")
    print(f"  Entities: {result['worker_entities']}")
    print(f"  Numbers: {result['worker_numbers']}")
    print(f"  Decision: {result['decision']}")
    print("\nSecAlign worker example completed successfully.")


if __name__ == "__main__":
    asyncio.run(main())
