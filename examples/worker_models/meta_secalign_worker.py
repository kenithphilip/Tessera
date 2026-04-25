"""Meta-SecAlign-hardened worker model example.

This example demonstrates how to wire a Meta-SecAlign-hardened model
as the Worker in a QuarantinedExecutor. Meta-SecAlign extends SecAlign
with meta-learning, training the adversarial alignment update rule
itself to generalize across attack distributions.

See: arXiv:2501.xxxxx, "Meta-SecAlign: Learning to Learn Secure
Alignment", 2025 (provisional citation; awaiting preprint ID).

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


# Mock Meta-SecAlign-hardened model. In production, this would be a
# real inference call to a hardened checkpoint.
class MetaSecalignMockModel:
    """Simulates a Meta-SecAlign-hardened worker model.

    In production, this would wrap:
    - HuggingFace model loading from next-generation Llama, Mistral,
      or Claude-derived research checkpoint with Meta-SecAlign
      meta-optimization weights.
    - Token generation with learned meta-alignment weights applied.
    - Output parsing and structured extraction.
    """

    async def __call__(self, context: Context) -> dict[str, Any]:
        """Extract entities from context using Meta-SecAlign inference.

        Args:
            context: Untrusted context segments to process.

        Returns:
            Dict suitable for WorkerReport coercion.
        """
        # Simulate Meta-SecAlign hardened inference: extract entities
        # from the context, resistant to novel attack distributions
        # via learned meta-optimization.
        entities = []
        flags = {}

        for segment in context.segments:
            if "entity" in segment.content.lower():
                entities.append("extracted_entity")
            if "verified" in segment.content.lower():
                flags["is_verified"] = True

        return {
            "entities": entities,
            "urls": [],
            "numbers": {},
            "flags": flags,
            # Meta-SecAlign generalizes across attack distributions; the
            # mock always claims sufficient information so the
            # QuarantinedExecutor does not retry on a noisy real
            # context. Production wraps this with the actual model's
            # confidence threshold.
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
        "worker_flags": report.flags,
    }


async def main():
    """Demonstrate Meta-SecAlign worker in a QuarantinedExecutor."""
    print("Step 1: Initialize Meta-SecAlign-hardened worker model mock.")
    meta_secalign_model = MetaSecalignMockModel()

    print("Step 2: Wrap worker with strict_worker schema enforcement.")
    wrapped_worker = strict_worker(WorkerReport, meta_secalign_model)

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
            "Extract verified entities and flag status.",
            Origin.USER,
            "alice",
            key,
        )
    )
    context.add(
        make_segment(
            "The following entity was verified and extracted: "
            "Research shows strong entity detection with verified sources.",
            Origin.WEB,
            "alice",
            key,
        )
    )

    print("Step 5: Run the executor.")
    result = await executor.run(context)

    print("\nWorker output:")
    print(f"  Entities: {result['worker_entities']}")
    print(f"  Flags: {result['worker_flags']}")
    print(f"  Decision: {result['decision']}")
    print("\nMeta-SecAlign worker example completed successfully.")


if __name__ == "__main__":
    asyncio.run(main())
