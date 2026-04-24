"""Dual-LLM quarantined execution.

This is Simon Willison's dual-LLM pattern, made concrete. The core idea: if
the planner model never sees untrusted text, it cannot be instructed by
untrusted text. Tool-gating at the policy layer catches the symptom; this
pattern eliminates the disease.

Two callables:

    - planner: sees only trusted segments (USER + SYSTEM) plus a structured
      summary produced by the worker. Proposes tool calls. This is the only
      model that can influence the agent's actions.
    - worker: sees the untrusted segments and returns a `WorkerReport` with
      structured data extracted from them. The worker has zero tool access.
      Its output is not injected back into the planner as free-form text; it
      is pinned to a schema the planner can read safely.

A well-behaved worker might extract entities, dates, URLs, or summaries. A
misbehaving worker (one that fell for an injection in the untrusted text)
can at worst return nonsense in the structured fields. It cannot propose
tool calls, because it doesn't have any.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

from pydantic import BaseModel, Field, ValidationError

from tessera.context import Context
from tessera.events import EventKind, SecurityEvent, emit as emit_event
from tessera.labels import TrustLevel
from tessera.telemetry import (
    quarantine_planner_span,
    quarantine_span,
    quarantine_worker_span,
)


class WorkerSchemaViolation(Exception):
    """Raised when a worker's output does not match its declared schema.

    This is a trust-boundary failure, not a soft validation error: the
    worker was supposed to return structured data constrained by a schema,
    and it did not. Treat this as a security event, not a retry condition.
    """


class WorkerInsufficientInformation(Exception):
    """Raised when the worker reports it does not have enough data.

    This is not a security failure. It means the worker honestly signaled
    that the untrusted context did not contain sufficient information to
    produce a reliable report. The executor can retry with more context
    or escalate to the user.
    """


class WorkerReport(BaseModel):
    """Safe-by-default structured output schema for the worker model.

    This schema deliberately contains no free-form string fields. The
    planner should be able to render this entire report as JSON without
    any field being interpretable as instructions.

    If you add a field, it should be either:
      - a pinned semantic type (float, int, bool, enum), or
      - a list of short tokens the planner renders as quoted bullets.

    Do NOT add a free-form `summary: str` or `notes: str`. A compromised
    worker that returns structurally-valid-but-adversarial strings in
    those fields re-opens the injection channel you built this wrapper
    to close. If your agent genuinely needs a summary, build a custom
    schema and document how the planner will render that field (e.g.
    wrap it in a spotlighted untrusted block before showing the planner).

    The `have_enough_information` field forces the worker to signal
    uncertainty. When False, the QuarantinedExecutor re-queries with
    more context rather than acting on partial or hallucinated output.
    """

    have_enough_information: bool = True
    entities: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    numbers: dict[str, float] = Field(default_factory=dict)
    flags: dict[str, bool] = Field(default_factory=dict)


ReportT = TypeVar("ReportT", bound=BaseModel)

PlannerFn = Callable[[Context, Any], Awaitable[dict[str, Any]]]
WorkerFn = Callable[[Context], Awaitable[Any]]


def strict_worker(
    schema: type[ReportT],
    inner: Callable[[Context], Awaitable[Any]],
) -> Callable[[Context], Awaitable[ReportT]]:
    """Wrap a raw worker callable with Pydantic schema enforcement.

    The inner callable can return a BaseModel instance, a dict, or a JSON
    string. The wrapper coerces into `schema` and raises
    `WorkerSchemaViolation` on any failure. A compromised worker that
    attempts to return free-form text hits the validator and fails closed.

    On schema violation a `WORKER_SCHEMA_VIOLATION` security event is
    emitted before the exception is raised, so incident response sees
    the failed attempt even when the caller catches the exception.

    Args:
        schema: The Pydantic model the worker must conform to.
        inner: The raw worker callable (typically an LLM wrapper).

    Returns:
        A WorkerFn that always returns a `schema` instance or raises.
    """

    async def wrapped(context: Context) -> ReportT:
        raw = await inner(context)
        if isinstance(raw, schema):
            return raw
        try:
            if isinstance(raw, str):
                return schema.model_validate_json(raw)
            return schema.model_validate(raw)
        except ValidationError as exc:
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.WORKER_SCHEMA_VIOLATION,
                    principal=context.principal,
                    detail={
                        "schema": schema.__name__,
                        "error": str(exc),
                    },
                )
            )
            raise WorkerSchemaViolation(
                f"worker output did not match schema {schema.__name__}: {exc}"
            ) from exc

    return wrapped


def split_by_trust(
    context: Context, threshold: TrustLevel = TrustLevel.TOOL
) -> tuple[Context, Context]:
    """Partition a context into (trusted, untrusted) by trust level.

    Segments at or above the threshold go to the trusted side. Everything
    below goes to untrusted. The default threshold is TOOL: only USER,
    SYSTEM, and vetted tool outputs count as trusted.
    """
    trusted = Context()
    untrusted = Context()
    for seg in context.segments:
        if seg.label.trust_level >= threshold:
            trusted.add(seg)
        else:
            untrusted.add(seg)
    return trusted, untrusted


@dataclass
class QuarantinedExecutor:
    """Run a planner/worker pair with strict trust separation.

    The executor enforces one rule above all others: the planner callable
    is never invoked with untrusted context in view. The worker callable is
    never granted the ability to propose tool calls (its return type is
    structurally incapable of carrying them).
    """

    planner: PlannerFn
    worker: WorkerFn
    threshold: TrustLevel = TrustLevel.TOOL
    max_worker_retries: int = 1

    async def run(self, context: Context) -> dict[str, Any]:
        trusted, untrusted = split_by_trust(context, self.threshold)

        with quarantine_span(
            trusted_count=len(trusted.segments),
            untrusted_count=len(untrusted.segments),
        ):
            if untrusted.segments:
                report = await self._run_worker_with_retry(untrusted)
                # Re-attach provenance labels stripped by the
                # JSON serialization boundary at the worker. Best-
                # effort: failures are non-fatal because the
                # downstream policy still has the trusted-segment
                # labels via min_trust on the planner context. The
                # recovery emits LABEL_RECOVERY_* events for every
                # field so SOC teams have full visibility.
                try:
                    from tessera.worker.recovery import (
                        field_provenance_recovery,
                    )

                    field_provenance_recovery(report, untrusted)
                except Exception:  # noqa: BLE001
                    # Recovery is observability + soft signal. Do
                    # not let a buggy recovery path block the
                    # planner.
                    pass
            else:
                report = WorkerReport()

            with quarantine_planner_span():
                return await self.planner(trusted, report)

    async def _run_worker_with_retry(self, untrusted: Context) -> Any:
        """Run the worker, retrying if it reports insufficient information."""
        for attempt in range(1 + self.max_worker_retries):
            with quarantine_worker_span():
                report = await self.worker(untrusted)

            # Check if the report signals insufficient information.
            # Only applies to WorkerReport or subclasses with the field.
            has_flag = hasattr(report, "have_enough_information")
            if not has_flag or report.have_enough_information:
                return report

            if attempt < self.max_worker_retries:
                continue

            # Out of retries. Emit event and raise.
            emit_event(
                SecurityEvent.now(
                    kind=EventKind.WORKER_SCHEMA_VIOLATION,
                    principal=untrusted.principal,
                    detail={
                        "reason": "worker reported insufficient information after retries",
                        "attempts": attempt + 1,
                    },
                )
            )
            raise WorkerInsufficientInformation(
                f"worker reported have_enough_information=False after {attempt + 1} attempts"
            )
