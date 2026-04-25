"""Deterministic evaluation of the v1 principles.

The Action Critic runs a deterministic principle pre-check BEFORE
calling any backend (LLM or otherwise). The pre-check covers the
load-bearing structural cases:

- :class:`Principle.ORIGIN_CONSISTENCY` rejects calls whose
  critical arguments fail the per-tool ``required_integrity``
  declared in :mod:`tessera.policy.tool_critical_args`.
- :class:`Principle.LEAST_PRIVILEGE` rejects same-planner-as-critic
  invocations when the operator has not opted in via the env var.
- :class:`Principle.UNTRUSTED_ARG_REASONABLE` rejects values whose
  shape is implausible for the tool's documented purpose
  (4 KiB UNTRUSTED string in ``transfer_funds.amount``, etc.).

The pre-check is fast (microseconds), deterministic, and has no
external dependencies. Only when it returns ALLOW does the
backend get called for the soft principles (data minimization,
irreversibility, no exfiltration), which require model judgment.

Reference
---------

- ``src/tessera/action_critic/principles/v1.yaml``
- ``docs/strategy/2026-04-engineering-brief.md`` Section 2.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from tessera.policy.tool_critical_args import CriticalArgSpec, specs_for
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
)


class Principle(StrEnum):
    """The six principles defined in :file:`principles/v1.yaml`."""

    DATA_MINIMIZATION = "data_minimization"
    ORIGIN_CONSISTENCY = "origin_consistency"
    IRREVERSIBILITY = "irreversibility"
    LEAST_PRIVILEGE = "least_privilege"
    NO_EXFILTRATION = "no_exfiltration"
    UNTRUSTED_ARG_REASONABLE = "untrusted_arg_reasonable"


@dataclass(frozen=True, slots=True)
class PrincipleViolation:
    """One concrete principle violation discovered during pre-check."""

    principle: Principle
    arg_name: str
    reason: str


# Threshold above which an UNTRUSTED string-capacity arg is treated
# as implausible for any tool. 4 KiB matches the engineering brief
# Section 2.3 example (4 KiB UNTRUSTED string in transfer_funds.amount).
_UNTRUSTED_LENGTH_LIMIT = 4096


def _integrity_below(
    required: IntegrityLevel, observed: IntegrityLevel
) -> bool:
    """Return True when ``observed`` is *worse* than ``required``.

    IntegrityLevel uses inverted numerics: TRUSTED=0 < ENDORSED=1
    < UNTRUSTED=2. Lower int is more trusted; observed integrity
    must satisfy ``observed.value <= required.value`` for the call
    to pass.
    """
    return observed.value > required.value


def evaluate_origin_consistency(
    tool: str, args: Iterable["ArgShapeLike"]
) -> list[PrincipleViolation]:
    """Check every critical arg's integrity against the spec table."""
    specs = {spec.name: spec for spec in specs_for(tool)}
    violations: list[PrincipleViolation] = []
    for arg in args:
        spec = specs.get(arg.name)
        if spec is None:
            continue
        if _integrity_below(spec.required_integrity, arg.label.integrity):
            violations.append(
                PrincipleViolation(
                    principle=Principle.ORIGIN_CONSISTENCY,
                    arg_name=arg.name,
                    reason=(
                        f"required_integrity={spec.required_integrity.name} "
                        f"but value carries {arg.label.integrity.name}"
                    ),
                )
            )
    return violations


def evaluate_untrusted_arg_reasonable(
    tool: str, args: Iterable["ArgShapeLike"]
) -> list[PrincipleViolation]:
    """Reject implausible UNTRUSTED arg shapes."""
    specs = {spec.name: spec for spec in specs_for(tool)}
    violations: list[PrincipleViolation] = []
    for arg in args:
        if arg.label.integrity != IntegrityLevel.UNTRUSTED:
            continue
        spec = specs.get(arg.name)
        # Length-based check: an UNTRUSTED string-capacity value
        # exceeding the limit is treated as implausible regardless
        # of the spec.
        if arg.length > _UNTRUSTED_LENGTH_LIMIT:
            violations.append(
                PrincipleViolation(
                    principle=Principle.UNTRUSTED_ARG_REASONABLE,
                    arg_name=arg.name,
                    reason=(
                        f"UNTRUSTED value of length {arg.length} exceeds "
                        f"per-tool limit ({_UNTRUSTED_LENGTH_LIMIT} bytes)"
                    ),
                )
            )
            continue
        # Capacity check: if the spec caps the capacity (NUMBER /
        # ENUM / BOOL), the value's capacity must respect it.
        if spec is not None and spec.capacity_max is not None:
            if arg.label.capacity.value > spec.capacity_max.value:
                violations.append(
                    PrincipleViolation(
                        principle=Principle.UNTRUSTED_ARG_REASONABLE,
                        arg_name=arg.name,
                        reason=(
                            f"capacity={arg.label.capacity.name} exceeds "
                            f"per-tool cap {spec.capacity_max.name}"
                        ),
                    )
                )
    return violations


def evaluate_no_exfiltration(
    tool: str, args: Iterable["ArgShapeLike"]
) -> list[PrincipleViolation]:
    """Reject calls whose audience-checked args expose readers
    that the value's label does not allow."""
    specs = {spec.name: spec for spec in specs_for(tool)}
    violations: list[PrincipleViolation] = []
    for arg in args:
        spec = specs.get(arg.name)
        if spec is None or not spec.audience_check:
            continue
        # The actual audience cross-check requires the call's
        # destination principal which the critic does not see in
        # ArgShape; the structural rule we can enforce here is:
        # if the arg has an explicit reader_principals set AND it
        # is empty (no reader allowed), every external send is a
        # violation.
        if (
            arg.label.reader_principals is not None
            and len(arg.label.reader_principals) == 0
        ):
            violations.append(
                PrincipleViolation(
                    principle=Principle.NO_EXFILTRATION,
                    arg_name=arg.name,
                    reason=(
                        "audience-checked arg carries empty reader set; "
                        "no external destination is permitted"
                    ),
                )
            )
    return violations


def deterministic_pre_check(
    tool: str, args: Iterable["ArgShapeLike"]
) -> list[PrincipleViolation]:
    """Run all deterministic principle checks; concatenate violations."""
    return (
        evaluate_origin_consistency(tool, args)
        + evaluate_untrusted_arg_reasonable(tool, args)
        + evaluate_no_exfiltration(tool, args)
    )


# Structural duck-type alias for ArgShape so this module avoids a
# circular import on tessera.action_critic.
class ArgShapeLike:  # pragma: no cover - typing alias only
    name: str
    length: int
    label: "LabelSummaryLike"


class LabelSummaryLike:  # pragma: no cover - typing alias only
    integrity: IntegrityLevel
    capacity: InformationCapacity
    reader_principals: tuple[str, ...] | None


__all__ = [
    "ArgShapeLike",
    "LabelSummaryLike",
    "Principle",
    "PrincipleViolation",
    "deterministic_pre_check",
    "evaluate_no_exfiltration",
    "evaluate_origin_consistency",
    "evaluate_untrusted_arg_reasonable",
]
