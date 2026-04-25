"""Deterministic evaluation of the action critic principles.

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

Principles version selection
-----------------------------

Set the environment variable ``TESSERA_PRINCIPLES_VERSION`` to
``"2"`` to load ``principles/v2.yaml`` (20 principles, P01-P20).
The default is ``"1"`` (``principles/v1.yaml``, 6 principles).

The :func:`load_principles` function returns a list of
:class:`PrincipleSpec` dataclasses representing the active set.
The :func:`deterministic_pre_check` signature is unchanged.

Reference
---------

- ``src/tessera/action_critic/principles/v1.yaml``
- ``src/tessera/action_critic/principles/v2.yaml``
- ``docs/strategy/principles_evolution.md``
- ``docs/strategy/2026-04-engineering-brief.md`` Section 2.3.
"""

from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable

from tessera.policy.tool_critical_args import CriticalArgSpec, specs_for
from tessera.taint.label import (
    InformationCapacity,
    IntegrityLevel,
)


class Principle(StrEnum):
    """All principles across v1 and v2.

    v1 principles (P01-P06) are the six original principles.
    v2 principles (P07-P20) are the fourteen additions in Wave 3G.
    """

    DATA_MINIMIZATION = "data_minimization"
    ORIGIN_CONSISTENCY = "origin_consistency"
    IRREVERSIBILITY = "irreversibility"
    LEAST_PRIVILEGE = "least_privilege"
    NO_EXFILTRATION = "no_exfiltration"
    UNTRUSTED_ARG_REASONABLE = "untrusted_arg_reasonable"
    # v2 additions
    TOOL_AUDIT_TRAIL_INTEGRITY = "tool_audit_trail_integrity"
    INPUT_FORMAT_CONSISTENCY = "input_format_consistency"
    CROSS_TOOL_DEPENDENCY_CHECK = "cross_tool_dependency_check"
    RATELIMIT_RESPECT = "ratelimit_respect"
    SECRECY_DONT_EXPORT = "secrecy_dont_export"
    CAPABILITY_MINIMIZATION = "capability_minimization"
    CONFUSED_DEPUTY_CHECK = "confused_deputy_check"
    DETERMINISTIC_UNDER_REPLAY = "deterministic_under_replay"
    READERS_AUDIENCE_MATCH = "readers_audience_match"
    UNSAFE_TEMPLATE_RENDER = "unsafe_template_render"
    DESTRUCTIVE_REQUIRES_APPROVAL = "destructive_requires_approval"
    MCP_TIER_FLOOR = "mcp_tier_floor"
    CRITIC_SELF_CONSISTENCY = "critic_self_consistency"
    EMERGENCY_BRAKE = "emergency_brake"


@dataclass(frozen=True, slots=True)
class PrincipleSpec:
    """One principle record as loaded from a principles YAML file.

    Args:
        id: Stable principle identifier (matches :class:`Principle` values).
        description: Plain-English statement surfaced in audit detail.
        asi_codes: OWASP Agentic Top 10 ASI-* mappings.
        atlas_codes: MITRE ATLAS technique IDs.
        rationale: Longer engineering justification.
    """

    id: str
    description: str
    asi_codes: tuple[str, ...]
    atlas_codes: tuple[str, ...]
    rationale: str


_PRINCIPLES_DIR = pathlib.Path(__file__).parent / "principles"


def _parse_spec(raw: dict[str, Any]) -> PrincipleSpec:
    return PrincipleSpec(
        id=raw["id"],
        description=raw.get("description", ""),
        asi_codes=tuple(raw.get("asi_codes") or []),
        atlas_codes=tuple(raw.get("atlas_codes") or []),
        rationale=raw.get("rationale", ""),
    )


def load_principles(version: int | None = None) -> list[PrincipleSpec]:
    """Load the principles set for the given version.

    Args:
        version: Principles version integer (1 or 2). When ``None``,
            reads ``TESSERA_PRINCIPLES_VERSION`` from the environment;
            defaults to ``1`` if the variable is absent or invalid.

    Returns:
        Ordered list of :class:`PrincipleSpec` records.

    Raises:
        FileNotFoundError: When the requested YAML file does not exist.
        ValueError: When the YAML does not contain a ``principles`` list.
    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "PyYAML is required for principles loading; "
            "add 'pyyaml' to your dependencies"
        ) from exc

    if version is None:
        raw_env = os.environ.get("TESSERA_PRINCIPLES_VERSION", "1").strip()
        try:
            version = int(raw_env)
        except ValueError:
            version = 1

    filename = f"v{version}.yaml"
    path = _PRINCIPLES_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Principles file not found: {path}. "
            f"Valid values for TESSERA_PRINCIPLES_VERSION: 1, 2."
        )

    with path.open("r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    principles_raw = doc.get("principles")
    if not isinstance(principles_raw, list):
        raise ValueError(f"{path}: missing or invalid 'principles' list")

    return [_parse_spec(p) for p in principles_raw]


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
    "PrincipleSpec",
    "PrincipleViolation",
    "deterministic_pre_check",
    "evaluate_no_exfiltration",
    "evaluate_origin_consistency",
    "evaluate_untrusted_arg_reasonable",
    "load_principles",
]
