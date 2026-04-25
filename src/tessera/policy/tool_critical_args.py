"""Per-tool critical-argument specs for argument-level enforcement.

Replaces the four flat ``CRITICAL_ARGS_*`` frozensets in
:mod:`tessera.taint` with a structured table that captures the
information argument-level provenance enforcement needs:

- **required_integrity**: minimum :class:`IntegrityLevel` for the
  argument value's label.
- **audience_check**: when True, the argument value's
  :class:`ProvenanceLabel.readers` set must include the tool's
  audience principal.
- **capacity_max**: cap on the value's :class:`InformationCapacity`;
  set to e.g. ``NUMBER`` for ``transfer_funds.amount`` so a
  STRING-capacity (unbounded) value cannot become a transfer
  amount.

Backward compatibility
----------------------

The legacy ``CRITICAL_ARGS_SEND`` etc. constants in
:mod:`tessera.taint` keep working: they are now computed properties
that derive their value from this table. The
:func:`critical_arg_names_for` helper returns just the names for a
tool, matching the old ``frozenset[str]`` contract.

Enforcement mode
----------------

The ``TESSERA_ENFORCEMENT_MODE`` environment variable controls which
enforcement path is primary:

- ``scalar``: legacy ``min_trust`` floor only (v0.7 behavior).
- ``args``: argument-level + critical_args only (v1.0 default per
  ADR 0006).
- ``both``: both checks must pass (v0.12 default for the parallel
  evaluation phase).

The default is ``both`` for v0.12; Phase 4 wave 4A flips the default
to ``args``.

References
----------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.6
- ``docs/adr/0006-arg-level-provenance-primary.md``
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from tessera.taint.label import InformationCapacity, IntegrityLevel


@dataclass(frozen=True, slots=True)
class CriticalArgSpec:
    """One argument's enforcement spec.

    Attributes:
        name: Argument name as it appears in the tool's input schema.
        required_integrity: Minimum integrity level required. The
            value's label must satisfy ``label.integrity <=
            required_integrity`` (recall the IntegrityLevel numerics:
            TRUSTED=0 < ENDORSED=1 < UNTRUSTED=2; lower int is more
            trusted).
        audience_check: When True, the value's readers set must
            include the tool's audience principal. Used for tools
            that exfiltrate to external destinations (send_email,
            transfer_funds): the recipient must be allowed to read
            the data being sent.
        capacity_max: Maximum InformationCapacity allowed. ``None``
            means no cap (any capacity allowed). Set to BOOL / ENUM /
            NUMBER for tools that should reject STRING-capacity
            (unbounded) inputs.
        description: Human-readable rationale; surfaced in audit
            events when the spec denies a tool call.
    """

    name: str
    required_integrity: IntegrityLevel = IntegrityLevel.TRUSTED
    audience_check: bool = False
    capacity_max: InformationCapacity | None = None
    description: str = ""


class EnforcementMode(StrEnum):
    """Values for the ``TESSERA_ENFORCEMENT_MODE`` env var."""

    SCALAR = "scalar"
    ARGS = "args"
    BOTH = "both"


_SCALAR_DEPRECATION_WARNED: bool = False


def get_enforcement_mode() -> EnforcementMode:
    """Return the active enforcement mode.

    Reads ``TESSERA_ENFORCEMENT_MODE`` from the environment with
    case-insensitive matching. The v1.0 default is
    :attr:`EnforcementMode.ARGS` per ADR 0006; operators upgrading
    from v0.x can pin the v0.12 behavior with
    ``TESSERA_ENFORCEMENT_MODE=both`` (or the legacy
    ``TESSERA_ENFORCEMENT_MODE=scalar`` for the v0.7 single-floor
    path). Unknown values fail safe to ``ARGS``: an operator with
    a typo gets the v1.0 default rather than silently falling back
    to legacy behavior.

    The legacy ``scalar`` mode emits a one-time
    :class:`DeprecationWarning` at first call so operators see the
    cutover path. The mode itself remains supported through the
    v1.x line; removal would land in v2.0 with a 12-month
    deprecation window per ``docs/api_stability/v1.0_freeze.md``.
    """
    global _SCALAR_DEPRECATION_WARNED
    raw = os.environ.get("TESSERA_ENFORCEMENT_MODE", "args").strip().lower()
    try:
        mode = EnforcementMode(raw)
    except ValueError:
        return EnforcementMode.ARGS
    if mode == EnforcementMode.SCALAR and not _SCALAR_DEPRECATION_WARNED:
        import warnings

        warnings.warn(
            "TESSERA_ENFORCEMENT_MODE=scalar is the v0.7-era legacy "
            "path that relies on Context.min_trust as the only gate. "
            "v1.0 default is 'args'; the 'scalar' path remains as a "
            "back-compat shim through the v1.x line. See "
            "docs/migration/v1.0-enforcement-mode.md for the cutover "
            "path.",
            DeprecationWarning,
            stacklevel=2,
        )
        _SCALAR_DEPRECATION_WARNED = True
    return mode


# ---------------------------------------------------------------------------
# Per-tool critical-argument table
# ---------------------------------------------------------------------------

#: Maps tool name (or fnmatch glob) to the list of critical arg
#: specs the policy engine must check before the tool call fires.
#: Glob patterns are matched in registration order; exact matches
#: take precedence over patterns.
CRITICAL_ARGS: dict[str, list[CriticalArgSpec]] = {
    "send_email": [
        CriticalArgSpec(
            name="to",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
            description=(
                "Recipient of an email must be user-authorized; an "
                "untrusted source cannot redirect a message."
            ),
        ),
        CriticalArgSpec(
            name="cc",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
            description="Same rationale as `to`.",
        ),
        CriticalArgSpec(
            name="bcc",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
            description="Same rationale as `to`.",
        ),
        CriticalArgSpec(
            name="body",
            required_integrity=IntegrityLevel.ENDORSED,
            description=(
                "Email body may include endorsed (declassified-via-"
                "capacity) tool output, but not raw untrusted bytes."
            ),
        ),
    ],
    "send_message": [
        CriticalArgSpec(
            name="to",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
        ),
        CriticalArgSpec(
            name="recipient",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
        ),
    ],
    "transfer_funds": [
        CriticalArgSpec(
            name="amount",
            required_integrity=IntegrityLevel.TRUSTED,
            capacity_max=InformationCapacity.NUMBER,
            description=(
                "Transfer amount must be user-specified and bounded; "
                "STRING-capacity inputs are rejected."
            ),
        ),
        CriticalArgSpec(
            name="recipient",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
        ),
        CriticalArgSpec(
            name="account",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
        ),
        CriticalArgSpec(
            name="iban",
            required_integrity=IntegrityLevel.TRUSTED,
            audience_check=True,
        ),
    ],
    "write_file": [
        CriticalArgSpec(
            name="path",
            required_integrity=IntegrityLevel.TRUSTED,
            description=(
                "Filesystem destinations must be user-specified to "
                "prevent path-traversal redirects from untrusted "
                "tool output."
            ),
        ),
        CriticalArgSpec(
            name="filename",
            required_integrity=IntegrityLevel.TRUSTED,
        ),
    ],
    "execute": [
        CriticalArgSpec(
            name="command",
            required_integrity=IntegrityLevel.TRUSTED,
            description=(
                "Shell commands must be user-specified; an untrusted "
                "source cannot inject a command."
            ),
        ),
        CriticalArgSpec(
            name="code",
            required_integrity=IntegrityLevel.TRUSTED,
        ),
        CriticalArgSpec(
            name="script",
            required_integrity=IntegrityLevel.TRUSTED,
        ),
        CriticalArgSpec(
            name="query",
            required_integrity=IntegrityLevel.ENDORSED,
            description=(
                "Database queries may be parameterized from endorsed "
                "tool output but never from raw untrusted text."
            ),
        ),
    ],
}


def specs_for(tool_name: str) -> list[CriticalArgSpec]:
    """Return the critical-arg specs for a tool name.

    Exact matches take precedence over patterns. Patterns are
    matched in registration order. Returns an empty list for tools
    with no specs (taint-floor or CEL alone may still gate them).
    """
    if tool_name in CRITICAL_ARGS:
        return CRITICAL_ARGS[tool_name]
    # Future: fnmatch over patterns once we have any in the table.
    return []


def critical_arg_names_for(tool_name: str) -> frozenset[str]:
    """Backward-compatible shim: return just the arg names a tool
    cares about. Matches the v0.7 ``frozenset[str]`` contract used
    by :class:`tessera.taint.DependencyAccumulator.evaluate_args`."""
    return frozenset(spec.name for spec in specs_for(tool_name))


# ---------------------------------------------------------------------------
# Backward-compat constants (the legacy CRITICAL_ARGS_* sets)
# ---------------------------------------------------------------------------
#
# These derive from the table above. They keep the v0.7 import surface
# (``from tessera.taint import CRITICAL_ARGS_SEND``) working unchanged.
# Computed at import time; if a caller mutates the underlying
# CRITICAL_ARGS table at runtime, they should call
# ``recompute_legacy_constants()`` to refresh.

CRITICAL_ARGS_SEND: frozenset[str] = (
    critical_arg_names_for("send_email")
    | critical_arg_names_for("send_message")
)

CRITICAL_ARGS_TRANSFER: frozenset[str] = critical_arg_names_for("transfer_funds")

CRITICAL_ARGS_WRITE: frozenset[str] = critical_arg_names_for("write_file") | frozenset(
    {"url", "endpoint"}
)

CRITICAL_ARGS_EXECUTE: frozenset[str] = critical_arg_names_for("execute")


def recompute_legacy_constants() -> None:
    """Refresh the four ``CRITICAL_ARGS_*`` shim constants after a
    runtime modification to :data:`CRITICAL_ARGS`. Most callers do
    not need this; the constants are computed at import time."""
    global CRITICAL_ARGS_SEND, CRITICAL_ARGS_TRANSFER
    global CRITICAL_ARGS_WRITE, CRITICAL_ARGS_EXECUTE
    CRITICAL_ARGS_SEND = critical_arg_names_for("send_email") | critical_arg_names_for(
        "send_message"
    )
    CRITICAL_ARGS_TRANSFER = critical_arg_names_for("transfer_funds")
    CRITICAL_ARGS_WRITE = critical_arg_names_for("write_file") | frozenset(
        {"url", "endpoint"}
    )
    CRITICAL_ARGS_EXECUTE = critical_arg_names_for("execute")


__all__ = [
    "CRITICAL_ARGS",
    "CRITICAL_ARGS_EXECUTE",
    "CRITICAL_ARGS_SEND",
    "CRITICAL_ARGS_TRANSFER",
    "CRITICAL_ARGS_WRITE",
    "CriticalArgSpec",
    "EnforcementMode",
    "critical_arg_names_for",
    "get_enforcement_mode",
    "recompute_legacy_constants",
    "specs_for",
]
