"""Static-analysis checks for provenance-coverage gaps.

The :func:`provenance_tracked` decorator (see
:mod:`tessera.taint.instrument`) rewrites a function so f-strings
and a few other operators preserve labels. For label preservation
to hold across an entire pipeline, every adapter handler that
accepts labeled input must be decorated. This module's
:func:`check_provenance_coverage` walks a target package and reports
which functions are missing the decorator.

The check is deterministic, source-only (no import side effects),
and intended for use in CI:

    from tessera.lint import check_provenance_coverage
    missing = check_provenance_coverage(["src/tessera/adapters"])
    if missing:
        sys.exit("\\n".join(missing))

Heuristics
----------

A function "needs" the decorator when it meets ALL of:

- It is defined at module top level (nested functions are not
  registered as adapter entry points).
- Its name matches one of the configured patterns: ``handle_*``,
  ``process_*``, ``on_*``, ``run_*``, or ``execute_*`` (the
  conventional adapter-handler shapes), OR the function has a
  parameter annotated with one of the labeled types
  (:class:`tessera.taint.label.LabeledValue`,
  :class:`tessera.taint.label.ProvenanceLabel`,
  :class:`tessera.taint.tstr.TaintedStr`).
- It does NOT already have the ``@provenance_tracked`` decorator
  (matched by attribute name; the import alias is irrelevant).

The default pattern set is conservative: false positives can be
silenced with the ``ALLOWLIST`` set (see below). False negatives
(handlers that should be tracked but aren't matched by any
pattern) require either renaming the function or adding the
decorator manually.

Reference
---------

- ``docs/strategy/2026-04-engineering-brief.md`` Section 1.4
  (label-recovery boundary).
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

#: Function-name prefixes that conventionally indicate an adapter
#: handler entry point. Match is case-sensitive and prefix-based
#: (``startswith``).
HANDLER_PREFIXES: tuple[str, ...] = (
    "handle_",
    "process_",
    "on_",
    "run_",
    "execute_",
)

#: Type names that, when used as a parameter annotation, signal
#: that the function is operating on labeled input. Matched against
#: the AST representation of the annotation (``ast.Name.id`` and
#: ``ast.Attribute.attr``).
LABELED_TYPE_NAMES: frozenset[str] = frozenset(
    {"LabeledValue", "ProvenanceLabel", "TaintedStr", "TaintedValue"}
)

#: Decorator names recognized as the provenance-tracked decorator.
#: Match against ``ast.Name.id`` for ``@provenance_tracked``
#: and against ``ast.Attribute.attr`` for
#: ``@tessera.taint.instrument.provenance_tracked``.
DECORATOR_NAMES: frozenset[str] = frozenset({"provenance_tracked"})

#: Default allowlist of fully-qualified names ``module.qualname``
#: known to be exempt from the check. Tests, internal stubs, and
#: legacy callbacks belong here.
DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Add module.qualname strings here once the lint check has
        # surfaced legitimate exceptions during Phase 1B-ii rollout.
    }
)


@dataclass(frozen=True, slots=True)
class CoverageGap:
    """One function missing the @provenance_tracked decorator."""

    module: str
    qualname: str
    file_path: str
    line: int
    reason: str

    def format(self) -> str:
        return (
            f"{self.file_path}:{self.line}: function "
            f"{self.module}.{self.qualname} is missing "
            f"@provenance_tracked ({self.reason})"
        )


def _decorator_matches_tracked(decorator: ast.expr) -> bool:
    """Return True when the decorator is @provenance_tracked or
    @tessera.taint.instrument.provenance_tracked or any equivalent."""
    target = decorator
    if isinstance(target, ast.Call):
        target = target.func
    if isinstance(target, ast.Name):
        return target.id in DECORATOR_NAMES
    if isinstance(target, ast.Attribute):
        return target.attr in DECORATOR_NAMES
    return False


def _annotation_is_labeled(annotation: ast.expr | None) -> bool:
    if annotation is None:
        return False
    if isinstance(annotation, ast.Name):
        return annotation.id in LABELED_TYPE_NAMES
    if isinstance(annotation, ast.Attribute):
        return annotation.attr in LABELED_TYPE_NAMES
    if isinstance(annotation, ast.Subscript):
        return _annotation_is_labeled(annotation.value)
    return False


def _function_needs_tracking(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[bool, str]:
    """Return (needs_tracking, reason) for a top-level function."""
    name = node.name
    if any(name.startswith(p) for p in HANDLER_PREFIXES):
        return True, f"name matches handler prefix in {HANDLER_PREFIXES!r}"
    args = list(node.args.args) + list(node.args.kwonlyargs)
    for arg in args:
        if _annotation_is_labeled(arg.annotation):
            return True, f"parameter {arg.arg!r} is annotated with a labeled type"
    return False, ""


def _walk_module(file_path: Path, module: str) -> Iterable[CoverageGap]:
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        needs, reason = _function_needs_tracking(node)
        if not needs:
            continue
        if any(_decorator_matches_tracked(d) for d in node.decorator_list):
            continue
        qualname = node.name
        fq = f"{module}.{qualname}"
        if fq in DEFAULT_ALLOWLIST:
            continue
        yield CoverageGap(
            module=module,
            qualname=qualname,
            file_path=str(file_path),
            line=node.lineno,
            reason=reason,
        )


def _module_name_for(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = rel.parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def check_provenance_coverage(
    targets: Iterable[str | os.PathLike[str]],
    *,
    allowlist: Iterable[str] = (),
) -> list[CoverageGap]:
    """Scan ``targets`` for functions missing ``@provenance_tracked``.

    Args:
        targets: Iterable of file or directory paths. Directories
            are scanned recursively for ``.py`` files.
        allowlist: Iterable of ``module.qualname`` strings to skip.
            Merged with :data:`DEFAULT_ALLOWLIST`.

    Returns:
        List of :class:`CoverageGap` entries; empty when every
        candidate function carries the decorator. Sort order is
        stable: by file path then line.
    """
    explicit_allowlist = frozenset(allowlist) | DEFAULT_ALLOWLIST
    gaps: list[CoverageGap] = []
    for raw in targets:
        target = Path(raw)
        if target.is_file():
            module = target.with_suffix("").name
            for gap in _walk_module(target, module):
                if f"{gap.module}.{gap.qualname}" not in explicit_allowlist:
                    gaps.append(gap)
            continue
        if not target.is_dir():
            continue
        # Use the directory name as the package root.
        for path in sorted(target.rglob("*.py")):
            module = _module_name_for(path, target.parent)
            for gap in _walk_module(path, module):
                if f"{gap.module}.{gap.qualname}" not in explicit_allowlist:
                    gaps.append(gap)
    gaps.sort(key=lambda g: (g.file_path, g.line))
    return gaps


__all__ = [
    "CoverageGap",
    "DECORATOR_NAMES",
    "DEFAULT_ALLOWLIST",
    "HANDLER_PREFIXES",
    "LABELED_TYPE_NAMES",
    "check_provenance_coverage",
]
