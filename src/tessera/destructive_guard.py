"""tessera.destructive_guard: explicit pattern deny for destructive operations.

Why separate from the irreversibility scorer
--------------------------------------------
The scorer returns a float; thresholds are tunable, every decision has
some epistemic wiggle room. This module returns booleans backed by named
patterns. An audit entry looks like ``denied: destructive.fs.rm_rf_root``
instead of ``denied: score=0.87 > 0.85``. That asymmetry is the whole
point: some actions have no defensible reason to appear in an arg
string and should never depend on a tunable.

Matching model
--------------
Every pattern is compiled once. ``check(tool_name, args)`` flattens
args into ``(arg_path, text)`` pairs (e.g. ``headers.x-run``) so audit
log entries can attribute the match to a specific argument. Patterns
may be scoped to a tool family via ``applies_to_tools``; leaving that
empty means "applies to any tool's args", which is the right default
for string-level invariants like ``rm -rf /``.

Scope of the rm -rf rule
------------------------
``fs.rm_rf_root`` only blocks when the target is terminally root or
home (``/``, ``/*``, ``~``, ``~/*``, ``$HOME``, ``$HOME/*``). Coding
agents legitimately need to ``rm -rf node_modules`` or ``dist`` and
blocking those would be hostile. If you want stricter behavior (e.g.,
block any ``rm -rf ~/...`` regardless of subpath), pass a custom
pattern via ``DestructiveGuard(extra=[...])``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DestructivePattern:
    """A single named destructive pattern.

    Attributes:
        id: Stable identifier for audit logs (e.g. ``fs.rm_rf_root``).
        description: Human-readable explanation.
        regex: Compiled pattern, applied to flattened arg text.
        category: Coarse grouping (filesystem, sql, git, iac, host).
        applies_to_tools: Restrict the rule to specific tools. Empty
            tuple means "applies to any tool's args".
    """

    id: str
    description: str
    regex: re.Pattern
    category: str
    applies_to_tools: tuple[str, ...] = ()

    def applies(self, tool_name: str) -> bool:
        if not self.applies_to_tools:
            return True
        return tool_name in self.applies_to_tools


_DEFAULT_PATTERNS: tuple[DestructivePattern, ...] = (
    # ---- filesystem ----
    DestructivePattern(
        id="fs.rm_rf_root",
        description="rm -rf on root or home",
        regex=re.compile(
            r"(?<!\S)rm\s+(?:-[a-zA-Z]*(?:[rR][a-zA-Z]*[fF]|[fF][a-zA-Z]*[rR])[a-zA-Z]*)\s+"
            r"(?:--no-preserve-root\s+)?"
            r"(?:/|/\*|~|~/\*|\$HOME|\$HOME/\*)"
            r"(?=\s|$|;|\||&)"
        ),
        category="filesystem",
    ),
    DestructivePattern(
        id="fs.no_preserve_root",
        description="rm invoked with --no-preserve-root",
        regex=re.compile(r"(?<!\S)rm\s+[^|&;]*--no-preserve-root\b"),
        category="filesystem",
    ),
    DestructivePattern(
        id="fs.dd_to_disk",
        description="dd writing to a block device",
        regex=re.compile(r"(?<!\S)dd\s+[^|&;]*\bof=/dev/(?:sd[a-z]|nvme\d|hd[a-z]|mmcblk\d)"),
        category="filesystem",
    ),
    DestructivePattern(
        id="fs.mkfs",
        description="mkfs invocation (reformat)",
        regex=re.compile(r"(?<!\S)mkfs(?:\.[a-z0-9]+)?\s+/dev/"),
        category="filesystem",
    ),
    DestructivePattern(
        id="fs.find_delete_broad",
        description="find with -delete at / or ~",
        regex=re.compile(r"(?<!\S)find\s+(?:/|~)\s+[^|&;]*\s-delete\b"),
        category="filesystem",
    ),
    DestructivePattern(
        id="fs.chmod_777_recursive_root",
        description="chmod -R 777 against /, ~, or /*",
        regex=re.compile(
            r"(?<!\S)chmod\s+-R\s+0?777\s+(?:/|~|/\*)(?=\s|$|;|\||&)"
        ),
        category="filesystem",
    ),
    # ---- shell / host ----
    DestructivePattern(
        id="host.forkbomb",
        description="classic bash fork bomb",
        regex=re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        category="host",
    ),
    DestructivePattern(
        id="host.shutdown",
        description="immediate shutdown/halt/poweroff",
        regex=re.compile(
            r"(?<!\S)(?:shutdown\s+(?:-h|-r|/s|/r)\s+(?:now|0|\+0)|"
            r"halt(?:\s+-p)?|poweroff|init\s+0|init\s+6)\b"
        ),
        category="host",
    ),
    # ---- SQL ----
    DestructivePattern(
        id="sql.drop_database",
        description="DROP DATABASE / SCHEMA",
        regex=re.compile(r"\bDROP\s+(?:DATABASE|SCHEMA)\b", re.IGNORECASE),
        category="sql",
    ),
    DestructivePattern(
        id="sql.drop_table",
        description="DROP TABLE",
        regex=re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
        category="sql",
    ),
    DestructivePattern(
        id="sql.truncate",
        description="TRUNCATE TABLE",
        regex=re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?[\w.`\"]+", re.IGNORECASE),
        category="sql",
    ),
    DestructivePattern(
        id="sql.delete_unscoped",
        description="DELETE with no WHERE clause",
        regex=re.compile(
            r"\bDELETE\s+FROM\s+[\w.`\"]+\s*(?:;|$|--)",
            re.IGNORECASE | re.MULTILINE,
        ),
        category="sql",
    ),
    DestructivePattern(
        id="sql.delete_tautology",
        description="DELETE with always-true predicate",
        regex=re.compile(
            r"\bDELETE\s+FROM\s+[\w.`\"]+\s+WHERE\s+(?:1\s*=\s*1|true|'a'\s*=\s*'a')",
            re.IGNORECASE,
        ),
        category="sql",
    ),
    DestructivePattern(
        id="sql.update_unscoped",
        description="UPDATE with no WHERE clause",
        regex=re.compile(
            r"\bUPDATE\s+[\w.`\"]+\s+SET\s+(?:(?!\bWHERE\b)[^;])+?(?:;|$)",
            re.IGNORECASE | re.DOTALL,
        ),
        category="sql",
    ),
    # ---- git ----
    DestructivePattern(
        id="git.push_force_protected",
        description="force push to main/master/release",
        regex=re.compile(
            r"(?<!\S)git\s+push\s+(?:[^|&;]*?\s)?(?:--force(?!-with-lease)|-f)\b"
            r"[^|&;]*\b(?:main|master|release/|prod)\b"
        ),
        category="git",
    ),
    DestructivePattern(
        id="git.clean_fdx",
        description="git clean -fdx (wipe ignored+untracked)",
        regex=re.compile(r"(?<!\S)git\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*d[a-zA-Z]*x\b"),
        category="git",
    ),
    DestructivePattern(
        id="git.reset_hard_remote",
        description="git reset --hard to a remote ref",
        regex=re.compile(
            r"(?<!\S)git\s+reset\s+--hard\s+(?:origin|upstream|remote)/\S+"
        ),
        category="git",
    ),
    # ---- cloud / infra ----
    DestructivePattern(
        id="iac.terraform_destroy_auto",
        description="terraform destroy -auto-approve",
        regex=re.compile(r"(?<!\S)terraform\s+destroy\b[^|&;]*\s-auto-approve\b"),
        category="iac",
    ),
    DestructivePattern(
        id="iac.k8s_delete_all_force",
        description="kubectl delete --all --force --grace-period=0",
        regex=re.compile(
            r"(?<!\S)kubectl\s+delete\b[^|&;]*\s--all\b[^|&;]*\s--force\b"
            r"[^|&;]*\s--grace-period\s*=?\s*0"
        ),
        category="iac",
    ),
    DestructivePattern(
        id="iac.aws_s3_rb_force",
        description="aws s3 rb --force",
        regex=re.compile(r"(?<!\S)aws\s+s3\s+rb\s+[^|&;]*--force\b"),
        category="iac",
    ),
)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardMatch:
    """A single pattern match attributed to a specific argument path."""

    pattern_id: str
    category: str
    description: str
    matched_text: str
    arg_path: str  # e.g. "command", "query", "headers.x-run"


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    matches: tuple[GuardMatch, ...] = field(default_factory=tuple)
    source: str = "tessera.destructive_guard"

    @property
    def primary_reason(self) -> str:
        if self.allowed:
            return ""
        m = self.matches[0]
        return f"{m.pattern_id}: {m.description}"


class DestructiveGuard:
    """Match known-destructive patterns against tool arguments.

    Usage::

        guard = DestructiveGuard()
        result = guard.check("bash.run", {"command": "rm -rf /"})
        if not result.allowed:
            return Decision.deny(reason=result.primary_reason, ...)

    Extending::

        guard = DestructiveGuard(extra=[DestructivePattern(...)])
        guard.register(DestructivePattern(...))

    Args:
        patterns: Replace the default pattern set entirely.
        extra: Add patterns on top of defaults (or `patterns`).
        include_defaults: Set False with `patterns=...` for full control.
    """

    def __init__(
        self,
        patterns: Iterable[DestructivePattern] | None = None,
        extra: Iterable[DestructivePattern] | None = None,
        include_defaults: bool = True,
    ) -> None:
        base: list[DestructivePattern] = []
        if include_defaults:
            base.extend(_DEFAULT_PATTERNS)
        if patterns is not None:
            base = list(patterns)
        if extra:
            base.extend(extra)
        self._patterns: tuple[DestructivePattern, ...] = tuple(base)

    def register(self, pattern: DestructivePattern) -> None:
        self._patterns = self._patterns + (pattern,)

    def patterns(self) -> tuple[DestructivePattern, ...]:
        return self._patterns

    def check(
        self,
        tool_name: str,
        args: str | Mapping[str, Any] | Sequence[Any] | None,
        *,
        stop_on_first: bool = True,
    ) -> GuardResult:
        if args is None:
            return GuardResult(allowed=True)
        flattened = list(_flatten_args(args))
        matches: list[GuardMatch] = []

        for pattern in self._patterns:
            if not pattern.applies(tool_name):
                continue
            for path, value in flattened:
                m = pattern.regex.search(value)
                if m is None:
                    continue
                matches.append(
                    GuardMatch(
                        pattern_id=pattern.id,
                        category=pattern.category,
                        description=pattern.description,
                        matched_text=m.group(0)[:200],
                        arg_path=path,
                    )
                )
                if stop_on_first:
                    return GuardResult(allowed=False, matches=tuple(matches))

        if matches:
            return GuardResult(allowed=False, matches=tuple(matches))
        return GuardResult(allowed=True)


def _flatten_args(
    args: str | Mapping[str, Any] | Sequence[Any] | Any,
    prefix: str = "",
) -> Iterable[tuple[str, str]]:
    """Yield (arg_path, text) pairs.

    Non-string leaves are JSON-serialized so numeric or bool values do
    not silently slip past pattern matchers that happen to be checking
    adjacent string tokens.
    """
    if args is None:
        return
    if isinstance(args, str):
        yield (prefix or "$", args)
        return
    if isinstance(args, (bytes, bytearray)):
        try:
            yield (prefix or "$", bytes(args).decode("utf-8", errors="replace"))
        except Exception:
            return
        return
    if isinstance(args, Mapping):
        for k, v in args.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten_args(v, child)
        return
    if isinstance(args, (list, tuple)):
        for i, v in enumerate(args):
            child = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _flatten_args(v, child)
        return
    try:
        yield (prefix or "$", json.dumps(args, default=str))
    except Exception:
        yield (prefix or "$", str(args))


__all__ = [
    "DestructivePattern",
    "GuardMatch",
    "GuardResult",
    "DestructiveGuard",
]
