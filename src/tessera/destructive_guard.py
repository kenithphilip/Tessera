"""Explicit pattern-based deny list for destructive operations.

Complements ``tessera.risk.irreversibility`` which computes a numeric
score. This module answers a simpler question: is this specific
command or tool-arg pattern in the known-destructive set?

Explicit denials are easier to audit than threshold-based scores.
Operations teams can point to a specific rule when explaining why a
call was blocked. Use both: the scorer for nuanced cases, this module
for the ones you never want to see.

References:
- Sondera sondera-coding-agent-hooks destructive.cedar policy
  (https://github.com/sondera-ai/sondera-coding-agent-hooks)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity of a destructive operation match.

    BLOCK: always block, no override. Catastrophic and irreversible.
    WARN: block by default but callers may override with explicit approval.
    INFO: allow but emit a security event for audit.
    """

    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class DestructiveMatch:
    """A single pattern that fired against the input.

    Attributes:
        rule_id: Stable identifier for the rule (e.g., "rm-rf-root").
        severity: Severity level.
        description: Human-readable explanation.
        matched_text: The substring of input that matched.
    """

    rule_id: str
    severity: Severity
    description: str
    matched_text: str


@dataclass(frozen=True)
class DestructiveCheckResult:
    """Result of checking a tool call for destructive patterns.

    Attributes:
        destructive: True if any rule matched.
        max_severity: Highest severity among matches, or None if clean.
        matches: All rules that fired.
    """

    destructive: bool
    max_severity: Severity | None
    matches: tuple[DestructiveMatch, ...]

    @property
    def should_block(self) -> bool:
        """True if any match is at BLOCK severity."""
        return any(m.severity == Severity.BLOCK for m in self.matches)


# Each rule: (rule_id, severity, description, regex).
# Matches are case-insensitive unless the pattern specifies otherwise.
_RULES: tuple[tuple[str, Severity, str, re.Pattern[str]], ...] = (
    # Filesystem destruction
    (
        "rm-rf-root",
        Severity.BLOCK,
        "recursive force-delete of a root or filesystem path",
        re.compile(r"\brm\s+(-[a-zA-Z]*[rRf][a-zA-Z]*)+\s+(/|~|/\*|/\w+)(\s|$)"),
    ),
    (
        "rm-rf-generic",
        Severity.WARN,
        "recursive force-delete (rm -rf)",
        re.compile(r"\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*|-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*)\s"),
    ),
    (
        "shred",
        Severity.BLOCK,
        "secure file wipe (shred)",
        re.compile(r"\bshred\s+-"),
    ),
    (
        "dd-of-device",
        Severity.BLOCK,
        "dd write to a raw device (disk wipe)",
        re.compile(r"\bdd\s+(?:[^&|]*\s)?of=/dev/(?:sd[a-z]|nvme|disk\d|xvd)", re.IGNORECASE),
    ),
    (
        "mkfs",
        Severity.BLOCK,
        "filesystem format (mkfs)",
        re.compile(r"\bmkfs(\.[a-z0-9]+)?\s+/dev/", re.IGNORECASE),
    ),

    # Git destructive operations
    (
        "git-force-push-main",
        Severity.BLOCK,
        "force-push to a protected branch (main/master/production)",
        re.compile(
            r"\bgit\s+push\s+(?:--force|-f)\b[^&|]*\b(main|master|production|release|prod)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "git-force-push-generic",
        Severity.WARN,
        "force-push to any branch",
        re.compile(r"\bgit\s+push\s+(?:--force|-f)\b", re.IGNORECASE),
    ),
    (
        "git-reset-hard",
        Severity.WARN,
        "hard reset (discards working tree)",
        re.compile(r"\bgit\s+reset\s+--hard\b", re.IGNORECASE),
    ),
    (
        "git-clean-force",
        Severity.WARN,
        "force-clean untracked files",
        re.compile(r"\bgit\s+clean\s+(?:-[a-z]*[fF])", re.IGNORECASE),
    ),
    (
        "git-branch-delete-force",
        Severity.WARN,
        "force-delete a branch (git branch -D)",
        re.compile(r"\bgit\s+branch\s+-D\b", re.IGNORECASE),
    ),

    # Database destruction
    (
        "drop-database",
        Severity.BLOCK,
        "DROP DATABASE statement",
        re.compile(r"\bdrop\s+database\b", re.IGNORECASE),
    ),
    (
        "drop-table",
        Severity.WARN,
        "DROP TABLE statement",
        re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    ),
    (
        "truncate-table",
        Severity.WARN,
        "TRUNCATE TABLE statement",
        re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
    ),
    (
        "delete-without-where",
        Severity.WARN,
        "DELETE without WHERE clause",
        re.compile(r"\bdelete\s+from\s+\w+\s*(?:;|$)", re.IGNORECASE),
    ),

    # Infrastructure teardown
    (
        "terraform-destroy",
        Severity.BLOCK,
        "terraform destroy (tears down infrastructure)",
        re.compile(r"\bterraform\s+destroy\b", re.IGNORECASE),
    ),
    (
        "docker-system-prune-force",
        Severity.WARN,
        "docker system prune with force (removes all unused)",
        re.compile(r"\bdocker\s+system\s+prune\s+.*(-f|--force|-a)", re.IGNORECASE),
    ),
    (
        "kubectl-delete-all",
        Severity.BLOCK,
        "kubectl delete all resources",
        re.compile(r"\bkubectl\s+delete\s+(?:all|deployment|statefulset|ns|namespace)\s+--all\b", re.IGNORECASE),
    ),

    # Lock file destruction
    (
        "delete-lock-file",
        Severity.WARN,
        "deleting a dependency lock file (supply-chain integrity risk)",
        re.compile(r"\brm\s+(?:-\w*\s+)*(?:\S*/)?(package-lock\.json|yarn\.lock|poetry\.lock|Pipfile\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|go\.sum)\b"),
    ),

    # Process management
    (
        "kill-9-pid-1",
        Severity.BLOCK,
        "SIGKILL to PID 1 (init)",
        re.compile(r"\bkill\s+-9\s+1\b"),
    ),
    (
        "pkill-everything",
        Severity.WARN,
        "pkill or killall with broad target",
        re.compile(r"\b(pkill|killall)\s+-9\b"),
    ),

    # Permission / ownership rewrites
    (
        "chmod-recursive-000",
        Severity.BLOCK,
        "recursive chmod to 000 (lock everyone out)",
        re.compile(r"\bchmod\s+-R\s+0*(000|400)\s+/"),
    ),
    (
        "chown-recursive-root",
        Severity.WARN,
        "recursive chown on root path",
        re.compile(r"\bchown\s+-R\s+\S+\s+/(?:\s|$)"),
    ),
)


def check_destructive(text: str) -> DestructiveCheckResult:
    """Scan text for destructive operation patterns.

    Args:
        text: A shell command, SQL statement, or tool-arg string.

    Returns:
        A DestructiveCheckResult with all matches, the max severity,
        and a ``should_block`` convenience flag.
    """
    if not text:
        return DestructiveCheckResult(
            destructive=False,
            max_severity=None,
            matches=(),
        )

    matches: list[DestructiveMatch] = []
    for rule_id, severity, description, pattern in _RULES:
        m = pattern.search(text)
        if m:
            matches.append(DestructiveMatch(
                rule_id=rule_id,
                severity=severity,
                description=description,
                matched_text=m.group(0),
            ))

    if not matches:
        return DestructiveCheckResult(
            destructive=False,
            max_severity=None,
            matches=(),
        )

    # Max severity: BLOCK > WARN > INFO
    order = {Severity.BLOCK: 2, Severity.WARN: 1, Severity.INFO: 0}
    max_sev = max((m.severity for m in matches), key=lambda s: order[s])

    return DestructiveCheckResult(
        destructive=True,
        max_severity=max_sev,
        matches=tuple(matches),
    )


def check_tool_args(args: dict[str, object]) -> DestructiveCheckResult:
    """Check tool-call arguments for destructive patterns.

    Flattens string-valued arguments and scans the concatenation.
    Useful when the destructive text is passed as a ``command`` or
    ``query`` argument rather than the tool name.

    Args:
        args: Tool-call argument dict.

    Returns:
        DestructiveCheckResult over all string arg values.
    """
    if not args:
        return DestructiveCheckResult(
            destructive=False,
            max_severity=None,
            matches=(),
        )
    combined = "\n".join(
        str(v) for v in args.values() if isinstance(v, (str, bytes))
    )
    return check_destructive(combined)
