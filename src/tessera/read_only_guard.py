"""Argument validation for read-only tools.

Side-effect-free tools bypass the taint-floor denial because they
cannot modify external state. But they CAN exfiltrate data: a
read_file("/etc/passwd") or search_database("SELECT * FROM users")
where the argument came from an untrusted segment leaks sensitive
content into the model's context, which may then appear in the
response to the user.

This module validates arguments on read-only tool calls to catch:

1. Path traversal: arguments containing "../", absolute paths to
   sensitive directories (/etc, /root, ~/.ssh), or home directory
   references injected by attacker content.

2. Data access expansion: arguments that access broader data than
   the user requested. If the user asked about "my account" and
   the tool is called with a wildcard or admin query, that is
   suspicious.

3. Exfiltration targets: arguments containing URLs, email addresses,
   or IBANs that did not appear in the user's original prompt.
   A read-only tool called with an attacker's URL as an argument
   is a navigational hijack.

The validator returns a ReadOnlyCheckResult with pass/fail and
the specific violation. It does NOT block by default (read-only
tools are allowed), but it emits SecurityEvents and the caller
can choose to block based on the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ReadOnlyViolation(StrEnum):
    PATH_TRAVERSAL = "path_traversal"
    SENSITIVE_PATH = "sensitive_path"
    SQL_EXPANSION = "sql_expansion"
    UNREQUESTED_TARGET = "unrequested_target"


@dataclass(frozen=True)
class ReadOnlyCheckResult:
    """Result of validating read-only tool arguments."""

    passed: bool
    violations: tuple[tuple[ReadOnlyViolation, str], ...]  # (type, detail)
    score: float  # 0.0-1.0


# Path traversal and sensitive path patterns
_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\")
_SENSITIVE_PATHS = re.compile(
    r"(?:^|/)(?:"
    r"etc/(?:passwd|shadow|hosts|cron|sudoers)|"
    r"root/|"
    r"\.ssh/|\.aws/|\.gnupg/|\.kube/|\.env|"
    r"authorized_keys|id_rsa|id_ed25519|"
    r"proc/self/|sys/class/|dev/|"
    r"var/log/auth|var/log/secure"
    r")",
    re.IGNORECASE,
)

# SQL expansion patterns (wildcard access, UNION injection)
_SQL_EXPANSION = re.compile(
    r"\bSELECT\s+\*\s+FROM\b|"
    r"\bUNION\s+(?:ALL\s+)?SELECT\b|"
    r"\bOR\s+1\s*=\s*1\b|"
    r"\bDROP\s+TABLE\b|"
    r";\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b|"
    r"--\s*$|"
    r"'\s*OR\s+'",
    re.IGNORECASE,
)

# External targets (URLs, emails, IBANs)
_EXTERNAL_TARGET = re.compile(
    r"(?:https?://[\w.-]+(?::\d+)?(?:/\S*)?)|"     # URLs
    r"(?:[\w.+-]+@[\w-]+\.[\w.-]+)|"                 # emails
    r"(?:[A-Z]{2}\d{10,34})",                        # IBANs
)


def check_read_only_args(
    tool_name: str,
    args: dict[str, object],
    user_prompt: str | None = None,
) -> ReadOnlyCheckResult:
    """Validate arguments on a read-only tool call.

    Checks for path traversal, sensitive path access, SQL expansion,
    and unrequested external targets. Does not block the call (that
    is the caller's decision), but reports violations.

    Args:
        tool_name: Name of the read-only tool being called.
        args: The tool call's arguments.
        user_prompt: The user's original prompt, used to determine
            which external targets were actually requested. If None,
            all external targets are flagged.

    Returns:
        ReadOnlyCheckResult with pass/fail and violation details.
    """
    violations: list[tuple[ReadOnlyViolation, str]] = []
    prompt_lower = (user_prompt or "").lower()

    for arg_name, arg_val in args.items():
        if not isinstance(arg_val, str):
            continue
        val = arg_val.strip()
        if not val:
            continue

        # Path traversal
        if _PATH_TRAVERSAL.search(val):
            violations.append((
                ReadOnlyViolation.PATH_TRAVERSAL,
                f"argument {arg_name!r} contains path traversal: {val[:80]}",
            ))

        # Sensitive paths
        if _SENSITIVE_PATHS.search(val):
            violations.append((
                ReadOnlyViolation.SENSITIVE_PATH,
                f"argument {arg_name!r} accesses sensitive path: {val[:80]}",
            ))

        # SQL expansion
        if _SQL_EXPANSION.search(val):
            violations.append((
                ReadOnlyViolation.SQL_EXPANSION,
                f"argument {arg_name!r} contains SQL expansion: {val[:80]}",
            ))

        # External targets not in user prompt
        for m in _EXTERNAL_TARGET.finditer(val):
            target = m.group(0).lower()
            if target not in prompt_lower:
                violations.append((
                    ReadOnlyViolation.UNREQUESTED_TARGET,
                    f"argument {arg_name!r} contains unrequested target: {m.group(0)[:80]}",
                ))

    if not violations:
        return ReadOnlyCheckResult(passed=True, violations=(), score=0.0)

    # Score by severity
    _SEVERITY = {
        ReadOnlyViolation.PATH_TRAVERSAL: 0.9,
        ReadOnlyViolation.SENSITIVE_PATH: 0.85,
        ReadOnlyViolation.SQL_EXPANSION: 0.8,
        ReadOnlyViolation.UNREQUESTED_TARGET: 0.6,
    }
    score = max(_SEVERITY.get(v[0], 0.5) for v in violations)

    return ReadOnlyCheckResult(
        passed=False,
        violations=tuple(violations),
        score=score,
    )


def check_and_emit(
    tool_name: str,
    args: dict[str, object],
    user_prompt: str | None = None,
    principal: str = "system",
) -> ReadOnlyCheckResult:
    """Check and emit SecurityEvent if violations are found."""
    result = check_read_only_args(tool_name, args, user_prompt)
    if not result.passed:
        from tessera.events import EventKind, SecurityEvent, emit

        emit(
            SecurityEvent.now(
                kind=EventKind.POLICY_DENY,
                principal=principal,
                detail={
                    "scanner": "read_only_guard",
                    "tool": tool_name,
                    "violations": [
                        {"type": str(v[0]), "detail": v[1]}
                        for v in result.violations
                    ],
                    "score": result.score,
                },
            )
        )
    return result
