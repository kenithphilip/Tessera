"""tessera.scanners

Re-exports the existing scanner suite plus the shared Scanner protocol
introduced for supply_chain and yara. Existing scanners (directive,
intent, heuristic, ...) can migrate to the protocol shape as a
follow-up without breaking imports here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Protocol, runtime_checkable

Severity = Literal["info", "low", "medium", "high", "critical"]

_SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def severity_rank(s: Severity) -> int:
    return _SEVERITY_RANK[s]


@dataclass(frozen=True)
class ScanFinding:
    """One finding from a scanner run.

    Attributes:
        rule_id: Stable identifier for the rule that fired.
        severity: One of info / low / medium / high / critical.
        message: Human-readable description.
        arg_path: Where the match was found (``headers.x-run``, ``$``).
        evidence: The matched substring, truncated to a safe length.
        metadata: Scanner-specific extras.
    """

    rule_id: str
    severity: Severity
    message: str
    arg_path: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    """Result of a single scanner run."""

    scanner: str
    allowed: bool
    findings: tuple[ScanFinding, ...] = ()

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: _SEVERITY_RANK[f.severity]).severity

    @property
    def primary_reason(self) -> str:
        if self.allowed or not self.findings:
            return ""
        top = max(self.findings, key=lambda f: _SEVERITY_RANK[f.severity])
        return f"{top.rule_id}: {top.message}"


@runtime_checkable
class Scanner(Protocol):
    """Protocol every scanner implements.

    ``name`` must be a stable, audit-friendly string like
    ``tessera.scanners.supply_chain``.
    """

    name: str

    def scan(
        self,
        *,
        tool_name: str,
        args: Any,
        trajectory_id: str = "",
    ) -> ScanResult: ...


def combine(results: Iterable[ScanResult]) -> ScanResult:
    """Merge multiple scan results into one. Allowed iff all are allowed."""
    rs = list(results)
    if not rs:
        return ScanResult(scanner="combined", allowed=True)
    allowed = all(r.allowed for r in rs)
    merged = tuple(f for r in rs for f in r.findings)
    return ScanResult(scanner="combined", allowed=allowed, findings=merged)


# ---------------------------------------------------------------------------
# Legacy scanner re-exports (stable; don't remove)
# ---------------------------------------------------------------------------

from tessera.scanners.canary import CanaryGuard
from tessera.scanners.codeshield import CodeFinding, CodeShieldScanner, codeshield_score
from tessera.scanners.heuristic import injection_score
from tessera.scanners.pii import PIIEntity, PIIScanner
from tessera.scanners.tool_descriptions import (
    PoisoningMatch,
    PoisoningSeverity,
    ToolDescriptionScanResult,
    scan_tool,
    scan_tools,
)
from tessera.scanners.tool_shadow import ShadowPair, ShadowScanResult, scan_cross_server_shadows
from tessera.scanners.unicode import UnicodeScanResult, scan_and_emit, scan_unicode_tags
from tessera.scanners.perplexity import PerplexityScanner, perplexity_score
from tessera.scanners.promptguard import PromptGuardScanner, promptguard_score


__all__ = [
    # Scanner protocol
    "Severity",
    "severity_rank",
    "ScanFinding",
    "ScanResult",
    "Scanner",
    "combine",
    # Legacy scanners
    "CanaryGuard",
    "CodeFinding",
    "CodeShieldScanner",
    "PIIEntity",
    "PIIScanner",
    "PerplexityScanner",
    "PoisoningMatch",
    "PoisoningSeverity",
    "PromptGuardScanner",
    "ShadowPair",
    "ShadowScanResult",
    "ToolDescriptionScanResult",
    "UnicodeScanResult",
    "codeshield_score",
    "injection_score",
    "perplexity_score",
    "promptguard_score",
    "scan_and_emit",
    "scan_cross_server_shadows",
    "scan_tool",
    "scan_tools",
    "scan_unicode_tags",
]
