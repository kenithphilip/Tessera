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

# Phase 3 ML-backed scanners with optional heavy dependencies.
# PromptGuard and Perplexity raise ImportError at class init time
# (not at module import) so they can always be imported for type
# checking and interface discovery.
from tessera.scanners.perplexity import PerplexityScanner, perplexity_score
from tessera.scanners.promptguard import PromptGuardScanner, promptguard_score

__all__ = [
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
