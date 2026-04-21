"""Supply chain attack detection for package managers and dep manifests.

Detects patterns that indicate supply chain attacks:

- Obfuscated or typosquatted package names in install commands
- Command injection in install flags
- Suspicious fetches to package registries
- Lock file tampering (delete or overwrite)
- Build script content indicating backdoors or exfiltration
- Known-bad package names (populated list, extensible)

Covers Python (pip, poetry), Node.js (npm, yarn, pnpm), Rust (cargo),
Ruby (gem), Go (go get), and system package managers (apt, yum).

This scanner complements ``tessera.destructive_guard`` (which catches
lock file deletion as a destructive op) by going further into the
content of install commands and manifests.

References:
- Sondera sondera-coding-agent-hooks supply_chain_risk.cedar
  (https://github.com/sondera-ai/sondera-coding-agent-hooks)
- MITRE ATT&CK T1195 Supply Chain Compromise
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class SupplyChainSeverity(Enum):
    BLOCK = "block"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class SupplyChainMatch:
    """A single supply chain pattern match.

    Attributes:
        rule_id: Stable identifier.
        severity: BLOCK / WARN / INFO.
        category: Category from MITRE ATT&CK (e.g., T1195.002).
        description: Human-readable explanation.
        matched_text: Matched substring.
    """

    rule_id: str
    severity: SupplyChainSeverity
    category: str
    description: str
    matched_text: str


@dataclass(frozen=True)
class SupplyChainResult:
    detected: bool
    max_severity: SupplyChainSeverity | None
    matches: tuple[SupplyChainMatch, ...]

    @property
    def should_block(self) -> bool:
        return any(m.severity == SupplyChainSeverity.BLOCK for m in self.matches)


# Package install command signatures (covers common package managers)
_INSTALL_PATTERNS: tuple[str, ...] = (
    r"\bpip\s+(?:install|download)\b",
    r"\bnpm\s+(?:install|i|add)\b",
    r"\byarn\s+(?:add|install)\b",
    r"\bpnpm\s+(?:add|install)\b",
    r"\bcargo\s+(?:add|install)\b",
    r"\bgem\s+install\b",
    r"\bgo\s+(?:get|install)\b",
    r"\bpoetry\s+add\b",
    r"\buv\s+add\b",
    r"\bapt(?:-get)?\s+install\b",
    r"\byum\s+install\b",
    r"\bdnf\s+install\b",
    r"\bbrew\s+install\b",
)
_INSTALL_REGEX = re.compile("|".join(_INSTALL_PATTERNS), re.IGNORECASE)


# Package names with suspicious characters (digit-for-letter substitution,
# unusual hyphens, or excessive length). These are typosquatting indicators.
_SUSPICIOUS_PACKAGE_NAME = re.compile(
    r"(?:^|\s)"
    r"(?:[a-z]+[0-9]+[a-z]+[0-9a-z_]*|"  # digits mid-word: b4se64_encoder
    r"[a-z]+_[a-z]+_[a-z]+_[a-z]+|"      # excessive underscores
    r"[a-z]{15,})"                        # very long name
    r"(?=\s|$|==|>=|<=|~=)",
    re.IGNORECASE,
)


# Known malicious or recently-reported typosquatting targets. This is a
# partial list, intended as a starting point; production deployments
# should load from a threat feed.
_KNOWN_BAD_PACKAGES: frozenset[str] = frozenset([
    # Typosquats of common Python packages
    "reqeusts", "reqests", "requestss",
    "urlib3", "urllib", "urlib",
    "dajngo", "djnago", "djanga",
    "numpi", "nummpy", "numpyy",
    "pandsa", "pandas3", "pandass",
    # Typosquats of common npm packages
    "loadash", "lodaash", "lodashh",
    "expresss", "expres",
    "reactt", "recat",
    # Historical malicious packages
    "colorama-",  # leading/trailing hyphens often malicious
    "discord-webhook-spammer",
    "node-ipc",  # the politicized attack from 2022
])


_RULES: tuple[tuple[str, SupplyChainSeverity, str, str, re.Pattern[str]], ...] = (
    # Command injection in install flags
    (
        "install-command-injection",
        SupplyChainSeverity.BLOCK,
        "T1195.001",
        "shell operators or substitution in package install command",
        re.compile(
            r"(?:pip\s+install|npm\s+install|yarn\s+add|cargo\s+add|gem\s+install)"
            r"\s+[^&|;]*(?:`[^`]+`|\$\([^)]+\)|&&\s*(?:rm|curl|wget)|\|\s*(?:sh|bash))",
            re.IGNORECASE,
        ),
    ),
    # Install from a git URL (bypasses registry, supply chain bypass)
    (
        "install-from-git-url",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "package installed directly from a git URL (bypasses registry verification)",
        re.compile(
            r"(?:pip\s+install|npm\s+install|yarn\s+add|cargo\s+add)"
            r"\s+.*?(?:git\+https?://|git\+ssh://|git://|github\.com/[^/]+/[^/\s]+\.git)",
            re.IGNORECASE,
        ),
    ),
    # Install from an HTTP URL (no HTTPS; or raw tarball)
    (
        "install-from-http-url",
        SupplyChainSeverity.BLOCK,
        "T1195.002",
        "package installed from http:// (no TLS)",
        re.compile(
            r"(?:pip\s+install|npm\s+install|yarn\s+add)\s+.*http://",
            re.IGNORECASE,
        ),
    ),
    # Install with --extra-index-url pointing at a non-default registry
    (
        "custom-index-exfil",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "install with --extra-index-url (dependency confusion risk)",
        re.compile(
            r"(?:pip\s+install|uv\s+add)\s+.*--extra-index-url\s+\S+",
            re.IGNORECASE,
        ),
    ),
    # curl | bash pattern in install context
    (
        "curl-pipe-shell",
        SupplyChainSeverity.BLOCK,
        "T1059.004",
        "curl-pipe-to-shell installer (no verification)",
        re.compile(
            r"curl\s+[^|]*(?:\|\s*|\&\&\s*)(?:bash|sh|zsh)\b",
            re.IGNORECASE,
        ),
    ),
    # Node preinstall/postinstall hook with shell commands
    (
        "npm-lifecycle-exec",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "npm preinstall/postinstall/prepublish with shell command (build-script attack)",
        re.compile(
            r'"(?:preinstall|postinstall|prepublish|prepare)"\s*:\s*"[^"]*(?:curl|wget|chmod\s+\+x|eval|base64\s+-d)',
            re.IGNORECASE,
        ),
    ),
    # Python setup.py with suspicious imports
    (
        "setup-py-suspicious",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "setup.py contains network or shell-exec patterns",
        re.compile(
            r"(?:setup\.py|setup\.cfg|pyproject\.toml)"
            r".*(?:urllib\.request|socket\.create_connection|base64\.b64decode|"
            r"exec\s*\(|subprocess\.Popen\()",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # Credentials embedded in package manifests
    (
        "credentials-in-manifest",
        SupplyChainSeverity.BLOCK,
        "T1552.001",
        "API key or token pattern in a package manifest",
        re.compile(
            r"(?:package\.json|requirements\.txt|pyproject\.toml|Cargo\.toml|Gemfile)"
            r".*(?:\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9]{20,}\b|\bghp_[A-Za-z0-9]{36}\b)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # Lockfile tampering (regen or overwrite without review)
    (
        "lockfile-regen",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "regenerating a lockfile (review the diff)",
        re.compile(
            r"\b(rm\s+(?:-\w+\s+)*(?:package-lock\.json|yarn\.lock|poetry\.lock|Cargo\.lock)"
            r"|npm\s+install\s+.*--package-lock-only"
            r"|cargo\s+update\s+--aggressive)\b",
            re.IGNORECASE,
        ),
    ),
    # Fetch to a package registry that is NOT the canonical one
    (
        "suspicious-registry-fetch",
        SupplyChainSeverity.WARN,
        "T1195.002",
        "fetch to a non-canonical package registry",
        re.compile(
            r"(?:curl|wget|http)\s+[^&|;]*"
            r"(?:pypi-unofficial|npm-proxy|npmjs\.co|pypi\.info|pypi\.io)",
            re.IGNORECASE,
        ),
    ),
)


def _is_install_command(text: str) -> bool:
    return bool(_INSTALL_REGEX.search(text))


def _extract_package_names(text: str) -> list[str]:
    """Extract package names that follow install commands.

    Simple heuristic: after a recognized install verb, collect bare
    identifiers (alphanumeric with hyphens and underscores) until we
    hit a flag or end of string.
    """
    names: list[str] = []
    for m in _INSTALL_REGEX.finditer(text):
        # Take the remainder of the text after the install verb
        tail = text[m.end():]
        # Stop at newline or shell separator
        for sep in ("\n", "&&", "||", ";", "|"):
            idx = tail.find(sep)
            if idx != -1:
                tail = tail[:idx]
        # Extract bare tokens (skip flags)
        for token in tail.split():
            if token.startswith("-"):
                continue
            # Strip version specifiers
            name = re.split(r"[=<>~]", token, maxsplit=1)[0].strip()
            # Strip quotes
            name = name.strip("'\"")
            if name and re.match(r"^[a-zA-Z0-9._-]+$", name):
                names.append(name.lower())
    return names


def check_supply_chain(text: str) -> SupplyChainResult:
    """Scan text for supply chain attack patterns.

    Args:
        text: Shell command, manifest contents, or tool-arg string.

    Returns:
        SupplyChainResult with all matches and max severity.
    """
    if not text:
        return SupplyChainResult(detected=False, max_severity=None, matches=())

    matches: list[SupplyChainMatch] = []

    # Pattern-based rules
    for rule_id, severity, category, description, pattern in _RULES:
        m = pattern.search(text)
        if m:
            matches.append(SupplyChainMatch(
                rule_id=rule_id,
                severity=severity,
                category=category,
                description=description,
                matched_text=m.group(0)[:200],
            ))

    # Package-name checks only when this is an install command
    if _is_install_command(text):
        for name in _extract_package_names(text):
            if name in _KNOWN_BAD_PACKAGES:
                matches.append(SupplyChainMatch(
                    rule_id="known-bad-package",
                    severity=SupplyChainSeverity.BLOCK,
                    category="T1195.001",
                    description=f"known malicious or typosquatting package: {name}",
                    matched_text=name,
                ))
            elif _SUSPICIOUS_PACKAGE_NAME.search(f" {name} "):
                matches.append(SupplyChainMatch(
                    rule_id="suspicious-package-name",
                    severity=SupplyChainSeverity.WARN,
                    category="T1195.001",
                    description=f"package name has typosquatting indicators: {name}",
                    matched_text=name,
                ))

    if not matches:
        return SupplyChainResult(detected=False, max_severity=None, matches=())

    order = {
        SupplyChainSeverity.BLOCK: 2,
        SupplyChainSeverity.WARN: 1,
        SupplyChainSeverity.INFO: 0,
    }
    max_sev = max((m.severity for m in matches), key=lambda s: order[s])

    return SupplyChainResult(
        detected=True,
        max_severity=max_sev,
        matches=tuple(matches),
    )
