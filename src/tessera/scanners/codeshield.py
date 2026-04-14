"""CWE-annotated insecure code detection.

Wraps CodeShield's insecure code detector for scanning tool outputs
that contain code. Falls back to a regex-based checker when CodeShield
is not installed.

Install the full backend with ``pip install tessera[codeshield]``.
The regex fallback is always available with zero extra dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CodeFinding:
    """One insecure code finding."""

    cwe_id: str
    description: str
    severity: str  # "high", "medium", "low"
    line: int | None


# Regex patterns for common dangerous code constructs. Each tuple is
# (compiled pattern, CWE ID, description, severity).
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        "CWE-95",
        "Use of eval() allows arbitrary code execution",
        "high",
    ),
    (
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        "CWE-95",
        "Use of exec() allows arbitrary code execution",
        "high",
    ),
    (
        re.compile(r"\bsubprocess\.(call|run|Popen|check_output)\s*\(", re.IGNORECASE),
        "CWE-78",
        "Subprocess call may allow OS command injection",
        "high",
    ),
    (
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        "CWE-78",
        "os.system() call may allow OS command injection",
        "high",
    ),
    (
        re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
        "CWE-78",
        "os.popen() call may allow OS command injection",
        "high",
    ),
    (
        re.compile(
            r"""(?:execute|cursor\.execute)\s*\(\s*(?:f['"]|['"].*%|['"].*\.format\()""",
            re.IGNORECASE,
        ),
        "CWE-89",
        "SQL query built with string formatting is vulnerable to injection",
        "high",
    ),
    (
        re.compile(r"\bpickle\.loads?\s*\(", re.IGNORECASE),
        "CWE-502",
        "Deserialization of untrusted data via pickle",
        "high",
    ),
    (
        re.compile(r"\byaml\.load\s*\((?!.*Loader\s*=\s*SafeLoader)", re.IGNORECASE),
        "CWE-502",
        "yaml.load() without SafeLoader allows arbitrary code execution",
        "high",
    ),
    (
        re.compile(r"\b__import__\s*\(", re.IGNORECASE),
        "CWE-95",
        "Dynamic import via __import__() may load untrusted code",
        "medium",
    ),
    (
        re.compile(r"\bcompile\s*\(.*\bexec\b", re.IGNORECASE),
        "CWE-95",
        "compile() with exec mode enables arbitrary code execution",
        "medium",
    ),
]


class CodeShieldScanner:
    """CWE-annotated insecure code detector.

    Requires: ``pip install tessera[codeshield]`` for the full backend.
    Falls back to regex-based pattern matching when CodeShield is absent.
    """

    def __init__(self) -> None:
        self._has_codeshield = False
        try:
            from codeshield.cs import CodeShield as _CS  # noqa: F401

            self._has_codeshield = True
        except ImportError:
            pass

    def scan(self, code: str, language: str = "python") -> list[CodeFinding]:
        """Analyze code for insecure patterns.

        Args:
            code: Source code to analyze.
            language: Programming language of the code.

        Returns:
            List of findings. Empty list means no issues detected.
        """
        if self._has_codeshield:
            return self._scan_codeshield(code, language)
        return self._scan_regex(code)

    def _scan_codeshield(self, code: str, language: str) -> list[CodeFinding]:
        """Scan using the CodeShield backend."""
        import asyncio

        from codeshield.cs import CodeShield as _CS

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already inside an async context; create a new loop in a thread.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(
                    asyncio.run, _CS.scan_code(code, language=language)
                ).result()
        else:
            result = asyncio.run(_CS.scan_code(code, language=language))

        findings: list[CodeFinding] = []
        if result.issues_found:
            for issue in result.recommended_treatment:
                findings.append(
                    CodeFinding(
                        cwe_id=getattr(issue, "cwe_id", "CWE-unknown"),
                        description=getattr(issue, "description", str(issue)),
                        severity=getattr(issue, "severity", "medium"),
                        line=getattr(issue, "line", None),
                    )
                )
        return findings

    def _scan_regex(self, code: str) -> list[CodeFinding]:
        """Regex fallback when CodeShield is not installed."""
        findings: list[CodeFinding] = []
        for line_no, line in enumerate(code.splitlines(), start=1):
            for pattern, cwe_id, description, severity in _DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        CodeFinding(
                            cwe_id=cwe_id,
                            description=description,
                            severity=severity,
                            line=line_no,
                        )
                    )
        return findings

    def score(self, text: str) -> float:
        """Return 1.0 if any finding, 0.0 otherwise.

        For ScannerRegistry compatibility.
        """
        return 1.0 if self.scan(text) else 0.0

    def scan_and_emit(
        self,
        code: str,
        language: str = "python",
        principal: str = "system",
    ) -> list[CodeFinding]:
        """Scan and emit a SecurityEvent for each finding.

        Args:
            code: Source code to analyze.
            language: Programming language.
            principal: Principal associated with this content.

        Returns:
            List of findings.
        """
        findings = self.scan(code, language)
        if findings:
            from tessera.events import EventKind, SecurityEvent, emit

            for finding in findings:
                emit(
                    SecurityEvent.now(
                        kind=EventKind.CONTENT_INJECTION_DETECTED,
                        principal=principal,
                        detail={
                            "scanner": "codeshield",
                            "cwe_id": finding.cwe_id,
                            "description": finding.description,
                            "severity": finding.severity,
                            "line": finding.line,
                            "language": language,
                            "backend": "codeshield" if self._has_codeshield else "regex",
                            "owasp": "LLM01",
                            "rule": "AGENT-codeshield-insecure-code",
                        },
                    )
                )
        return findings


_scanner: CodeShieldScanner | None = None


def codeshield_score(text: str) -> float:
    """Module-level scorer for use with ScannerRegistry.

    Lazily initializes the scanner on first call. Always available
    (falls back to regex when CodeShield is not installed).
    """
    global _scanner  # noqa: PLW0603
    if _scanner is None:
        _scanner = CodeShieldScanner()
    return _scanner.score(text)
