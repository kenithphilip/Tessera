"""tessera.scanners.yara

Optional YARA scanner backed by the ``yara-x`` Python bindings. Import
is lazy: if ``yara_x`` is not installed the scanner initializes with
``available=False`` and returns an empty :class:`ScanResult` from every
scan. The evaluator wiring stays the same across environments.

Rules can be supplied as:
  * a directory of ``.yar`` / ``.yara`` files (recursively), or
  * a list of inline rule source strings.

Each YARA rule can carry metadata that Tessera consumes::

    meta:
        severity = "high"             // default: "medium"
        rule_id  = "yara.my_rule"     // default: "yara.{ns}.{name}"
        message  = "..."              // default: rule name

Usage::

    scanner = YaraScanner(rules_dir=Path("/etc/tessera/yara"))
    if not scanner.available:
        log.warning("yara-x not installed; scanner disabled")
    result = scanner.scan(tool_name="bash.run", args={"command": "..."})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from tessera.scanners import ScanFinding, ScanResult, Severity, severity_rank

logger = logging.getLogger(__name__)

try:  # pragma: no cover - environment-dependent
    import yara_x  # type: ignore

    _YARA_AVAILABLE = True
    _YARA_IMPORT_ERROR: Exception | None = None
except Exception as e:  # pragma: no cover
    yara_x = None  # type: ignore
    _YARA_AVAILABLE = False
    _YARA_IMPORT_ERROR = e


_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"info", "low", "medium", "high", "critical"}
)


@dataclass(frozen=True)
class _RuleSource:
    path: str
    source: str


class YaraScanner:
    """YARA-X scanner implementing the :class:`Scanner` protocol.

    Args:
        rules_dir: Directory of ``.yar`` / ``.yara`` files (scanned recursively).
        rules: Inline YARA rule source strings.
        default_severity: Fallback severity when a rule has no ``meta.severity``.
        block_severity: Minimum severity that causes ``allowed=False``.
    """

    name = "tessera.scanners.yara"

    def __init__(
        self,
        rules_dir: Path | str | None = None,
        rules: Iterable[str] | None = None,
        default_severity: Severity = "medium",
        block_severity: Severity = "high",
    ) -> None:
        self._default_severity: Severity = default_severity
        self._block_severity: Severity = block_severity
        self._rules_dir = Path(rules_dir) if rules_dir else None
        self._inline = tuple(rules or ())
        self._compiled: Any = None
        self._rule_count = 0
        self._load_errors: list[str] = []

        if not _YARA_AVAILABLE:
            logger.info("yara-x not available: %r", _YARA_IMPORT_ERROR)
            return

        self._compile()

    @property
    def available(self) -> bool:
        return _YARA_AVAILABLE and self._compiled is not None

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def load_errors(self) -> tuple[str, ...]:
        return tuple(self._load_errors)

    def scan(
        self,
        *,
        tool_name: str,
        args: Any,
        trajectory_id: str = "",
    ) -> ScanResult:
        if not self.available:
            return ScanResult(scanner=self.name, allowed=True)

        findings: list[ScanFinding] = []
        for path, text in _flatten_strings(args):
            findings.extend(self._scan_text(text, arg_path=path))
        return self._build_result(findings)

    def scan_content(self, *, content: str, source_label: str = "content") -> ScanResult:
        """Scan a single text blob; convenience for post-ingestion flows."""
        if not self.available:
            return ScanResult(scanner=self.name, allowed=True)
        findings = self._scan_text(content, arg_path=source_label)
        return self._build_result(findings)

    def _compile(self) -> None:
        sources: list[_RuleSource] = []
        if self._rules_dir:
            for path in _iter_rule_files(self._rules_dir):
                try:
                    sources.append(
                        _RuleSource(path=str(path), source=path.read_text(encoding="utf-8"))
                    )
                except Exception as e:
                    self._load_errors.append(f"{path}: {e}")
        for i, src in enumerate(self._inline):
            sources.append(_RuleSource(path=f"inline:{i}", source=src))

        if not sources:
            logger.info("yara scanner: no rules configured")
            return

        try:
            compiler = yara_x.Compiler()
            count = 0
            for s in sources:
                try:
                    compiler.add_source(s.source, origin=s.path)
                    count += 1
                except Exception as e:
                    self._load_errors.append(f"{s.path}: {e}")
            self._compiled = compiler.build()
            self._rule_count = count
        except Exception as e:
            self._load_errors.append(f"compile: {e}")
            self._compiled = None

    def _scan_text(self, text: str, *, arg_path: str) -> list[ScanFinding]:
        assert self._compiled is not None
        try:
            results = self._compiled.scan(text.encode("utf-8", errors="replace"))
        except Exception as e:
            logger.warning("yara scan failed: %s", e)
            return []

        findings: list[ScanFinding] = []
        for match in getattr(results, "matching_rules", ()):
            meta = _extract_meta(match)
            rule_id = meta.get("rule_id") or _default_rule_id(match)
            severity = _coerce_severity(meta.get("severity"), self._default_severity)
            message = meta.get("message") or getattr(match, "identifier", "yara match")
            evidence = _first_match_evidence(match, text)
            findings.append(
                ScanFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=str(message),
                    arg_path=arg_path,
                    evidence=evidence,
                    metadata={
                        k: v for k, v in meta.items()
                        if k not in {"rule_id", "severity", "message"}
                    },
                )
            )
        return findings

    def _build_result(self, findings: list[ScanFinding]) -> ScanResult:
        block_rank = severity_rank(self._block_severity)
        allowed = all(severity_rank(f.severity) < block_rank for f in findings)
        return ScanResult(scanner=self.name, allowed=allowed, findings=tuple(findings))


def _iter_rule_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".yar", ".yara"}:
            yield p


def _extract_meta(match: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    raw = getattr(match, "metadata", None) or ()
    for item in raw:
        try:
            name, value = item
        except Exception:
            continue
        meta[str(name)] = value
    return meta


def _coerce_severity(value: Any, fallback: Severity) -> Severity:
    if isinstance(value, str) and value.lower() in _VALID_SEVERITIES:
        return value.lower()  # type: ignore[return-value]
    return fallback


def _default_rule_id(match: Any) -> str:
    ns = getattr(match, "namespace", None) or ""
    name = getattr(match, "identifier", "rule")
    return f"yara.{ns}.{name}" if ns else f"yara.{name}"


def _first_match_evidence(match: Any, original: str) -> str:
    patterns = getattr(match, "patterns", None) or ()
    for p in patterns:
        matches = getattr(p, "matches", None) or ()
        for m in matches:
            offset = getattr(m, "offset", 0)
            length = getattr(m, "length", 0)
            if length:
                return original[offset : offset + length][:200]
    return ""


def _flatten_strings(args: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if args is None:
        return
    if isinstance(args, str):
        yield (prefix or "$", args)
        return
    if isinstance(args, (bytes, bytearray)):
        yield (prefix or "$", bytes(args).decode("utf-8", errors="replace"))
        return
    if isinstance(args, Mapping):
        for k, v in args.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten_strings(v, child)
        return
    if isinstance(args, (list, tuple)):
        for i, v in enumerate(args):
            child = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _flatten_strings(v, child)


__all__ = ["YaraScanner"]
