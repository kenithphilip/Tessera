"""Tests for Phase 3 ML-backed scanners.

All three scanners depend on heavy optional packages (torch, transformers,
codeshield) that are NOT installed in the test environment. Tests verify:
- Module-level imports succeed without the packages
- Scanner __init__ raises ImportError with a helpful message when packages are missing
- Module-level scorer functions raise ImportError when packages are missing
- CodeShield regex fallback works correctly
- SecurityEvent emission on detection
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tessera.events import EventKind, SecurityEvent, clear_sinks, register_sink


# ---------------------------------------------------------------------------
# 3.1 PromptGuard
# ---------------------------------------------------------------------------


class TestPromptGuardImport:
    """Verify that the module can be imported without torch."""

    def test_module_import_succeeds(self) -> None:
        import tessera.scanners.promptguard  # noqa: F401

    def test_class_importable(self) -> None:
        from tessera.scanners.promptguard import PromptGuardScanner  # noqa: F401

    def test_scorer_function_importable(self) -> None:
        from tessera.scanners.promptguard import promptguard_score  # noqa: F401


class TestPromptGuardInit:
    """PromptGuardScanner.__init__ raises ImportError without torch."""

    def test_init_raises_import_error(self) -> None:
        from tessera.scanners.promptguard import PromptGuardScanner

        with pytest.raises(ImportError, match="torch and transformers"):
            PromptGuardScanner()

    def test_init_error_mentions_install(self) -> None:
        from tessera.scanners.promptguard import PromptGuardScanner

        with pytest.raises(ImportError, match="pip install tessera"):
            PromptGuardScanner()

    def test_module_level_scorer_raises(self) -> None:
        from tessera.scanners.promptguard import promptguard_score

        with pytest.raises(ImportError, match="torch and transformers"):
            promptguard_score("test input")


class TestPromptGuardWithMock:
    """Test score and event emission with mocked ML model."""

    def _make_scanner(self) -> MagicMock:
        """Create a mock scanner that behaves like PromptGuardScanner."""
        from tessera.scanners.promptguard import PromptGuardScanner

        scanner = object.__new__(PromptGuardScanner)
        scanner.model_name = "mock-model"
        scanner.threshold = 0.9
        scanner.device = "cpu"
        scanner._tokenizer = MagicMock()
        scanner._model = MagicMock()
        return scanner

    def test_scan_and_emit_fires_event(self) -> None:
        scanner = self._make_scanner()
        # Mock score to return above threshold.
        scanner.score = MagicMock(return_value=0.95)

        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            result = scanner.scan_and_emit("malicious input", principal="test")
            assert result == 0.95
            assert len(events) == 1
            assert events[0].kind == EventKind.CONTENT_INJECTION_DETECTED
            assert events[0].detail["scanner"] == "promptguard"
            assert events[0].detail["score"] == 0.95
        finally:
            clear_sinks()

    def test_scan_and_emit_no_event_below_threshold(self) -> None:
        scanner = self._make_scanner()
        scanner.score = MagicMock(return_value=0.3)

        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            result = scanner.scan_and_emit("safe input")
            assert result == 0.3
            assert len(events) == 0
        finally:
            clear_sinks()


# ---------------------------------------------------------------------------
# 3.2 CodeShield
# ---------------------------------------------------------------------------


class TestCodeShieldCreation:
    """CodeShieldScanner can be created (falls back to regex)."""

    def test_scanner_creates_without_codeshield(self) -> None:
        from tessera.scanners.codeshield import CodeShieldScanner

        scanner = CodeShieldScanner()
        assert not scanner._has_codeshield

    def test_module_import_succeeds(self) -> None:
        import tessera.scanners.codeshield  # noqa: F401

    def test_scorer_function_importable(self) -> None:
        from tessera.scanners.codeshield import codeshield_score  # noqa: F401


class TestCodeShieldRegexFallback:
    """Regex fallback detects dangerous patterns."""

    def setup_method(self) -> None:
        from tessera.scanners.codeshield import CodeShieldScanner

        self.scanner = CodeShieldScanner()

    def test_detects_eval_call(self) -> None:
        findings = self.scanner.scan("result = eval(user_input)")
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-95" for f in findings)

    def test_detects_exec_call(self) -> None:
        findings = self.scanner.scan("exec(code_string)")
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-95" for f in findings)

    def test_detects_subprocess(self) -> None:
        findings = self.scanner.scan("subprocess.call(cmd)")
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-78" for f in findings)

    def test_detects_os_system(self) -> None:
        findings = self.scanner.scan("os.system('rm -rf /')")
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-78" for f in findings)

    def test_detects_pickle(self) -> None:
        findings = self.scanner.scan("data = pickle.loads(payload)")
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-502" for f in findings)

    def test_clean_code_returns_empty(self) -> None:
        safe_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        findings = self.scanner.scan(safe_code)
        assert len(findings) == 0

    def test_clean_code_multiline(self) -> None:
        safe_code = (
            "import json\n"
            "def parse(data: str) -> dict:\n"
            "    return json.loads(data)\n"
        )
        findings = self.scanner.scan(safe_code)
        assert len(findings) == 0

    def test_finding_has_line_number(self) -> None:
        code = "x = 1\ny = eval('2+2')\n"
        findings = self.scanner.scan(code)
        assert len(findings) >= 1
        assert findings[0].line == 2


class TestCodeShieldScore:
    """score() returns 1.0 on finding, 0.0 on clean."""

    def setup_method(self) -> None:
        from tessera.scanners.codeshield import CodeShieldScanner

        self.scanner = CodeShieldScanner()

    def test_score_returns_one_on_finding(self) -> None:
        assert self.scanner.score("exec(bad_code)") == 1.0

    def test_score_returns_zero_on_clean(self) -> None:
        assert self.scanner.score("x = 1 + 2") == 0.0

    def test_module_level_scorer(self) -> None:
        from tessera.scanners.codeshield import codeshield_score

        assert codeshield_score("exec(x)") == 1.0
        assert codeshield_score("x = 1") == 0.0


class TestCodeShieldEmit:
    """scan_and_emit emits SecurityEvent on finding."""

    def test_emits_event_on_finding(self) -> None:
        from tessera.scanners.codeshield import CodeShieldScanner

        scanner = CodeShieldScanner()
        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            findings = scanner.scan_and_emit("exec(payload)")
            assert len(findings) >= 1
            assert len(events) >= 1
            assert events[0].kind == EventKind.CONTENT_INJECTION_DETECTED
            assert events[0].detail["scanner"] == "codeshield"
            assert events[0].detail["cwe_id"] == "CWE-95"
            assert events[0].detail["backend"] == "regex"
        finally:
            clear_sinks()

    def test_no_event_on_clean_code(self) -> None:
        from tessera.scanners.codeshield import CodeShieldScanner

        scanner = CodeShieldScanner()
        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            findings = scanner.scan_and_emit("x = 1 + 2")
            assert len(findings) == 0
            assert len(events) == 0
        finally:
            clear_sinks()


# ---------------------------------------------------------------------------
# 3.3 Perplexity
# ---------------------------------------------------------------------------


class TestPerplexityImport:
    """Verify that the module can be imported without torch."""

    def test_module_import_succeeds(self) -> None:
        import tessera.scanners.perplexity  # noqa: F401

    def test_class_importable(self) -> None:
        from tessera.scanners.perplexity import PerplexityScanner  # noqa: F401

    def test_scorer_function_importable(self) -> None:
        from tessera.scanners.perplexity import perplexity_score  # noqa: F401


class TestPerplexityInit:
    """PerplexityScanner.__init__ raises ImportError without torch."""

    def test_init_raises_import_error(self) -> None:
        from tessera.scanners.perplexity import PerplexityScanner

        with pytest.raises(ImportError, match="torch and transformers"):
            PerplexityScanner()

    def test_init_error_mentions_install(self) -> None:
        from tessera.scanners.perplexity import PerplexityScanner

        with pytest.raises(ImportError, match="pip install tessera"):
            PerplexityScanner()

    def test_module_level_scorer_raises(self) -> None:
        from tessera.scanners.perplexity import perplexity_score

        with pytest.raises(ImportError, match="torch and transformers"):
            perplexity_score("test input")


class TestPerplexityWithMock:
    """Test event emission with mocked perplexity scanner."""

    def _make_scanner(self) -> MagicMock:
        from tessera.scanners.perplexity import PerplexityScanner

        scanner = object.__new__(PerplexityScanner)
        scanner.model_name = "mock-model"
        scanner.length_ratio_threshold = 10.0
        scanner.suffix_ratio_threshold = 5.0
        scanner.suffix_fraction = 0.3
        scanner.device = "cpu"
        scanner._tokenizer = MagicMock()
        scanner._model = MagicMock()
        return scanner

    def test_scan_and_emit_fires_event(self) -> None:
        scanner = self._make_scanner()
        scanner.score = MagicMock(return_value=0.85)

        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            result = scanner.scan_and_emit("adversarial suffix text")
            assert result == 0.85
            assert len(events) == 1
            assert events[0].kind == EventKind.CONTENT_INJECTION_DETECTED
            assert events[0].detail["scanner"] == "perplexity"
            assert events[0].detail["score"] == 0.85
        finally:
            clear_sinks()

    def test_scan_and_emit_no_event_below_threshold(self) -> None:
        scanner = self._make_scanner()
        scanner.score = MagicMock(return_value=0.2)

        events: list[SecurityEvent] = []
        register_sink(events.append)
        try:
            result = scanner.scan_and_emit("normal text")
            assert result == 0.2
            assert len(events) == 0
        finally:
            clear_sinks()


# ---------------------------------------------------------------------------
# General: all three have module-level scorers and emit SecurityEvents
# ---------------------------------------------------------------------------


class TestModuleLevelScorers:
    """All three modules expose a module-level scorer function."""

    def test_promptguard_scorer_is_callable(self) -> None:
        from tessera.scanners.promptguard import promptguard_score

        assert callable(promptguard_score)

    def test_codeshield_scorer_is_callable(self) -> None:
        from tessera.scanners.codeshield import codeshield_score

        assert callable(codeshield_score)

    def test_perplexity_scorer_is_callable(self) -> None:
        from tessera.scanners.perplexity import perplexity_score

        assert callable(perplexity_score)


class TestCodeFindingDataclass:
    """CodeFinding dataclass is frozen and well-formed."""

    def test_creation(self) -> None:
        from tessera.scanners.codeshield import CodeFinding

        f = CodeFinding(cwe_id="CWE-78", description="test", severity="high", line=5)
        assert f.cwe_id == "CWE-78"
        assert f.line == 5

    def test_frozen(self) -> None:
        from tessera.scanners.codeshield import CodeFinding

        f = CodeFinding(cwe_id="CWE-78", description="test", severity="high", line=1)
        with pytest.raises(AttributeError):
            f.cwe_id = "CWE-79"  # type: ignore[misc]

    def test_none_line(self) -> None:
        from tessera.scanners.codeshield import CodeFinding

        f = CodeFinding(cwe_id="CWE-95", description="test", severity="medium", line=None)
        assert f.line is None
