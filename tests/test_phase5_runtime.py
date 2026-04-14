"""Tests for Phase 5: Runtime Infrastructure."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from tessera.events import EventKind, SecurityEvent


# -- 5.1 Scanner Cache -----------------------------------------------

class TestScannerCache:
    def test_cache_hit_skips_scorer(self) -> None:
        from tessera.scanners.cache import ScannerCache

        call_count = 0

        def scorer(text: str) -> float:
            nonlocal call_count
            call_count += 1
            return 0.42

        cache = ScannerCache(maxsize=16)
        first = cache.get_or_compute("hello", scorer)
        second = cache.get_or_compute("hello", scorer)

        assert first == 0.42
        assert second == 0.42
        assert call_count == 1

    def test_cache_miss_calls_scorer(self) -> None:
        from tessera.scanners.cache import ScannerCache

        cache = ScannerCache(maxsize=16)
        result = cache.get_or_compute("test", lambda t: 0.7)
        assert result == 0.7
        assert cache.stats.misses == 1

    def test_stats_track_hits_and_misses(self) -> None:
        from tessera.scanners.cache import ScannerCache

        cache = ScannerCache(maxsize=16)
        scorer = lambda t: 0.5  # noqa: E731

        cache.get_or_compute("a", scorer)
        cache.get_or_compute("a", scorer)
        cache.get_or_compute("b", scorer)

        stats = cache.stats
        assert stats.hits == 1
        assert stats.misses == 2
        assert stats.size == 2
        assert stats.hit_rate == pytest.approx(1 / 3)

    def test_clear_resets_cache(self) -> None:
        from tessera.scanners.cache import ScannerCache

        cache = ScannerCache(maxsize=16)
        cache.get_or_compute("x", lambda t: 0.1)
        cache.clear()

        stats = cache.stats
        assert stats.size == 0
        assert stats.hits == 0
        assert stats.misses == 0

    def test_different_texts_get_different_entries(self) -> None:
        from tessera.scanners.cache import ScannerCache

        cache = ScannerCache(maxsize=16)

        r1 = cache.get_or_compute("alpha", lambda t: 0.1)
        r2 = cache.get_or_compute("beta", lambda t: 0.9)

        assert r1 == 0.1
        assert r2 == 0.9
        assert cache.stats.size == 2


# -- 5.2 Parallel Scanner Execution ----------------------------------

class TestParallelScanners:
    def test_max_score_from_two_scanners(self) -> None:
        from tessera.scanners.parallel import run_scanners_parallel

        def low_scorer(text: str) -> float:
            return 0.2

        def high_scorer(text: str) -> float:
            return 0.8

        result = asyncio.run(
            run_scanners_parallel("test", [low_scorer, high_scorer])
        )
        assert result.max_score == 0.8
        assert len(result.scores) == 2
        assert result.elapsed_ms >= 0.0

    def test_per_scanner_scores_present(self) -> None:
        from tessera.scanners.parallel import run_scanners_parallel

        def scanner_a(text: str) -> float:
            return 0.3

        def scanner_b(text: str) -> float:
            return 0.6

        result = asyncio.run(
            run_scanners_parallel("text", [scanner_a, scanner_b])
        )
        assert "scanner_a" in result.scores
        assert "scanner_b" in result.scores
        assert result.scores["scanner_a"] == 0.3
        assert result.scores["scanner_b"] == 0.6

    def test_empty_scanner_list_returns_zero(self) -> None:
        from tessera.scanners.parallel import run_scanners_parallel

        result = asyncio.run(
            run_scanners_parallel("text", [])
        )
        assert result.max_score == 0.0
        assert result.scores == {}


# -- 5.3 Scanner Registry --------------------------------------------

class TestScannerRegistry:
    def test_register_and_select_by_name(self) -> None:
        from tessera.scanners.parallel import ScannerRegistry

        registry = ScannerRegistry()
        scanner_fn = lambda t: 0.5  # noqa: E731
        registry.register("heuristic", scanner_fn)

        selected = registry.select(["heuristic"])
        assert len(selected) == 1
        assert selected[0] is scanner_fn

    def test_select_none_returns_all(self) -> None:
        from tessera.scanners.parallel import ScannerRegistry

        registry = ScannerRegistry()
        registry.register("a", lambda t: 0.1)
        registry.register("b", lambda t: 0.2)

        selected = registry.select(None)
        assert len(selected) == 2

    def test_select_subset(self) -> None:
        from tessera.scanners.parallel import ScannerRegistry

        registry = ScannerRegistry()
        fn_a = lambda t: 0.1  # noqa: E731
        fn_b = lambda t: 0.2  # noqa: E731
        fn_c = lambda t: 0.3  # noqa: E731
        registry.register("a", fn_a)
        registry.register("b", fn_b)
        registry.register("c", fn_c)

        selected = registry.select(["a", "c"])
        assert len(selected) == 2
        assert fn_a in selected
        assert fn_c in selected
        assert fn_b not in selected


# -- 5.4 Confidence Tiers --------------------------------------------

class TestConfidenceTiers:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (1.0, "BLOCK"),
            (0.92, "BLOCK"),
            (0.91, "WARN"),
            (0.60, "WARN"),
            (0.59, "INFO"),
            (0.30, "INFO"),
            (0.29, "SUPPRESS"),
            (0.0, "SUPPRESS"),
        ],
    )
    def test_classify_boundaries(self, score: float, expected: str) -> None:
        from tessera.confidence import ConfidenceTier, classify_confidence

        result = classify_confidence(score)
        assert result == ConfidenceTier(expected)

    def test_enrich_adds_confidence_fields(self) -> None:
        from tessera.confidence import enrich_with_confidence

        event = SecurityEvent.now(
            kind=EventKind.CONTENT_INJECTION_DETECTED,
            principal="test-agent",
            detail={"scanner": "heuristic"},
        )
        enriched = enrich_with_confidence(event, 0.95)

        assert enriched["confidence"] == 0.95
        assert enriched["confidence_tier"] == "BLOCK"
        assert enriched["kind"] == "content_injection_detected"


# -- 5.5 SARIF Output ------------------------------------------------

class TestSARIFSink:
    def _make_event(self, kind: EventKind = EventKind.POLICY_DENY) -> SecurityEvent:
        return SecurityEvent.now(
            kind=kind,
            principal="test-agent",
            detail={"tool": "send_email", "reason": "untrusted context"},
        )

    def test_collects_events(self) -> None:
        from tessera.events_sarif import SARIFSink

        sink = SARIFSink()
        event = self._make_event()
        sink(event)
        sink(event)

        sarif = sink.to_sarif()
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_structure(self) -> None:
        from tessera.events_sarif import SARIFSink

        sink = SARIFSink(tool_name="tessera", tool_version="0.0.1")
        sink(self._make_event())

        sarif = sink.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "tessera"
        assert run["tool"]["driver"]["version"] == "0.0.1"
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_event_maps_to_rule_and_level(self) -> None:
        from tessera.events_sarif import SARIFSink

        sink = SARIFSink()
        sink(self._make_event(EventKind.POLICY_DENY))
        sink(self._make_event(EventKind.CONTENT_INJECTION_DETECTED))

        sarif = sink.to_sarif()
        results = sarif["runs"][0]["results"]

        assert results[0]["ruleId"] == "tessera/policy-deny"
        assert results[0]["level"] == "error"
        assert results[1]["ruleId"] == "tessera/injection-detected"
        assert results[1]["level"] == "error"

    def test_result_has_properties(self) -> None:
        from tessera.events_sarif import SARIFSink

        sink = SARIFSink()
        sink(self._make_event())

        result = sink.to_sarif()["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["principal"] == "test-agent"

    def test_write_creates_file(self) -> None:
        from tessera.events_sarif import SARIFSink

        sink = SARIFSink()
        sink(self._make_event())

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name

        sink.write(path)

        content = json.loads(Path(path).read_text())
        assert content["version"] == "2.1.0"
        assert len(content["runs"][0]["results"]) == 1

        Path(path).unlink()
