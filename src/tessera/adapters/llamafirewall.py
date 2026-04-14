"""LlamaFirewall scanner adapter for Tessera.

Wraps LlamaFirewall's scan() as a Tessera scanner. Tessera provides
trust-label-based targeting (only scan untrusted segments), while
LlamaFirewall provides the scanner implementations.

Install requirements:
    pip install tessera[llamafirewall]   # adds llamafirewall

Source attribution: scanner interface from LlamaFirewall (scanner.py).
"""

from __future__ import annotations

from typing import Any

from tessera.context import Context, LabeledSegment
from tessera.labels import TrustLevel
from tessera.scanners.heuristic import injection_score as _heuristic_score

try:
    import llamafirewall as _lf

    _LLAMAFIREWALL_AVAILABLE = True
except ImportError:
    _LLAMAFIREWALL_AVAILABLE = False


class LlamaFirewallAdapter:
    """Wrap LlamaFirewall scanners for use in Tessera's scanner pipeline.

    Tessera's advantage: only scans segments with trust_level below
    threshold, skipping USER and SYSTEM segments entirely. This reduces
    false positives and compute cost.

    When llamafirewall is not installed, falls back to Tessera's own
    heuristic injection scorer.

    Args:
        scanners: List of LlamaFirewall scanner names to use.
            Options: "prompt_guard", "code_shield", "hidden_ascii",
            "alignment_check". If None, defaults to ["prompt_guard"].
        threshold: Only scan segments below this trust level.
    """

    def __init__(
        self,
        scanners: list[str] | None = None,
        threshold: TrustLevel = TrustLevel.TOOL,
    ) -> None:
        self._scanner_names = scanners or ["prompt_guard"]
        self._threshold = threshold
        self._firewall: Any = None

        if _LLAMAFIREWALL_AVAILABLE:
            self._firewall = _lf.LlamaFirewall(scanners=self._scanner_names)

    def score(self, text: str) -> float:
        """Score text using LlamaFirewall.

        Returns max score across configured scanners. Falls back to
        Tessera's heuristic scorer if llamafirewall is not installed.

        Args:
            text: The text to score.

        Returns:
            Float between 0.0 and 1.0. Higher means more suspicious.
        """
        if not text or not text.strip():
            return 0.0

        if self._firewall is not None:
            try:
                result = self._firewall.scan(text)
                if hasattr(result, "score"):
                    return float(result.score)
                if isinstance(result, dict) and "score" in result:
                    return float(result["score"])
                return 0.0
            except Exception:  # noqa: BLE001 - fall back on any error
                pass

        return _heuristic_score(text)

    def scan_segment(self, segment: LabeledSegment) -> float:
        """Score a labeled segment. Skips trusted segments (returns 0.0).

        Args:
            segment: The labeled segment to scan.

        Returns:
            Float between 0.0 and 1.0. Returns 0.0 for trusted segments.
        """
        if segment.label.trust_level >= self._threshold:
            return 0.0
        return self.score(segment.content)

    def scan_context(self, context: Context) -> dict[int, float]:
        """Score all untrusted segments in a context.

        Only scans segments with trust_level below the configured
        threshold. Trusted segments are skipped entirely.

        Args:
            context: The context containing segments to scan.

        Returns:
            Dict mapping segment index to score. Only includes segments
            that were actually scanned (trust below threshold).
        """
        results: dict[int, float] = {}
        for i, segment in enumerate(context.segments):
            if segment.label.trust_level < self._threshold:
                results[i] = self.score(segment.content)
        return results


def llamafirewall_score(text: str) -> float:
    """Module-level scorer for ScannerRegistry compatibility.

    Args:
        text: The text to score.

    Returns:
        Float between 0.0 and 1.0.
    """
    adapter = LlamaFirewallAdapter()
    return adapter.score(text)
