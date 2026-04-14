"""Perplexity-based adversarial suffix detection.

GCG-style attacks optimize token sequences that have high perplexity
(they look like random characters to a language model) but successfully
jailbreak the target. This scanner uses GPT-2 perplexity as a signal
to flag text with anomalous perplexity patterns.

Two detection modes:
1. Length/perplexity ratio: text that is too short for its perplexity.
2. Suffix perplexity: the last N tokens have much higher perplexity
   than the prefix, indicating an appended adversarial suffix.

Requires torch + transformers: ``pip install tessera[perplexity]``.
"""

from __future__ import annotations

import math
from typing import Any


class PerplexityScanner:
    """Detect adversarial suffixes via perplexity analysis.

    Args:
        model_name: HuggingFace model for perplexity computation.
        length_ratio_threshold: Perplexity-per-token threshold.
            Text with perplexity/token_count above this is flagged.
        suffix_ratio_threshold: Ratio of suffix perplexity to prefix
            perplexity above which the text is flagged.
        suffix_fraction: Fraction of tokens treated as the suffix.
        device: ``"cpu"`` or ``"cuda"``. Auto-detected when ``None``.
    """

    def __init__(
        self,
        model_name: str = "openai-community/gpt2",
        length_ratio_threshold: float = 10.0,
        suffix_ratio_threshold: float = 5.0,
        suffix_fraction: float = 0.3,
        device: str | None = None,
    ) -> None:
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForCausalLM, AutoTokenizer  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "Perplexity scanner requires torch and transformers. "
                "Install with: pip install tessera[perplexity]"
            ) from exc

        self.model_name = model_name
        self.length_ratio_threshold = length_ratio_threshold
        self.suffix_ratio_threshold = suffix_ratio_threshold
        self.suffix_fraction = suffix_fraction

        if device is None:
            import torch as _torch

            device = "cuda" if _torch.cuda.is_available() else "cpu"
        self.device = device

        self._tokenizer: Any = AutoTokenizer.from_pretrained(model_name)
        self._model: Any = AutoModelForCausalLM.from_pretrained(model_name)
        self._model.to(self.device)
        self._model.eval()

    def perplexity(self, text: str) -> float:
        """Compute GPT-2 perplexity of text.

        Args:
            text: Input text.

        Returns:
            Perplexity value. Higher means less predictable.
        """
        import torch

        encodings = self._tokenizer(text, return_tensors="pt").to(self.device)
        input_ids = encodings.input_ids

        if input_ids.size(1) == 0:
            return 0.0

        with torch.no_grad():
            outputs = self._model(input_ids, labels=input_ids)
            loss = outputs.loss

        return math.exp(loss.item())

    def _perplexity_of_slice(self, input_ids: Any, start: int, end: int) -> float:
        """Compute perplexity for a token slice."""
        import torch

        sliced = input_ids[:, start:end]
        if sliced.size(1) < 2:
            return 0.0

        with torch.no_grad():
            outputs = self._model(sliced, labels=sliced)
            loss = outputs.loss

        return math.exp(loss.item())

    def score(self, text: str) -> float:
        """Return 0.0-1.0 score. Higher means more likely adversarial.

        Checks both detection modes and returns the maximum signal.
        """
        if not text or not text.strip():
            return 0.0

        import torch

        encodings = self._tokenizer(text, return_tensors="pt").to(self.device)
        input_ids = encodings.input_ids
        n_tokens = input_ids.size(1)

        if n_tokens < 4:
            return 0.0

        # Mode 1: length/perplexity ratio.
        ppl = self.perplexity(text)
        ratio = ppl / n_tokens
        length_score = min(ratio / self.length_ratio_threshold, 1.0)

        # Mode 2: suffix vs prefix perplexity.
        suffix_len = max(2, int(n_tokens * self.suffix_fraction))
        split_point = n_tokens - suffix_len

        prefix_ppl = self._perplexity_of_slice(input_ids, 0, split_point)
        suffix_ppl = self._perplexity_of_slice(input_ids, split_point, n_tokens)

        suffix_score = 0.0
        if prefix_ppl > 0:
            suffix_ratio = suffix_ppl / prefix_ppl
            suffix_score = min(suffix_ratio / self.suffix_ratio_threshold, 1.0)

        return max(length_score, suffix_score)

    def scan_and_emit(
        self,
        text: str,
        principal: str = "system",
        source: str = "unknown",
    ) -> float:
        """Score and emit SecurityEvent if flagged.

        Args:
            text: Content to scan.
            principal: Principal associated with this content.
            source: Human-readable source label.

        Returns:
            Score 0.0-1.0.
        """
        result = self.score(text)
        if result >= 0.5:
            from tessera.events import EventKind, SecurityEvent, emit

            emit(
                SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=principal,
                    detail={
                        "scanner": "perplexity",
                        "source": source,
                        "score": result,
                        "model": self.model_name,
                        "owasp": "LLM01",
                        "rule": "AGENT-perplexity-adversarial-suffix",
                    },
                )
            )
        return result


_scanner: PerplexityScanner | None = None


def perplexity_score(text: str) -> float:
    """Module-level scorer for use with ScannerRegistry.

    Lazily initializes the scanner on first call.

    Raises:
        ImportError: If torch/transformers are not installed.
    """
    global _scanner  # noqa: PLW0603
    if _scanner is None:
        _scanner = PerplexityScanner()
    return _scanner.score(text)
