"""Neural prompt injection detection via Meta's PromptGuard 2.

Wraps the PromptGuard 2 classifier to produce a 0.0-1.0 injection
probability score. The model is loaded lazily on first use and
requires torch + transformers (install via ``pip install tessera[promptguard]``).

Source attribution: Meta PromptGuard 2 (meta-llama/Prompt-Guard-86M).
"""

from __future__ import annotations

from typing import Any


class PromptGuardScanner:
    """Neural prompt injection detector using Meta's PromptGuard 2.

    Requires: ``pip install tessera[promptguard]``
    (pulls torch + transformers).

    Args:
        model_name: HuggingFace model identifier.
        threshold: Score above which content is flagged.
        device: ``"cpu"`` or ``"cuda"``. Auto-detected when ``None``.
    """

    def __init__(
        self,
        model_name: str = "meta-llama/Prompt-Guard-86M",
        threshold: float = 0.9,
        device: str | None = None,
    ) -> None:
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise ImportError(
                "PromptGuard scanner requires torch and transformers. "
                "Install with: pip install tessera[promptguard]"
            ) from exc

        self.model_name = model_name
        self.threshold = threshold

        if device is None:
            import torch as _torch

            device = "cuda" if _torch.cuda.is_available() else "cpu"
        self.device = device

        self._tokenizer: Any = AutoTokenizer.from_pretrained(model_name)
        self._model: Any = AutoModelForSequenceClassification.from_pretrained(model_name)
        self._model.to(self.device)
        self._model.eval()

    def score(self, text: str) -> float:
        """Return injection probability 0.0-1.0.

        Higher values indicate higher likelihood of prompt injection.
        The model produces a softmax over [safe, injection]; this method
        returns the injection probability so that the convention matches
        the heuristic scanner (higher = more suspicious).
        """
        import torch

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        ).to(self.device)

        with torch.no_grad():
            logits = self._model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)

        # Class 0 = safe, class 1 = injection.
        injection_prob: float = probs[0, 1].item()
        return injection_prob

    def scan_and_emit(
        self,
        text: str,
        principal: str = "system",
        source: str = "unknown",
    ) -> float:
        """Score text and emit a SecurityEvent if above threshold.

        Args:
            text: Content to scan.
            principal: Principal associated with this content.
            source: Human-readable source label.

        Returns:
            Injection probability 0.0-1.0.
        """
        result = self.score(text)
        if result >= self.threshold:
            from tessera.events import EventKind, SecurityEvent, emit

            emit(
                SecurityEvent.now(
                    kind=EventKind.CONTENT_INJECTION_DETECTED,
                    principal=principal,
                    detail={
                        "scanner": "promptguard",
                        "source": source,
                        "score": result,
                        "threshold": self.threshold,
                        "model": self.model_name,
                        "owasp": "LLM01",
                        "rule": "AGENT-promptguard-neural-injection",
                    },
                )
            )
        return result


_scanner: PromptGuardScanner | None = None


def promptguard_score(text: str) -> float:
    """Module-level scorer for use with ScannerRegistry.

    Lazily initializes the scanner on first call.

    Raises:
        ImportError: If torch/transformers are not installed.
    """
    global _scanner  # noqa: PLW0603
    if _scanner is None:
        _scanner = PromptGuardScanner()
    return _scanner.score(text)
