"""Embedder protocol and factory for semantic text similarity.

Used by the tool shadow scanner to detect near-duplicate tool names that
edit-distance alone cannot catch (e.g. "send_email" vs "email_send" have
Levenshtein distance 6 but cosine similarity near 1.0 once embedded).

Default backend: sentence-transformers/all-MiniLM-L6-v2 (fast, ~80 MB,
no GPU required). Switch to OpenAI via TESSERA_EMBEDDER=openai:text-embedding-3-small.

The sentence_transformers import is lazy so the package remains optional.
Production deployments that do not need semantic shadow detection pay no
import cost.
"""

from __future__ import annotations

import math
import os
from typing import Callable, Protocol


class Embedder(Protocol):
    """Callable that maps a string to a float vector."""

    def __call__(self, text: str) -> list[float]: ...


# Module-level cache so the model is loaded at most once per process.
_cached_embedder: Embedder | None = None


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Return cosine similarity in [-1, 1] between two vectors.

    Args:
        a: First embedding vector.
        b: Second embedding vector.

    Returns:
        Cosine similarity. Returns 0.0 if either vector is zero-length.
    """
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def _make_sentence_transformer_embedder(model_name: str) -> Embedder:
    """Build an embedder backed by sentence-transformers.

    Args:
        model_name: HuggingFace model identifier.

    Returns:
        Callable that encodes a single string to a float list.

    Raises:
        ImportError: If sentence_transformers is not installed.
    """
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "sentence_transformers is not installed. "
            "Install it with: pip install sentence-transformers"
        ) from exc

    model = SentenceTransformer(model_name)

    def embed(text: str) -> list[float]:
        return model.encode(text, convert_to_numpy=True).tolist()

    return embed


def _make_openai_embedder(model_name: str) -> Embedder:
    """Build an embedder backed by the OpenAI embeddings API.

    Args:
        model_name: OpenAI model identifier (e.g. text-embedding-3-small).

    Returns:
        Callable that calls the OpenAI API for each string.

    Raises:
        ImportError: If the openai package is not installed.
    """
    try:
        import openai  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "openai is not installed. Install it with: pip install openai"
        ) from exc

    client = openai.OpenAI()

    def embed(text: str) -> list[float]:
        response = client.embeddings.create(input=text, model=model_name)
        return response.data[0].embedding

    return embed


def get_embedder() -> Embedder | None:
    """Return the configured embedder, or None if no backend is available.

    Reads TESSERA_EMBEDDER to determine the backend:
      - unset or "sentence-transformers": uses all-MiniLM-L6-v2
      - "openai:<model>": calls the OpenAI embeddings API
      - "none": disables embedding (returns None)

    The result is cached at module level after the first successful load.

    Returns:
        An Embedder callable, or None if embedding is disabled or unavailable.
    """
    global _cached_embedder  # noqa: PLW0603

    if _cached_embedder is not None:
        return _cached_embedder

    spec = os.environ.get("TESSERA_EMBEDDER", "sentence-transformers")

    if spec == "none":
        return None

    if spec.startswith("openai:"):
        model = spec[len("openai:"):]
        _cached_embedder = _make_openai_embedder(model)
        return _cached_embedder

    # Default: sentence-transformers with all-MiniLM-L6-v2.
    # The env var can also be "sentence-transformers" (bare) or
    # "sentence-transformers:<model>" for a custom model.
    if spec.startswith("sentence-transformers:"):
        model = spec[len("sentence-transformers:"):]
    else:
        model = "sentence-transformers/all-MiniLM-L6-v2"

    try:
        _cached_embedder = _make_sentence_transformer_embedder(model)
        return _cached_embedder
    except ImportError:
        return None


# Convenience type alias for callers that want to annotate their own embedder refs.
EmbedFn = Callable[[str], list[float]]
