"""Tests for semantic_similarity_risk in tessera.scanners.tool_shadow.

Uses a deterministic stub embedder so sentence_transformers is not required.
"""

from __future__ import annotations

import pytest

from tessera.scanners.tool_shadow import ShadowRisk, semantic_similarity_risk


# ---------------------------------------------------------------------------
# Stub embedder: returns canned vectors for known names.
# Cosine similarity between parallel vectors = 1.0; orthogonal = 0.0.
# ---------------------------------------------------------------------------

def _stub_embedder(text: str) -> list[float]:
    """Return deterministic 4-D vectors for test tool names."""
    vectors: dict[str, list[float]] = {
        # Near-duplicate pair: both map to nearly the same direction.
        "send_email": [1.0, 0.1, 0.0, 0.0],
        "email_send": [0.99, 0.1, 0.01, 0.0],
        # Unrelated tool: orthogonal to send_email.
        "list_files": [0.0, 0.0, 1.0, 0.0],
    }
    return vectors.get(text, [0.5, 0.5, 0.5, 0.5])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_risk_when_below_threshold() -> None:
    """Orthogonal embeddings produce no ShadowRisk."""
    risks = semantic_similarity_risk(
        "send_email",
        ["list_files"],
        embedder=_stub_embedder,
        threshold=0.88,
    )
    assert risks == []


def test_shadow_risk_detected_for_near_duplicate() -> None:
    """Near-duplicate names above threshold produce a ShadowRisk."""
    risks = semantic_similarity_risk(
        "send_email",
        ["email_send", "list_files"],
        embedder=_stub_embedder,
        threshold=0.88,
    )
    assert len(risks) == 1
    risk = risks[0]
    assert isinstance(risk, ShadowRisk)
    assert risk.proposed == "send_email"
    assert risk.registered == "email_send"
    assert risk.similarity >= 0.88


def test_exact_match_always_above_threshold() -> None:
    """An exact name match yields cosine similarity 1.0."""
    risks = semantic_similarity_risk(
        "send_email",
        ["send_email"],
        embedder=_stub_embedder,
        threshold=0.99,
    )
    assert len(risks) == 1
    assert risks[0].similarity == pytest.approx(1.0, abs=0.01)


def test_fallback_when_embedder_is_none() -> None:
    """Returns empty list when embedder is None (package not installed)."""
    # Patch get_embedder to return None so we truly test the fallback path.
    import tessera.mcp.embedding as emb
    original = emb._cached_embedder
    try:
        emb._cached_embedder = None
        import os
        orig_env = os.environ.get("TESSERA_EMBEDDER")
        os.environ["TESSERA_EMBEDDER"] = "none"
        try:
            risks = semantic_similarity_risk(
                "send_email",
                ["email_send"],
                embedder=None,
            )
            assert risks == []
        finally:
            if orig_env is None:
                os.environ.pop("TESSERA_EMBEDDER", None)
            else:
                os.environ["TESSERA_EMBEDDER"] = orig_env
    finally:
        emb._cached_embedder = original


def test_threshold_boundary() -> None:
    """A pair exactly at the threshold is included."""
    from tessera.mcp.embedding import cosine_similarity

    # Two identical vectors have cosine similarity 1.0; use 1.0 as threshold.
    risks = semantic_similarity_risk(
        "send_email",
        ["send_email"],
        embedder=_stub_embedder,
        threshold=1.0,
    )
    # send_email vs send_email: similarity very close to 1.0 but floating point
    # means we allow a small tolerance -- the result should still be flagged.
    assert len(risks) == 1
