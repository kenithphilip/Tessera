"""Wave 2H audit: Mesh* aliases over the existing Tessera* adapter classes.

The v0.12-to-v1.0 plan spells the recommended adapter class names
as ``MeshCallbackHandler`` / ``MeshLangGraphGuard`` / etc. The
in-tree implementation predates the plan and uses ``Tessera*``
names. This test pins both names to the same class so existing
callers and the spec'd names both work, and so framework-upstream
PRs (Wave 2H) can reference the spec'd names.
"""

from __future__ import annotations


def test_langchain_mesh_alias() -> None:
    from tessera.adapters.langchain import (
        MeshCallbackHandler,
        TesseraCallbackHandler,
    )

    assert MeshCallbackHandler is TesseraCallbackHandler


def test_langgraph_mesh_alias() -> None:
    from tessera.adapters.langgraph import (
        MeshLangGraphGuard,
        TesseraLangGraphGuard,
    )

    assert MeshLangGraphGuard is TesseraLangGraphGuard


def test_crewai_mesh_alias() -> None:
    from tessera.adapters.crewai import (
        MeshCrewCallback,
        TesseraCrewCallback,
    )

    assert MeshCrewCallback is TesseraCrewCallback


def test_llamaindex_mesh_alias() -> None:
    from tessera.adapters.llamaindex import (
        MeshLlamaIndexHandler,
        TesseraLlamaIndexHandler,
    )

    assert MeshLlamaIndexHandler is TesseraLlamaIndexHandler


def test_pydantic_ai_mesh_alias() -> None:
    from tessera.adapters.pydantic_ai import (
        MeshPydanticAIGuard,
        TesseraPydanticAIGuard,
    )

    assert MeshPydanticAIGuard is TesseraPydanticAIGuard
