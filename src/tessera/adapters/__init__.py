"""Framework adapters for Tessera.

Lazy-import adapters so that Tessera does not require framework
packages as hard dependencies. Import the adapter you need directly:

    from tessera.adapters.langchain import TesseraCallbackHandler
    from tessera.adapters.openai_agents import TesseraAgentHooks
    from tessera.adapters.crewai import TesseraCrewCallback
    from tessera.adapters.google_adk import TesseraADKCallbacks
    from tessera.adapters.llamaindex import TesseraLlamaIndexHandler
    from tessera.adapters.haystack import TesseraHaystackGuard
    from tessera.adapters.langgraph import TesseraLangGraphGuard
    from tessera.adapters.pydantic_ai import TesseraPydanticAIGuard
"""
