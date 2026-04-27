"""TPS-005 framework adapter conformance tests.

Each module under this package pins the public interface of one
Tessera framework adapter (LangChain, LangGraph, CrewAI,
LlamaIndex, PydanticAI) so a future framework version that
silently drops a parameter or renames a hook breaks loudly here.

Layered structure per file:

1. **Stub-based contract** (runs in default CI). Uses the
   ``_stub_framework`` helpers from ``conftest`` to inject mock
   modules into ``sys.modules`` so the adapter imports succeed
   without the real framework dependency. Asserts:
   - The adapter instantiates.
   - Each public method is callable with the documented signature.
   - Tessera ``SecurityEvent``s fire on the documented occasions
     (capture sink + assert).

2. **Live integration** (``@pytest.mark.integration``, gated on
   the actual framework being installed). Constructs a tiny but
   real pipeline (chain / graph / crew / agent) and exercises the
   adapter end-to-end. Skipped when the framework is missing.

Run fast contract tests only:

    pytest tests/conformance/ -v -m "not integration"

Run full conformance (requires the ``conformance`` extra):

    pip install -e '.[conformance]'
    pytest tests/conformance/ -v
"""
