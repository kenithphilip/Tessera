# Framework integrations

Wave 2H of the v0.12 to v1.0 plan delivers Tessera as a default
recommended callback in the five most-adopted agent frameworks.
Each framework gets a thin adapter in :mod:`tessera.adapters` and
upstream documentation showing how to wire Tessera as the security
layer.

The adapter shape is identical across frameworks: a callback /
guard / handler that intercepts every tool call, builds an
:class:`tessera.action_critic.ActionReview`, runs
:func:`tessera.policy.evaluate`, and lets the call proceed only on
ALLOW. Denied calls surface as the framework's standard "tool
returned an error" path so downstream code does not need to
special-case Tessera.

Apache-2.0 is the only license that can be safely bundled by
default in framework middleware (per ADR-0001), so the
``tessera-rs`` Python wheel (Apache-2.0) is what frameworks
recommend; the AgentMesh proxy (AGPL-3.0-or-later) is the optional
service users run separately.

| Framework | Adapter module | Wave 2H entry |
| --- | --- | --- |
| LangChain | `tessera.adapters.langchain.MeshCallbackHandler` | [langchain.md](langchain.md) |
| LangGraph | `tessera.adapters.langgraph.MeshLangGraphGuard` | [langgraph.md](langgraph.md) |
| CrewAI | `tessera.adapters.crewai.MeshCrewCallback` | [crewai.md](crewai.md) |
| LlamaIndex | `tessera.adapters.llamaindex.MeshLlamaIndexHandler` | [llamaindex.md](llamaindex.md) |
| PydanticAI | `tessera.adapters.pydantic_ai.MeshPydanticAIGuard` | [pydantic_ai.md](pydantic_ai.md) |

Each integration page lists:

- A 5-line install + wire snippet.
- The exact adapter class and the framework callback it implements.
- The minimum framework version Tessera is tested against.
- A pointer to the framework's upstream contribution PR (filed
  under Wave 2H).

The adapters are tested in `tests/adapters/`; the integration
pages exist for upstream documentation reuse.
