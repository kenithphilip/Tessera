# LangGraph integration

Tessera plugs into LangGraph as a guard node that intercepts every
tool call edge in the graph.

## Install

```bash
pip install "tessera-mesh>=0.13"
pip install "langgraph>=0.2"
```

## Wire

```python
from langgraph.graph import StateGraph
from tessera.adapters.langgraph import MeshLangGraphGuard

guard = MeshLangGraphGuard(trust_key=b"...", critic_mode="on")
graph = StateGraph(MyState)
graph.add_node("tool_caller", my_tool_caller)
graph.add_node("guard", guard)
graph.add_edge("tool_caller", "guard")
graph.add_conditional_edges(
    "guard",
    guard.routing_fn,                     # routes ALLOW/DENY/REQUIRE_APPROVAL
    {"allow": "execute", "deny": END, "approve": "human_review"},
)
```

## Tested versions

| LangGraph | Tessera |
| --- | --- |
| 0.2.x | 0.13.0 |

## Upstream contribution

Wave 2H upstream PR filed at
https://github.com/langchain-ai/langgraph/pull/<TBD-2H-langgraph>.
