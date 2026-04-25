# PydanticAI integration

Tessera plugs into PydanticAI via a per-agent guard.

## Install

```bash
pip install "tessera-mesh>=0.13"
pip install "pydantic-ai>=0.0.20"
```

## Wire

```python
from pydantic_ai import Agent
from tessera.adapters.pydantic_ai import MeshPydanticAIGuard

guard = MeshPydanticAIGuard(trust_key=b"...", critic_mode="on")

agent = Agent(
    "openai:gpt-4o",
    deps_type=MyDeps,
    instrument=guard.instrument(),
)
```

`guard.instrument()` returns a PydanticAI instrumentation
configuration that wraps every tool invocation. Denied calls
become standard PydanticAI `ModelRetry` exceptions so caller
code does not need to special-case Tessera.

## Tested versions

| PydanticAI | Tessera |
| --- | --- |
| 0.0.20 | 0.13.0 |

## Upstream contribution

Wave 2H PR: https://github.com/pydantic/pydantic-ai/pull/<TBD-2H-pydantic-ai>.
