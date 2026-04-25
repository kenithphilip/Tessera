# LlamaIndex integration

Tessera plugs into LlamaIndex via a `BaseCallbackHandler`.

## Install

```bash
pip install "tessera-mesh>=0.13"
pip install "llama-index>=0.12"
```

## Wire

```python
from llama_index.core.callbacks import CallbackManager
from tessera.adapters.llamaindex import MeshLlamaIndexHandler

handler = MeshLlamaIndexHandler(trust_key=b"...", critic_mode="on")
callback_manager = CallbackManager([handler])

# Pass into LlamaIndex agent / query engine constructors:
agent = ReActAgent.from_tools(
    tools=[...],
    callback_manager=callback_manager,
)
```

## Tested versions

| LlamaIndex | Tessera |
| --- | --- |
| 0.12.x | 0.13.0 |

## Upstream contribution

Wave 2H PR: https://github.com/run-llama/llama_index/pull/<TBD-2H-llamaindex>.
