# LangChain integration

Tessera ships as a LangChain `BaseCallbackHandler` so existing
LangChain agents can adopt Tessera as the policy layer with two
extra lines.

## Install

```bash
pip install "tessera-mesh>=0.13"
pip install "langchain>=0.3"
```

## Wire

```python
from langchain.agents import AgentExecutor
from tessera.adapters.langchain import MeshCallbackHandler

handler = MeshCallbackHandler(
    trust_key=b"...",                     # 32-byte HMAC key
    enforcement_mode="args",              # default for v0.13.x is "both"
    critic_mode="stub",                   # set "on" once a model is wired
)

executor = AgentExecutor(
    agent=my_agent,
    tools=my_tools,
    callbacks=[handler],
)
```

## What the handler does

For every tool call LangChain proposes, the handler:

1. Wraps the call in a :class:`tessera.action_critic.ActionReview`.
2. Runs :func:`tessera.policy.evaluate` with the active context.
3. Runs :func:`tessera.action_critic.review` (skipped when
   ``critic_mode="off"``).
4. If both return ALLOW, the call proceeds. If either returns
   DENY, the handler raises
   :class:`tessera.policy.PolicyViolation` which LangChain
   surfaces as a standard tool error.
5. REQUIRE_APPROVAL routes through the configured human-in-the-
   loop callback (see ``MeshCallbackHandler(approval_handler=...)``).

## Tested versions

| LangChain | Tessera |
| --- | --- |
| 0.3.x | 0.13.0 |

## Upstream contribution

Wave 2H upstream PR filed at
https://github.com/langchain-ai/langchain/pull/<TBD-2H-langchain>.

The PR adds Tessera as a documented "secure-by-default" callback
in the LangChain agent docs and ships the adapter in
`langchain-tessera` (Apache-2.0 wheel).
