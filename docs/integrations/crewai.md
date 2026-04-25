# CrewAI integration

Tessera attaches to CrewAI via a per-agent callback.

## Install

```bash
pip install "tessera-mesh>=0.13"
pip install "crewai>=0.80"
```

## Wire

```python
from crewai import Agent, Crew
from tessera.adapters.crewai import MeshCrewCallback

callback = MeshCrewCallback(trust_key=b"...", critic_mode="on")

agent = Agent(
    role="researcher",
    tools=[...],
    callbacks=[callback],
)
crew = Crew(agents=[agent], tasks=[...])
result = crew.kickoff()
```

## Tested versions

| CrewAI | Tessera |
| --- | --- |
| 0.80.x | 0.13.0 |

## Upstream contribution

Wave 2H PR: https://github.com/crewAIInc/crewAI/pull/<TBD-2H-crewai>.
