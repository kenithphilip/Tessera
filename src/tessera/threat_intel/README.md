# tessera.threat_intel

Structured threat-intelligence feed schema for Tessera-aware deployments.

## What this is

`tessera.threat_intel` defines a Pydantic schema for a threat-intel feed
covering three indicator-of-compromise (IOC) kinds relevant to LLM agent
security:

- **MaliciousMcpServer**: a known-bad MCP server URI observed exfiltrating
  data or injecting adversarial prompts.
- **InjectionPattern**: a regex, substring, or embedding descriptor that
  matches known prompt injection payloads.
- **ModelFingerprint**: a model family or weight hash associated with
  elevated risk (uncensored fine-tunes, supply-chain-compromised weights).

All models are `frozen=True` and use strict Pydantic validation.

## Non-hosting decision (ADR-0002)

Feed hosting with SLA is out of scope for the Tessera OSS repository. The
decision is recorded in `docs/adr/0002-no-hosted-services.md`. In summary:
operating a live threat-intel service from the OSS layer would impose
availability commitments and commercial-service governance complexity that
conflict with Tessera's role as a composable library.

AgentMesh Cloud (a future separate offering) may host a live feed against
this schema. The OSS repository ships only:

1. The schema (this package).
2. A reference sample feed (`sample_feed.json`).
3. The planned downstream consumer (`tessera.scanners.threat_intel_match`,
   Wave 3F).

## Schema layout

```
ThreatIntelFeed
  schema_version: "tessera.threat_intel.v1"    (fixed literal)
  generated_at:   datetime (UTC)
  feed_id:        UUID string
  maintainer:     str
  iocs:           tuple of MaliciousMcpServer | InjectionPattern | ModelFingerprint
  signatures:     dict[key_id, public_key_material]

IOC (base)
  ioc_id:         UUID string
  kind:           IOCKind enum
  value:          str
  confidence:     float 0.0 to 1.0
  first_seen:     datetime (UTC)
  last_seen:      datetime (UTC)
  tags:           frozenset[str]
  source:         str

MaliciousMcpServer extends IOC
  domain:         str
  protocol:       "http" | "https" | "mcp+ws" | "mcp+stdio"

InjectionPattern extends IOC
  pattern_type:            "regex" | "substring" | "embedding"
  pattern_value:           str
  mitre_atlas_techniques:  tuple[str, ...]   (AML.T* codes)

ModelFingerprint extends IOC
  model_family:  str
  weight_hash:   str | None   (SHA-256 of weights)
  provider:      str | None
  risk_class:    "low" | "medium" | "high" | "critical"
```

The `signatures` dict holds the feed maintainer's public key material keyed
by key ID. Consumers should verify the feed signature before trusting IOC
data. The signature scheme is intentionally unspecified at this layer;
signers may use HMAC-SHA256, RS256 JWTs, or any key type appropriate to
their deployment trust model.

## Consuming a feed

```python
from tessera.threat_intel import validate_feed, InjectionPattern

with open("my_feed.json") as f:
    feed = validate_feed(f.read())

injection_patterns = [
    ioc for ioc in feed.iocs
    if isinstance(ioc, InjectionPattern)
]
```

The planned scanner integration (`tessera.scanners.threat_intel_match`) will
accept a `ThreatIntelFeed` and expose a `Scanner`-protocol-compatible
interface so feeds can be composed into the standard `tessera.scanners`
pipeline.

## Sample feed

`sample_feed.json` contains four placeholder IOCs:

- One `MaliciousMcpServer` at `evil-mcp.example.com` (not real).
- Two `InjectionPattern` records: a substring match and a regex match
  (illustrative payloads, not curated threat data).
- One `ModelFingerprint` for a hypothetical uncensored fine-tune (not real).

The public key in `signatures` is a placeholder string. Do not treat any
value in the sample feed as real threat intelligence.

## Getting the JSON Schema

```python
from tessera.threat_intel import feed_schema_v1

schema = feed_schema_v1()
# schema is a dict suitable for passing to any JSON Schema validator.
```
