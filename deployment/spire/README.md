# SPIRE + Tessera reference deployment

A minimal docker-compose that runs a SPIRE server, a SPIRE agent, and a
placeholder `retrieval` workload container. The retrieval service can
fetch a live JWT-SVID from the local Workload API and present it as
`ASM-Agent-Identity`; downstream workloads verify those identities from
live JWT bundles exposed by the same trust domain.

This is a reference. It is not hardened, not production-ready, and uses
`join_token` node attestation for simplicity. Do not copy-paste into a
real cluster without replacing node attestation with something stronger
(e.g. `k8s_sat`, `aws_iid`, or `gcp_iit`).

## Layout

```
deployment/spire/
  docker-compose.yml   three services: spire-server, spire-agent, retrieval
  server.conf          SPIRE server config (trust_domain = example.org)
  agent.conf           SPIRE agent config (workload API at /tmp/spire-agent-api/api.sock)
  README.md            this file
```

## Bring it up

```
cd deployment/spire
docker compose up -d spire-server
```

Generate a join token on the server:

```
docker compose exec spire-server \
  /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/agent
```

Copy the token into `agent.conf` under `NodeAttestor "join_token"` or
pass it on the agent CLI. Then:

```
docker compose up -d spire-agent
```

Register the retrieval workload:

```
docker compose exec spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID spiffe://example.org/agent \
  -spiffeID spiffe://example.org/retrieval \
  -selector docker:label:service:retrieval
```

Start the retrieval container:

```
docker compose up -d retrieval
```

## Using it from Tessera

Inside the retrieval container, fetch a live JWT-SVID and attach it to
outbound requests:

```python
from tessera.spire import SpireJWTSource

source = SpireJWTSource(socket_path="unix:///tmp/spire-agent-api/api.sock")
headers = source.identity_headers(audience="spiffe://example.org/ns/proxy/i/abcd")
```

On the proxy side, verify with live JWT bundles from the local Workload
API:

```python
from tessera.spire import create_spire_identity_verifier

verifier = create_spire_identity_verifier(
    socket_path="unix:///tmp/spire-agent-api/api.sock",
    expected_issuer="spiffe://example.org",
    expected_trust_domain="example.org",
)
```

Then hand `verifier` to `tessera.proxy.create_app(identity_verifier=...)`.

Important boundary: a JWT-SVID is already a signed workload credential.
It does not hand you a reusable private key for `JWTSigner`. If you want
custom-signed label payloads, use Tessera's label signers directly with
your own key material or a separate key-management path. SPIRE's live
JWT-SVID path in this repository is for workload identity and trust
bundle verification.

## Tear down

```
docker compose down -v
```

## Why this matters

Without SPIFFE, every Tessera-aware workload in a deployment has to
share a symmetric HMAC key. Compromise of any one workload forges
labels for all of them. With SPIRE + JWT-SVIDs, each workload gets a
distinct identity, short-lived SVIDs rotate automatically, and the
proxy accepts inbound workload identities only when they validate
against the local trust bundle. That is the minimum bar for a
multi-workload agent deployment that you can defend in an incident
postmortem.
