# SPIRE + Tessera reference deployment

A minimal docker-compose that runs a SPIRE server, a SPIRE agent, and a
placeholder `retrieval` workload container. The retrieval service uses
`tessera.signing.JWTSigner` with a JWT-SVID minted by SPIRE; downstream
workloads verify those labels using `JWKSVerifier` pointed at the
trust domain's bundle endpoint.

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

Inside the retrieval container, fetch a JWT-SVID and hand it to
`JWTSigner`. The simplest path uses the `py-spiffe` library:

```python
from pyspiffe.workloadapi import default_jwt_source
from tessera.signing import JWTSigner
from tessera.context import make_segment
from tessera.labels import Origin

with default_jwt_source() as jwt_source:
    svid = jwt_source.get_jwt_svid(audiences=["tessera-proxy"])
    signer = JWTSigner(
        private_key=svid.private_key_pem(),
        key_id=svid.key_id(),
        issuer="spiffe://example.org/retrieval",
    )
    segment = make_segment(
        content=scraped_page,
        origin=Origin.WEB,
        principal="spiffe://example.org/retrieval",
        signer=signer,
    )
```

On the proxy side, verify with a JWKS pulled from the trust bundle
endpoint:

```python
import httpx
from tessera.signing import JWKSVerifier

def fetch_jwks():
    return httpx.get("http://spire-server:8081/bundle").json()

verifier = JWKSVerifier(
    fetch_jwks=fetch_jwks,
    expected_issuer="spiffe://example.org/retrieval",
)

if segment.verify(verifier):
    context.add(segment)
else:
    raise RuntimeError("label signature did not verify")
```

## Tear down

```
docker compose down -v
```

## Why this matters

Without SPIFFE, every Tessera-aware workload in a deployment has to
share a symmetric HMAC key. Compromise of any one workload forges
labels for all of them. With SPIRE + JWT-SVIDs, each workload gets a
distinct signing identity, short-lived SVIDs rotate automatically,
and the proxy accepts labels only from identities it has explicitly
registered. That is the minimum bar for a multi-workload agent
deployment that you can defend in an incident postmortem.
