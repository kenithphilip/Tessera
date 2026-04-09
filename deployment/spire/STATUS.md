# Status: reference, not end-to-end tested

This directory is a **reference deployment**, not a continuously
verified integration. Read this file before treating it as production
guidance.

## What has been verified

- `docker-compose.yml` parses as valid compose syntax.
- `server.conf` and `agent.conf` follow the SPIRE 1.9.x config schema
  by inspection against the official SPIRE documentation.
- The walkthrough in `README.md` is the standard SPIRE quickstart flow
  adapted to the agent workload selector model.
- Tessera's `JWTSigner`, `JWTVerifier`, and `JWKSVerifier` components
  are tested with in-memory RSA keypairs. See `tests/test_signing.py`.

## What has NOT been verified

- The compose file has not been brought up end-to-end against a live
  SPIRE server. There is no CI job that stands up the stack.
- The workload registration command has not been executed against a
  running `spire-server` container. Syntax is from the SPIRE docs.
- JWT-SVIDs from a real SPIRE server have not been passed through
  `JWTSigner` and verified by `JWKSVerifier` in this repository's
  test suite.
- The `retrieval` container in the compose file does not actually run
  Tessera; it runs `sleep infinity` as a placeholder. You are
  expected to replace it with your own workload.
- Network connectivity between Tessera components and a SPIRE agent
  socket has not been tested across the container boundary.

## What this means in practice

If you deploy this reference as-is and it works, great. If it does
not, you are on your own for debugging the SPIRE side. Report bugs,
but expect us to say "we never tested this end-to-end" as a first
response.

The primitives in Tessera itself (`JWTSigner`, `JWTVerifier`,
`JWKSVerifier`) are tested and will work with any JWT-SVID that
validates against the trust bundle you give them. The untested part
is the SPIRE-specific plumbing to get those SVIDs into Tessera's
hands.

## What we want from the community

1. **A CI job that brings up the compose stack.** GitHub Actions with
   the `services:` block running `spire-server`, then a step that
   registers a workload, issues a JWT-SVID, passes it through a
   Tessera test script, and asserts the label verifies. This is the
   single most valuable contribution for the SPIRE reference.
2. **A real retrieval container.** A minimal Python workload that
   fetches a JWT-SVID from the workload API socket, signs a labeled
   segment with `JWTSigner`, and sends it to a second workload that
   verifies with `JWKSVerifier`.
3. **A Helm chart.** The compose file is the quickstart. Real
   deployments live in Kubernetes. A Helm chart that deploys SPIRE
   alongside a Tessera-protected agent would be a natural follow-up.

## Alternatives

If you want a production-ready SPIFFE + SPIRE deployment right now,
use one of:

- The official SPIRE Helm charts at
  <https://github.com/spiffe/helm-charts-hardened>
- HashiCorp Vault Enterprise 1.21+ with SPIFFE authentication
- Any platform that implements the SPIFFE Workload API

Tessera's primitives (`JWTSigner`, `JWKSVerifier`) work with all of
these because they operate on the standard JWT-SVID format, not on a
SPIRE-specific wire protocol.
