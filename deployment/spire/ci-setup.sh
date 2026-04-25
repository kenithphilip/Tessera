#!/usr/bin/env bash
set -euo pipefail

# Register workload entries for CI test runner.
# Uses unix workload attestation (UID-based) since CI tests run on the host.
# The SPIRE agent socket at /tmp/spire-agent-api/api.sock is shared via volume.
#
# The agent's SPIFFE ID is assigned by the join_token NodeAttestor as
#   spiffe://<trust-domain>/spire/agent/join_token/<TOKEN>
# so the workload registration's -parentID must use that exact path,
# not a hand-rolled spiffe://<trust-domain>/agent. The previous form
# silently failed: entries got created on the server but never
# propagated to the agent, surfacing as "no identity issued"
# (PERMISSION_DENIED) at fetch time.

TRUST_DOMAIN="example.org"
TEST_UID="$(id -u)"

if [ -z "${SPIRE_JOIN_TOKEN:-}" ]; then
  echo "SPIRE_JOIN_TOKEN env var is required (export it from the join-token step)"
  exit 1
fi

PARENT_ID="spiffe://${TRUST_DOMAIN}/spire/agent/join_token/${SPIRE_JOIN_TOKEN}"
echo "Registering workload entry for UID ${TEST_UID} under parent ${PARENT_ID}..."

# Test runner workload
docker compose exec -T spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID "${PARENT_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/ci/test-runner" \
  -selector "unix:uid:${TEST_UID}" \
  -ttl 300

echo "Workload entry registered. Listing for verification:"
docker compose exec -T spire-server \
  /opt/spire/bin/spire-server entry show -parentID "${PARENT_ID}"
