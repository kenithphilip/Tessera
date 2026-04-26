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
echo "Registering workload entries under parent ${PARENT_ID}..."
echo "  host runner UID: ${TEST_UID}"

# The Workload API socket is bind-mounted between host and the
# spire-agent container. Tests run as the host runner UID
# (typically 1001 on GitHub Actions ubuntu-latest), but
# `docker exec spire-agent-ci ...` calls connect as the
# container's default user (uid 0). Both paths need a workload
# entry against the same SPIFFE ID so the agent issues an
# identity regardless of which side opens the socket. Without
# the uid 0 entry the in-container PEERCRED diagnostic step
# fails with "no identity issued" (PERMISSION_DENIED) even when
# the host-side test would succeed.

# Test runner workload (host UID, normally 1001)
docker compose exec -T spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID "${PARENT_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/ci/test-runner" \
  -selector "unix:uid:${TEST_UID}" \
  -ttl 300

# Container-side workload (uid 0) - same SPIFFE ID so any
# downstream consumer treats them as the same identity. Skip
# duplicate when the runner happens to also be uid 0 (unusual).
if [ "${TEST_UID}" != "0" ]; then
  docker compose exec -T spire-server \
    /opt/spire/bin/spire-server entry create \
    -parentID "${PARENT_ID}" \
    -spiffeID "spiffe://${TRUST_DOMAIN}/ci/test-runner" \
    -selector "unix:uid:0" \
    -ttl 300
fi

echo "Workload entries registered. Listing for verification:"
docker compose exec -T spire-server \
  /opt/spire/bin/spire-server entry show -parentID "${PARENT_ID}"
