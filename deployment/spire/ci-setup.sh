#!/usr/bin/env bash
set -euo pipefail

# Register workload entries for CI test runner.
# Uses unix workload attestation (UID-based) since CI tests run on the host.
# The SPIRE agent socket at /tmp/spire-agent-api/api.sock is shared via volume.

TRUST_DOMAIN="example.org"
PARENT_ID="spiffe://${TRUST_DOMAIN}/agent"
TEST_UID="$(id -u)"

echo "Registering workload entries for UID ${TEST_UID}..."

# Test runner workload
docker compose exec -T spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID "${PARENT_ID}" \
  -spiffeID "spiffe://${TRUST_DOMAIN}/ci/test-runner" \
  -selector "unix:uid:${TEST_UID}" \
  -ttl 300

echo "Workload entries registered."
