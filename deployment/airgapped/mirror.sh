#!/usr/bin/env bash
# mirror.sh - Pull OCI artifacts listed in dependencies.txt and re-tag for
# an internal registry.
#
# Usage:
#   INTERNAL_REGISTRY=registry.internal.example.com ./mirror.sh
#
# Prerequisites:
#   - Docker (or another OCI-compatible client: podman, crane)
#   - Network access to the source registries (run this on a bastion with
#     outbound internet access before transferring images to the air-gapped env)
#   - Write access to INTERNAL_REGISTRY
#
# After mirroring, transfer images to the air-gapped network via:
#   docker save <images> | gzip > tessera-mesh-images.tar.gz
# then on the air-gapped side:
#   gzip -dc tessera-mesh-images.tar.gz | docker load
#   docker push <internal-registry>/<repo>:<tag>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_FILE="${SCRIPT_DIR}/dependencies.txt"
INTERNAL_REGISTRY="${INTERNAL_REGISTRY:-}"

if [[ -z "${INTERNAL_REGISTRY}" ]]; then
  echo "ERROR: set INTERNAL_REGISTRY to your internal OCI registry hostname." >&2
  exit 1
fi

if [[ ! -f "${DEPS_FILE}" ]]; then
  echo "ERROR: ${DEPS_FILE} not found." >&2
  exit 1
fi

# Read non-comment, non-empty lines from dependencies.txt
while IFS= read -r line; do
  [[ "${line}" =~ ^#.*$ || -z "${line}" ]] && continue

  image="$(echo "${line}" | awk '{print $1}')"
  digest="$(echo "${line}" | awk '{print $2}')"

  if [[ "${digest}" == *"TODO"* ]]; then
    echo "SKIP (unverified digest): ${image}" >&2
    continue
  fi

  # Derive the internal tag from the source image path.
  # ghcr.io/kenithphilip/tessera-mesh:0.13.0 -> registry.internal/tessera-mesh:0.13.0
  repo_and_tag="$(echo "${image}" | sed 's|^[^/]*/||')"
  internal_image="${INTERNAL_REGISTRY}/${repo_and_tag}"

  echo "Pulling  ${image}@${digest}"
  docker pull "${image}@${digest}"

  echo "Tagging  ${internal_image}"
  docker tag "${image}@${digest}" "${internal_image}"

  echo "Pushing  ${internal_image}"
  docker push "${internal_image}"

  echo "OK: ${internal_image}"
done < "${DEPS_FILE}"

echo ""
echo "Mirror complete. Update image references in values.yaml or deployment.yaml"
echo "to point at ${INTERNAL_REGISTRY}/..."
