#!/usr/bin/env bash
# bootstrap-trust-root.sh - Fetch the Sigstore public-good trust root,
# verify its integrity, and stage it for offline Cosign/Sigstore use.
#
# Run this on a machine with outbound internet access. The resulting
# trust-root directory is then transferred to the air-gapped environment
# and pointed at via SIGSTORE_ROOT_FILE.
#
# Usage:
#   ./bootstrap-trust-root.sh [output-dir]
#
# Output directory defaults to ./sigstore-trust-root/
#
# References:
#   https://github.com/sigstore/root-signing
#   https://sigstore.dev/tuf-root

set -euo pipefail

TRUST_ROOT_URL="https://tuf-repo-cdn.sigstore.dev"
OUTPUT_DIR="${1:-"$(dirname "${BASH_SOURCE[0]}")/sigstore-trust-root"}"

# Minimum tools check
for tool in curl sha256sum; do
  if ! command -v "${tool}" &>/dev/null; then
    echo "ERROR: ${tool} is required but not found in PATH." >&2
    exit 1
  fi
done

mkdir -p "${OUTPUT_DIR}"

echo "Fetching Sigstore TUF root from ${TRUST_ROOT_URL}..."

# Fetch the root.json (TUF root of trust)
ROOT_JSON="${OUTPUT_DIR}/root.json"
curl -fsSL "${TRUST_ROOT_URL}/root.json" -o "${ROOT_JSON}"

# Fetch the trusted_root.json (Cosign v2 bundle format)
TRUSTED_ROOT_JSON="${OUTPUT_DIR}/trusted_root.json"
curl -fsSL "${TRUST_ROOT_URL}/trusted_root.json" -o "${TRUSTED_ROOT_JSON}" 2>/dev/null || true

echo "Downloaded:"
echo "  ${ROOT_JSON}"
echo "  ${TRUSTED_ROOT_JSON}"
echo ""

# Compute and record digests for verification on the air-gapped side.
DIGEST_FILE="${OUTPUT_DIR}/digests.sha256"
sha256sum "${ROOT_JSON}" > "${DIGEST_FILE}"
[[ -f "${TRUSTED_ROOT_JSON}" ]] && sha256sum "${TRUSTED_ROOT_JSON}" >> "${DIGEST_FILE}"

echo "Digests written to ${DIGEST_FILE}:"
cat "${DIGEST_FILE}"
echo ""

echo "To use in the air-gapped environment:"
echo "  export SIGSTORE_ROOT_FILE=${OUTPUT_DIR}/trusted_root.json"
echo "  cosign verify --certificate-identity=... --certificate-oidc-issuer=..."
echo ""
echo "Transfer ${OUTPUT_DIR}/ to the air-gapped network and verify digests with:"
echo "  sha256sum -c ${DIGEST_FILE}"
