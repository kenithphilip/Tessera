#!/usr/bin/env bash
# oras-push.sh -- push each OCI layout produced by `tessera mcp mirror sync`
# to the GHCR mirror repository.
#
# Usage:
#   ./oras-push.sh <output-dir> <mirror-image>
#
# Arguments:
#   output-dir    Directory containing the OCI layouts under oci/<tag>/
#                 and mirror-manifest.json. Typically ./mirror-output.
#   mirror-image  OCI image repository without a tag, e.g.
#                 ghcr.io/kenithphilip/mcp-registry-mirror
#
# Environment:
#   ORAS_EXTRA_FLAGS  Additional flags forwarded to every `oras push` call.
#                     Useful for --plain-http or --insecure in local testing.
#
# Exit codes:
#   0  All artifacts pushed (or nothing to push).
#   1  Missing arguments or oras not found.
#   2  One or more oras push calls failed (push continues for remaining tags).

set -euo pipefail

OUTPUT_DIR="${1:-}"
MIRROR_IMAGE="${2:-}"

if [[ -z "$OUTPUT_DIR" || -z "$MIRROR_IMAGE" ]]; then
  echo "usage: $0 <output-dir> <mirror-image>" >&2
  exit 1
fi

if ! command -v oras &>/dev/null; then
  echo "oras CLI not found in PATH; install from https://oras.land" >&2
  exit 1
fi

OCI_DIR="${OUTPUT_DIR}/oci"
if [[ ! -d "$OCI_DIR" ]]; then
  echo "no oci/ directory found in ${OUTPUT_DIR}; nothing to push" >&2
  exit 0
fi

MEDIA_TYPE="application/vnd.tessera.mcp.signed-manifest+json"
EXTRA="${ORAS_EXTRA_FLAGS:-}"
FAIL=0

for layout_dir in "${OCI_DIR}"/*/; do
  tag="$(basename "$layout_dir")"
  ref="${MIRROR_IMAGE}:${tag}"
  echo "pushing ${ref} ..."
  # oras push --from-oci-layout reads the OCI image layout produced by
  # RegistryMirror.package_oci and pushes it as a tagged reference.
  if ! oras copy \
        --from-oci-layout "${layout_dir}" \
        "${ref}" \
        $EXTRA; then
    echo "warn: push failed for ${ref}" >&2
    FAIL=2
  else
    echo "pushed ${ref}"
  fi
done

if [[ $FAIL -ne 0 ]]; then
  echo "one or more push operations failed" >&2
fi
exit $FAIL
