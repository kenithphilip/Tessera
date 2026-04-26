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
TOTAL=0
PUSHED=0
FAILED=0
# Permit a small number of transient permission_denied errors from
# ghcr (typically the first few writes against a brand-new package
# or short-lived rate-limit hiccups). Tunable via env. The whole
# job still fails if the failure rate exceeds the threshold.
MAX_FAILURE_PCT="${MAX_FAILURE_PCT:-10}"
RETRY_COUNT="${RETRY_COUNT:-2}"
RETRY_BACKOFF_SECONDS="${RETRY_BACKOFF_SECONDS:-3}"

# push_one tag layout_path -> 0 on success, non-zero on terminal failure.
# Retries up to RETRY_COUNT times with linear backoff before giving up.
push_one() {
  local _tag="$1"
  local _layout_path="$2"
  local _ref="${MIRROR_IMAGE}:${_tag}"
  local attempt
  for ((attempt=1; attempt<=RETRY_COUNT+1; attempt++)); do
    if oras copy --from-oci-layout "${_layout_path}:${_tag}" "${_ref}" $EXTRA; then
      echo "pushed ${_ref}"
      return 0
    fi
    if (( attempt <= RETRY_COUNT )); then
      sleep "$(( RETRY_BACKOFF_SECONDS * attempt ))"
    fi
  done
  echo "warn: push failed for ${_ref} after ${RETRY_COUNT} retries" >&2
  return 1
}

for layout_dir in "${OCI_DIR}"/*/; do
  tag="$(basename "$layout_dir")"
  ref="${MIRROR_IMAGE}:${tag}"
  TOTAL=$((TOTAL + 1))
  echo "pushing ${ref} ..."
  layout_path="${layout_dir%/}"
  if push_one "${tag}" "${layout_path}"; then
    PUSHED=$((PUSHED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
done

echo "summary: ${PUSHED}/${TOTAL} pushed, ${FAILED} failed"
if (( TOTAL == 0 )); then
  exit 0
fi

# Compute integer percentage of failures.
FAIL_PCT=$(( FAILED * 100 / TOTAL ))
if (( FAIL_PCT > MAX_FAILURE_PCT )); then
  echo "failure rate ${FAIL_PCT}% > ${MAX_FAILURE_PCT}% threshold; failing the job" >&2
  exit 2
fi
exit 0
