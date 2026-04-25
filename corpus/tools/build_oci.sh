#!/usr/bin/env bash
# build_oci.sh: package the tessera-redteam-corpus as an OCI artifact.
#
# Prerequisites: oras (https://oras.land/), jq
#
# Usage:
#   ./tools/build_oci.sh [TAG]
#
# TAG defaults to the current quarter: vYYYY.QN (e.g., v2026.Q2).
# The script must be run from the repository root.
#
# The artifact is pushed to:
#   ghcr.io/kenithphilip/tessera-redteam-corpus:<TAG>

set -euo pipefail

REGISTRY="ghcr.io/kenithphilip/tessera-redteam-corpus"
PROBES_DIR="probes"
SCHEMA_DIR="schema"
WORK_DIR="$(mktemp -d)"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Derive default tag from current quarter.
if [[ -z "${1:-}" ]]; then
    YEAR="$(date +%Y)"
    MONTH="$(date +%m)"
    QUARTER=$(( (10#$MONTH - 1) / 3 + 1 ))
    TAG="v${YEAR}.Q${QUARTER}"
else
    TAG="$1"
fi

echo "Building OCI artifact ${REGISTRY}:${TAG}"

# Merge all probe JSONL files into a single corpus file.
CORPUS="${WORK_DIR}/tessera_community_corpus.jsonl"
for f in "${PROBES_DIR}"/*.jsonl; do
    grep -v '^$' "$f" >> "$CORPUS"
done

PROBE_COUNT="$(wc -l < "$CORPUS" | tr -d ' ')"
echo "Probe count: ${PROBE_COUNT}"

# Copy schema.
cp "${SCHEMA_DIR}/probe_v1.json" "${WORK_DIR}/probe_v1.json"

# Write a manifest sidecar.
MANIFEST="${WORK_DIR}/manifest.json"
jq -n \
    --arg tag "$TAG" \
    --arg count "$PROBE_COUNT" \
    --arg built_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{tag: $tag, probe_count: ($count | tonumber), built_at: $built_at}' \
    > "$MANIFEST"

# Push via oras.
oras push \
    "${REGISTRY}:${TAG}" \
    "${CORPUS}:application/vnd.tessera.corpus.jsonl" \
    "${WORK_DIR}/probe_v1.json:application/vnd.tessera.schema.json" \
    "${MANIFEST}:application/vnd.tessera.manifest.json"

echo "Pushed ${REGISTRY}:${TAG} (${PROBE_COUNT} probes)."
