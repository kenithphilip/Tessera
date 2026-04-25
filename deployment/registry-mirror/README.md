# Tessera MCP Registry Mirror

This directory contains the CI and helper tooling for the nightly registry
mirror sync. The mirror publishes Tessera-re-signed MCP manifests to
`ghcr.io/kenithphilip/mcp-registry-mirror` as OCI artifacts.

## What the mirror is

The public MCP registry contains manifests signed by each server author.
Consumers who want to enforce a strict trust tier must verify every upstream
author's Sigstore identity independently. The Tessera mirror collapses that
into a single trust anchor: only the Tessera org signing identity needs to be
trusted, and the mirror tracks exactly which upstream manifests it has
processed and when.

The SOC value is twofold:

1. Auditable inventory. The `mirror-manifest.json` produced each run is the
   authoritative on-disk record of every manifest the mirror has seen. SIEM
   pipelines can diff successive runs to detect unexpected additions or
   removals from the upstream registry.

2. Supply-chain gate. Re-signing happens only after the upstream DSSE envelope
   parses and validates against the Tessera in-toto Statement schema. Malformed
   or schema-invalid upstream manifests are skipped and logged. The mirror
   never blindly re-publishes upstream content.

## Publishing flow

```
nightly cron (GitHub Actions)
  |
  v
tessera mcp mirror sync
  --upstream https://registry.modelcontextprotocol.io
  --out ./mirror-output
  --sign hmac          (or sigstore in production with OIDC)
  |
  v
mirror-output/
  mirror-manifest.json     <- summary of all processed entries
  envelopes/<tag>.json     <- re-signed DSSE envelope per server
  oci/<tag>/               <- OCI image layout per server
  |
  v
./oras-push.sh mirror-output ghcr.io/kenithphilip/mcp-registry-mirror
  |
  v
ghcr.io/kenithphilip/mcp-registry-mirror:<tag>
```

## Configuration

Set these environment variables before running the sync:

| Variable | Purpose |
|---|---|
| `TESSERA_MIRROR_HMAC_KEY` | Hex-encoded HMAC key (at least 32 bytes). Required for `--sign hmac`. Generate with `openssl rand -hex 32`. |
| `TESSERA_MIRROR_SIGSTORE_TOKEN` | OIDC token for `--sign sigstore`. CI provides this automatically via `ACTIONS_ID_TOKEN_REQUEST_URL`. |
| `GHCR_TOKEN` | GitHub PAT or Actions token with `packages:write`. Used by `oras-push.sh`. |

## Local dry-run

```bash
export TESSERA_MIRROR_HMAC_KEY=$(openssl rand -hex 32)
tessera mcp mirror sync \
    --upstream https://registry.modelcontextprotocol.io \
    --out /tmp/mirror-test \
    --sign hmac

tessera mcp mirror status --out /tmp/mirror-test
```

## OCI artifact format

Each artifact is a single-layer OCI image. The layer blob is the raw
re-signed DSSE envelope JSON. The media type of the layer is:

```
application/vnd.tessera.mcp.signed-manifest+json
```

Consumers pull with:

```bash
oras pull ghcr.io/kenithphilip/mcp-registry-mirror:<tag> \
    --media-type application/vnd.tessera.mcp.signed-manifest+json
```

## Verification

After pulling, verify the envelope with:

```bash
tessera mcp fetch file://<path-to-envelope.json> \
    --min-tier community \
    --hmac-key $TESSERA_MIRROR_HMAC_KEY
```
