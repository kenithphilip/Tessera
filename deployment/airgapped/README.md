# tessera-mesh air-gapped installation

This directory contains scripts and configuration for deploying tessera-mesh
in a fully offline (air-gapped) environment. Artifacts must be mirrored to
an internal OCI registry before the cluster has any access to them.

Reference: https://github.com/kenithphilip/Tessera

---

## Step 1: Mirror OCI artifacts

On a bastion host with outbound internet access:

```bash
# Verify digests in dependencies.txt match upstream before mirroring.
# Replace TODO placeholders with the real SHA256 digests:
#   crane digest ghcr.io/kenithphilip/tessera-mesh:0.13.0

INTERNAL_REGISTRY=registry.internal.example.com ./mirror.sh
```

The script skips any artifact whose digest field still reads TODO. Fill in
all digests before running in a production mirror pipeline.

After mirroring, save images to a tarball for transfer across the air gap:

```bash
docker save \
  registry.internal.example.com/kenithphilip/tessera-mesh:0.13.0 \
  registry.internal.example.com/spiffe/spire-server:1.9.4 \
  registry.internal.example.com/spiffe/spire-agent:1.9.4 \
  | gzip > tessera-mesh-images.tar.gz
```

Load on the air-gapped side:

```bash
gzip -dc tessera-mesh-images.tar.gz | docker load
docker push registry.internal.example.com/kenithphilip/tessera-mesh:0.13.0
```

Update `deployment/helm/values.yaml` or `deployment/k8s/deployment.yaml` to
point `image.repository` at the internal registry path.

---

## Step 2: Bootstrap the Sigstore trust root (optional)

Required only if you use Cosign to verify image signatures. Skip this step
if your supply-chain policy uses only digest pinning.

On the internet-connected bastion:

```bash
./bootstrap-trust-root.sh ./sigstore-trust-root/
```

Transfer `sigstore-trust-root/` to the air-gapped environment and verify:

```bash
sha256sum -c sigstore-trust-root/digests.sha256
```

Set the environment variable before running Cosign commands:

```bash
export SIGSTORE_ROOT_FILE=/path/to/sigstore-trust-root/trusted_root.json
cosign verify \
  --certificate-identity=https://github.com/kenithphilip/Tessera/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  registry.internal.example.com/kenithphilip/tessera-mesh:0.13.0
```

---

## Step 3: SPIRE in fully-offline mode

Use `sample-spire-offline.yaml` as a reference for the SPIRE server
configuration. Key points for air-gapped operation:

1. Set `trust_domain` to your internal domain (not `example.internal`).
2. Replace the `disk` UpstreamAuthority CA paths with your actual CA files.
3. Generate the self-signed CA before starting SPIRE:

```bash
# Generate a self-signed CA for the SPIRE trust domain (offline).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout root-key.pem -out root-cert.pem \
  -days 3650 -nodes \
  -subj "/CN=tessera-mesh SPIRE Root CA"
```

4. Telemetry is disabled in `sample-spire-offline.yaml`. If your air-gapped
   environment has an internal Prometheus or OTel sink, add it under the
   `telemetry` key.

SPIRE federation with external deployments is not supported in offline mode.
Use SVID rotation schedules appropriate for your CA TTL settings.

---

## Step 4: Dependency version pinning

Pin all image tags and Helm chart versions in your GitOps configuration.
Never use `latest` or floating tags in air-gapped environments because you
cannot pull a new image on demand.

In `deployment/helm/values.yaml`:

```yaml
image:
  repository: registry.internal.example.com/kenithphilip/tessera-mesh
  tag: "0.13.0"
  pullPolicy: Never
```

Setting `pullPolicy: Never` ensures the kubelet uses the locally cached image
and never attempts an external pull.

---

## Step 5: Apply the manifests

```bash
# With Helm
helm install tessera-mesh deployment/helm/ \
  --namespace tessera-mesh \
  --create-namespace \
  --set image.repository=registry.internal.example.com/kenithphilip/tessera-mesh \
  --set image.pullPolicy=Never

# With kustomize
kubectl apply -k deployment/k8s/
```

---

## Troubleshooting

- Pod stays in `ImagePullBackOff`: verify the image was pushed to the
  internal registry and the `image.repository` value matches exactly.
- SPIRE attestation fails: confirm the PSAT token is mounted and the
  `service_account_allow_list` in `sample-spire-offline.yaml` includes
  `tessera-mesh:tessera-mesh`.
- Sigstore verification fails offline: confirm `SIGSTORE_ROOT_FILE` points at
  the downloaded `trusted_root.json` and the digest in `digests.sha256`
  matches the file on disk.
