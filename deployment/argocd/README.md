# tessera-mesh ArgoCD deployment

ArgoCD manifests for single-cluster (`application.yaml`) and multi-cluster
(`applicationset.yaml`) rollouts of the tessera-mesh Helm chart.

Reference: https://github.com/kenithphilip/Tessera

---

## Prerequisites

- ArgoCD 2.9+ installed in the `argocd` namespace
- The Tessera repository accessible to ArgoCD (public or with deploy key)
- Secrets provisioned via the secrets-store CSI driver (see below)

---

## Wiring the secrets-store CSI driver for signing keys

The ArgoCD Application sets `signing.existingSecret: tessera-mesh-signing`.
That Secret must exist in the `tessera-mesh` namespace before sync. The
recommended approach is the secrets-store CSI driver with your preferred
provider (Vault, AWS SSM, GCP Secret Manager, Azure Key Vault).

### Example: HashiCorp Vault provider

1. Store the keys in Vault:

```bash
vault kv put secret/tessera-mesh/signing \
  hmac-key="$(base64 /path/to/hmac.key)" \
  oauth-client-secret="$(base64 /path/to/oauth.secret)"
```

2. Create a `SecretProviderClass` in the `tessera-mesh` namespace:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: tessera-mesh-signing
  namespace: tessera-mesh
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.internal.example.com"
    roleName: "tessera-mesh"
    objects: |
      - objectName: "hmac-key"
        secretPath: "secret/data/tessera-mesh/signing"
        secretKey: "hmac-key"
      - objectName: "oauth-client-secret"
        secretPath: "secret/data/tessera-mesh/signing"
        secretKey: "oauth-client-secret"
  secretObjects:
    - secretName: tessera-mesh-signing
      type: Opaque
      data:
        - objectName: hmac-key
          key: hmac-key
        - objectName: oauth-client-secret
          key: oauth-client-secret
```

3. Mount the CSI volume in the Deployment. Add to `values.yaml`:

```yaml
extraEnv:
  - name: TESSERA_HMAC_KEY
    valueFrom:
      secretKeyRef:
        name: tessera-mesh-signing
        key: hmac-key
```

The CSI driver syncs the Secret before pod start. ArgoCD is configured to
ignore the Secret's `data` field so it does not overwrite the CSI-managed
values on each sync.

---

## Single-cluster rollout

```bash
kubectl apply -f deployment/argocd/application.yaml
argocd app sync tessera-mesh
```

---

## Multi-cluster rollout with ApplicationSet

1. Edit `applicationset.yaml` and replace the `elements` list with your
   actual cluster names and API server URLs.

2. Register each cluster with ArgoCD:

```bash
argocd cluster add prod-us-east --name prod-us-east
argocd cluster add prod-eu-west --name prod-eu-west
argocd cluster add staging       --name staging
```

3. Apply the ApplicationSet:

```bash
kubectl apply -f deployment/argocd/applicationset.yaml
```

ArgoCD generates one Application per cluster entry and syncs them
independently.

---

## Rollout strategy

These manifests do not include a Rollout resource (Argo Rollouts). The
Deployment uses the default `RollingUpdate` strategy with 2 replicas, giving
one pod available at all times during an upgrade.

For canary or blue-green rollouts, replace the Deployment with an
`argoproj.io/v1alpha1 Rollout` resource and set the strategy in
`values.yaml`. The tessera-mesh Helm chart does not ship a Rollout template
in v0.1.0; this is planned for a later release.

---

## Sync safety

`automated.prune` is set to `false` on all Applications. Enable pruning only
after manually confirming the diff does not remove load-bearing resources.
The `ignoreDifferences` block prevents ArgoCD from overwriting the
CSI-managed Secret on each sync.
