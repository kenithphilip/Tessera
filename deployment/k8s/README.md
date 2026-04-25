# tessera-mesh raw Kubernetes manifests

Raw manifests for clusters that do not use Helm. Apply with kustomize
(bundled with kubectl 1.21+):

```bash
kubectl apply -k deployment/k8s/
```

## Prerequisites

- Kubernetes 1.25+ (PodSecurity admission, no PodSecurityPolicy)
- The `tessera-mesh` namespace will be created by the kustomization
- An OTel collector reachable at
  `otel-collector.observability.svc.cluster.local:4317`
- A SPIRE agent socket at `/run/spire/sockets/agent.sock` on every node
  (or remove the hostPath volume from `deployment.yaml` if SPIRE is not used)

## Secrets

`secret.yaml` is a stub with empty placeholder values. Before applying to
any non-local environment:

1. Delete `secret.yaml` from the kustomization resources list.
2. Create the Secret out-of-band:

```bash
kubectl create secret generic tessera-mesh-signing \
  --namespace tessera-mesh \
  --from-literal=hmac-key="$(cat /path/to/hmac.key)" \
  --from-literal=oauth-client-secret="$(cat /path/to/oauth.secret)"
```

Or provision via the secrets-store CSI driver. See
`deployment/argocd/README.md` for an example.

## Replacing the agent-app placeholder

The Deployment contains a `busybox` placeholder. Replace the `agent-app`
container spec in `deployment.yaml` with your actual agent image before
applying to production.

## Teardown

```bash
kubectl delete -k deployment/k8s/
```
