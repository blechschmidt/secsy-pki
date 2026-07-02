# secsy-pki Helm chart

Deploys the HSM-backed secsy-pki server (X.509 + SSH CA, ACME issuance, envelope
secret encryption, RBAC & audit) to Kubernetes.

Full operational guide: [`docs/kubernetes.md`](../../../docs/kubernetes.md).

## TL;DR

```bash
# Build & load the image (kind example)
docker build -t secsy-pki:0.1.0 .
kind load docker-image secsy-pki:0.1.0

# Install with the bundled SoftHSM (dev/CI only)
helm upgrade --install secsy deploy/helm/secsy-pki \
  --namespace secsy-pki --create-namespace \
  --set image.tag=0.1.0 \
  -f deploy/helm/secsy-pki/ci/softhsm-values.yaml
```

For a fully automated kind + SoftHSM end-to-end check, run
[`scripts/k8s-smoke-test.sh`](../../../scripts/k8s-smoke-test.sh).

## What the chart renders

| Resource | When |
|----------|------|
| Deployment (+ SoftHSM init container) | always |
| ConfigMap (`config.yaml`) | always |
| Secret (HSM PIN + root password) | `secrets.create=true` |
| Service | always |
| ServiceAccount | `serviceAccount.create=true` |
| PersistentVolumeClaim | `persistence.enabled=true` and no `existingClaim` |
| Ingress | `ingress.enabled=true` |
| ServiceMonitor | `serviceMonitor.enabled=true` |
| cert-manager `Certificate` (server TLS) | `tls.certManager.enabled=true` |
| cert-manager `ClusterIssuer` (ACME) | `certManager.clusterIssuer.enabled=true` |

## Key design points

- **Secrets never touch the ConfigMap.** The HSM user PIN and the built-in root
  password are always read from a Kubernetes Secret and injected as
  `SECSY_USER_PIN` / `SECSY_ROOT_PASSWORD`. Everything else is rendered into a
  ConfigMap.
- **HSM module mount is pluggable** via `hsm.module.mode`:
  - `softhsm` — use the SoftHSM module baked into the image; an init container
    provisions a token so the readiness probe passes. Dev/CI only.
  - `hostPath` — bind-mount a vendor PKCS#11 library from the node (read-only).
  - `image` — the module already lives in a custom image; just set `modulePath`.
- **Probes are wired to the app's own endpoints**: `/healthz` (liveness/startup)
  and `/readyz` (readiness). `/readyz` fails until the server can reach the HSM
  through PKCS#11 and open the database, so a Ready pod is a working PKI.
- **Fail-closed TLS.** The server refuses cleartext unless
  `tls.allowInsecureHTTP=true`. Provide TLS via `tls.existingSecret`, have
  cert-manager issue it (`tls.certManager.enabled=true`), or terminate upstream
  and opt into HTTP behind the proxy.
- **Hardened pod**: non-root (UID 65532), read-only root filesystem, all
  capabilities dropped, `RuntimeDefault` seccomp.

## cert-manager integration

Set `config.acme.enabled=true` (pointing at an ACME-enabled issuing CA) and
`certManager.clusterIssuer.enabled=true`. The chart renders an ACME
`ClusterIssuer` targeting this server's `/acme/directory`, so any workload gets
HSM-backed certs with a plain `Certificate` object. See
[`deploy/cert-manager/`](../../cert-manager/) for standalone manifests and an
example, and [`docs/kubernetes.md`](../../../docs/kubernetes.md) for the walkthrough.

See [`values.yaml`](values.yaml) for the full, commented list of settings.
