# Kubernetes deployment

Run secsy-pki on Kubernetes: a hardened container image, a Helm chart wired to
the HSM/PKCS#11 module, TLS, RBAC/policy config and the `/healthz` + `/readyz`
probes, and cert-manager integration so workloads request HSM-backed
certificates natively. A kind + SoftHSM smoke test validates the whole path.

- Container image: [`Dockerfile`](../Dockerfile)
- Helm chart: [`deploy/helm/secsy-pki`](../deploy/helm/secsy-pki) ([chart README](../deploy/helm/secsy-pki/README.md))
- cert-manager manifests: [`deploy/cert-manager`](../deploy/cert-manager)
- Smoke test: [`scripts/k8s-smoke-test.sh`](../scripts/k8s-smoke-test.sh)

Read [HSM configuration](hsm-configuration.md), [ACME](acme.md) and
[Observability](observability.md) alongside this guide.

---

## 1. Container image

The [`Dockerfile`](../Dockerfile) is multi-stage:

- **builder** (`golang:1.25-bookworm`) compiles the server and the CLIs
  (`secsy-ca`, `secsy-secret`, `secsy-ssh`, `secsy-verify`) with `CGO_ENABLED=1`.
  cgo is required because the SQLite driver (`sqlite` build tag) and the PKCS#11
  binding both link against C. `-ldflags "-s -w"` and `-trimpath` keep the
  binaries small and reproducible.
- **runtime** (`debian:bookworm-slim`) ships `ca-certificates`, plus `softhsm2`
  and `opensc` (for `softhsm2-util`/`pkcs11-tool`). It runs as non-root UID/GID
  `65532` and serves the SPA from `/app/web/static`.

```bash
docker build -t secsy-pki:0.1.0 --build-arg VERSION=0.1.0 .
docker run --rm secsy-pki:0.1.0 secsy-ca help
```

For a **production HSM**, the vendor PKCS#11 module is provided at runtime — bind
it into the container (`hsm.module.mode=hostPath`) or bake it into a derived
image (`hsm.module.mode=image`). SoftHSM in the base image is only for dev/CI.

---

## 2. Helm chart

```bash
helm upgrade --install secsy deploy/helm/secsy-pki \
  --namespace secsy-pki --create-namespace \
  --set image.repository=registry.example.com/secsy-pki \
  --set image.tag=0.1.0 \
  -f my-values.yaml
```

### HSM / PKCS#11

`hsm.module.mode` selects where the PKCS#11 `.so` comes from:

| mode | use | how it mounts |
|------|-----|---------------|
| `softhsm` | dev / CI | bundled module; an init container `softhsm2-util --init-token`s a token into a shared volume so `/readyz` passes |
| `hostPath` | node-installed HSM client (e.g. network HSM) | node dir mounted read-only at the same path; set `hsm.module.modulePath` |
| `image` | module baked into a custom image | no mount; just set `hsm.module.modulePath` |

Token selection uses `hsm.token.label` (and optional `serial`/`manufacturer`).

Production example (vendor module on the node under `/opt/hsm/lib`):

```yaml
hsm:
  module:
    mode: hostPath
    modulePath: /opt/hsm/lib/libvendorpkcs11.so
    hostPath: { path: /opt/hsm/lib, type: Directory }
  token:
    label: secsy-prod
```

### PIN and root password via Secret

The HSM **user PIN** and the built-in **root password** are never written to the
ConfigMap. They come from a Kubernetes Secret and are injected as
`SECSY_USER_PIN` and `SECSY_ROOT_PASSWORD`.

- Dev/CI: `secrets.create=true` renders the Secret from `secrets.userPin` /
  `secrets.rootPassword` (do **not** commit real values).
- Production: pre-create the Secret (e.g. via External Secrets / Vault) and set:

  ```yaml
  secrets:
    create: false
    existingSecret: secsy-pki-credentials
    pinKey: user-pin
    rootPasswordKey: root-password
  ```

### TLS

The server fails closed — it refuses cleartext unless told otherwise. Pick one:

- `tls.existingSecret: my-tls` — mount a `kubernetes.io/tls` Secret.
- `tls.certManager.enabled: true` with an `issuerRef` — cert-manager issues the
  server's own cert and the chart mounts it.
- `tls.allowInsecureHTTP: true` — plain HTTP; only behind a trusted
  TLS-terminating ingress/proxy.

### RBAC / policy / profiles

`config.rbac`, `config.policy`, and `config.profiles` render straight into
`config.yaml` (see [RBAC & audit](rbac-and-audit.md)):

```yaml
config:
  policy:
    allowRootBasicAuth: false      # disable the shared superuser in prod
    maxCertValidityDays: 397
  rbac:
    subjects:
      "1a2b3c-oidc-subject": [admin]
    groups:
      "group-uuid-pki-ops": [issuer]
  profiles:
    - name: short-lived-client
      key_usages: [digitalSignature]
      ext_key_usages: [clientAuth]
      default_validity_days: 7
      max_validity_days: 30
```

### Probes

Wired to the application endpoints and gated on real dependencies:

- **liveness / startup** → `/healthz`
- **readiness** → `/readyz` (fails until the DB opens **and** the HSM answers a
  PKCS#11 probe with the configured PIN)

So a Ready pod is a working PKI. The probe scheme follows the TLS setting
(HTTPS unless `tls.allowInsecureHTTP=true`). Tune under `probes.*`.

### Persistence & scaling

Default state is SQLite on a `ReadWriteOnce` PVC (`persistence.*`), and the
Deployment uses the `Recreate` strategy — SQLite is single-writer, so keep
`replicaCount: 1`. To scale horizontally, point every replica at a shared
PostgreSQL via the `externalDatabase` block below.

### External PostgreSQL for HA

For multi-replica high availability, run a shared PostgreSQL and enable the
chart's `externalDatabase` block. It injects `SECSY_DATABASE_DRIVER` and
`SECSY_DATABASE_DSN` (from a Secret — the DSN carries credentials and never lands
in the ConfigMap), plus the pool-size env vars, which override the rendered
config at startup.

```yaml
replicaCount: 3
persistence:
  enabled: false          # PostgreSQL is now the source of truth
externalDatabase:
  enabled: true
  driver: postgres
  # Production: reference a Secret you manage (e.g. External Secrets / Vault):
  dsnSecret:
    name: secsy-pg
    key: database-dsn
  # ...or, for dev/CI only, render an inline DSN into the chart's Secret:
  # dsn: "postgres://secsy:secsy@my-postgres:5432/secsy_pki?sslmode=require"
  maxOpenConns: 10
  maxIdleConns: 5
```

Migrate an existing single-node SQLite store into PostgreSQL **before** scaling
out, with `secsy-ca db migrate` (see the
[persistence guide](persistence.md#migrating-an-existing-sqlite-store-into-postgresql)).
The audit-chain serialization and transactional serial/CRL counters make
concurrent writes across replicas safe. HSM key material stays in the HSM — only
metadata, public certificates, and audit records live in the database.

### Metrics

With the Prometheus operator, set `serviceMonitor.enabled=true` to scrape
`/metrics`. See [Observability](observability.md).

---

## 3. cert-manager: HSM-backed certs for workloads

secsy-pki exposes an RFC 8555 ACME server backed by HSM-held CA keys, so
cert-manager's native ACME support is all that's needed for workloads to request
HSM-backed certificates declaratively — no custom controller required.

1. **Enable ACME on the server** against an ACME-enabled issuing CA (see
   [ACME](acme.md)):

   ```yaml
   config:
     acme:
       enabled: true
       caLabel: "Secsy Issuing CA"
       profile: server
   ```

2. **Render the ClusterIssuer** (needs cert-manager installed):

   ```yaml
   certManager:
     clusterIssuer:
       enabled: true
       name: secsy-pki
       email: platform@example.com
       # server: defaults to the in-cluster ACME directory URL
       skipTLSVerify: true        # or supply caBundle: <base64 PEM>
   ```

   The chart points the issuer at
   `https://<release>-secsy-pki.<ns>.svc:<port>/acme/directory`. cert-manager
   must trust the server's TLS cert — supply `caBundle` (preferred) or, for
   non-production, `skipTLSVerify`.

3. **Workloads request certs** with an ordinary `Certificate` — cert-manager
   drives the ACME order/challenge, secsy-pki signs it with an HSM-held key, and
   the result lands in a Secret:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: { name: example-app-tls, namespace: default }
   spec:
     secretName: example-app-tls
     dnsNames: [example-app.example.com]
     issuerRef: { name: secsy-pki, kind: ClusterIssuer, group: cert-manager.io }
   ```

Standalone manifests (for when cert-manager resources are managed outside the
chart) live in [`deploy/cert-manager/`](../deploy/cert-manager):
[`clusterissuer-acme.yaml`](../deploy/cert-manager/clusterissuer-acme.yaml) and
[`example-certificate.yaml`](../deploy/cert-manager/example-certificate.yaml).

> **Why ACME rather than a bespoke external issuer?** cert-manager's ACME
> integration is mature and gives the same outcome — workloads request certs
> natively and secsy-pki signs them on the HSM — without a second controller to
> operate and secure. A dedicated `external-issuer` CRD/controller could be added
> later if per-namespace `Issuer` semantics or non-ACME auth are required.

---

## 4. First CA and verification

After the release is Ready, create a CA on the HSM (keys are generated and stay
on the token):

```bash
kubectl -n secsy-pki exec deploy/secsy-secsy-pki -c secsy-pki -- \
  secsy-ca -config /etc/secsy/config.yaml init-root \
    -label secsy-prod-root -cn "Secsy Root CA" -key-type ecdsa-p384

kubectl -n secsy-pki exec deploy/secsy-secsy-pki -c secsy-pki -- \
  secsy-ca -config /etc/secsy/config.yaml list
```

Check health:

```bash
kubectl -n secsy-pki port-forward svc/secsy-secsy-pki 8443:8443
curl -k https://localhost:8443/healthz
curl -k https://localhost:8443/readyz     # {"status":"ready","components":{...}}
```

---

## 5. kind + SoftHSM smoke test

[`scripts/k8s-smoke-test.sh`](../scripts/k8s-smoke-test.sh) runs the full path on
a throwaway kind cluster: builds and loads the image, installs the chart with
[`ci/softhsm-values.yaml`](../deploy/helm/secsy-pki/ci/softhsm-values.yaml),
waits for readiness (which proves the in-cluster PKCS#11 probe passed), curls
`/healthz` and `/readyz`, and creates an HSM-backed root CA inside the pod.

```bash
scripts/k8s-smoke-test.sh                 # build, deploy, verify, tear down
KEEP=1 scripts/k8s-smoke-test.sh          # leave the cluster up for debugging
REUSE_IMAGE=1 IMAGE=secsy-pki:ci scripts/k8s-smoke-test.sh
```

It self-skips (exit 0) if `docker`, `kind`, `kubectl`, `helm`, or `curl` are
missing, so it is safe to wire into CI conditionally.
