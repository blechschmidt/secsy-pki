# Private CA for service-to-service mTLS

Stand up an HSM-backed private CA that issues short-lived **server** and
**client** certificates to internal workloads, so your services authenticate
each other with mutual TLS against a single trust anchor. Automation enrolls with
a scoped **API-token service account** or a bound **mutual-TLS operator
certificate** — no shared passwords.

| File | Purpose |
|------|---------|
| [`config.yaml`](config.yaml) | Server: `mtls-server` / `mtls-client` leaf profiles + machine operator auth (API token + mTLS binding) + rate limiting |

Reference: [`docs/certificate-authority.md`](../../docs/certificate-authority.md),
[`docs/authentication.md`](../../docs/authentication.md),
[`docs/rbac-and-audit.md`](../../docs/rbac-and-audit.md).

---

## 1. Provision an issuing CA

```console
$ secsy-ca -config config.yaml init-root \
      -cn "Example Root" -label "Example Root"
$ secsy-ca -config config.yaml issue-intermediate \
      -parent "Example Root" -cn "Example Issuing CA" -label "Example Issuing CA"
$ secsy-pki-server -config config.yaml
```

Distribute the **root** certificate to every service's trust store — it's the
anchor both ends verify against.

## 2. Issue a server certificate

Workloads hold their own private key; the CA signs a CSR (the key never leaves
the workload). Generate a key + CSR, then sign it under the `mtls-server`
profile:

```console
# On the service host
$ openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout api.key -out api.csr -subj "/CN=api.svc.internal" \
      -addext "subjectAltName=DNS:api.svc.internal"

# Sign it (operator/automation side)
$ secsy-ca -config config.yaml issue \
      -ca "Example Issuing CA" -profile mtls-server \
      -csr api.csr -chain -out api.crt
```

## 3. Issue a client / workload-identity certificate

```console
$ openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout worker.key -out worker.csr -subj "/CN=worker.svc.internal"
$ secsy-ca -config config.yaml issue \
      -ca "Example Issuing CA" -profile mtls-client \
      -csr worker.csr -chain -out worker.crt
```

`mtls-client` carries `clientAuth`; `mtls-server` carries `serverAuth`. For a
workload that both dials and serves, use the built-in `server-client` profile.

## 4. Wire up mutual TLS

Each side presents its certificate and requires + verifies the peer's against the
root. A quick smoke test with openssl:

```console
# Server requires and verifies a client cert
$ openssl s_server -accept 8443 -cert api.crt -key api.key \
      -CAfile root.pem -Verify 1 -www

# Client presents its cert and verifies the server
$ openssl s_client -connect localhost:8443 \
      -cert worker.crt -key worker.key -CAfile root.pem
```

In real deployments this is the same certificate/key/CA-bundle triple your
proxy, service mesh, or application TLS config consumes (nginx
`ssl_client_certificate` + `ssl_verify_client on`, Envoy `validation_context`,
Go `tls.Config{Certificates, ClientCAs, RootCAs, ClientAuth: RequireAndVerify}`,
…).

## 5. Automate enrollment from CI / config management

Mint a scoped **service account** token with only the `issuer` role (least
privilege — it can issue/renew/revoke and nothing else) and hand it to your
deployer:

```console
$ secsy-ca -config config.yaml token create -name deployer -roles issuer -expires-days 90
# prints the secret ONCE: secsy_pat_XXXXXXXX…  (store it as a CI secret)
```

Then issue over the REST API with that token — no HSM access on the CI side:

```console
$ curl -fsS -X POST "https://pki.example.com/api/ca/$CA_ID/issue" \
      -H "Authorization: Token $SECSY_TOKEN" \
      -H 'Content-Type: application/json' \
      -d "{\"csr\":$(jq -Rs . < worker.csr),\"profile\":\"mtls-client\"}" \
  | jq -r '.certificate, .chain' > worker-bundle.pem
```

Prefer certificate-based automation? The [`config.yaml`](config.yaml) also enables
an `auth.mtls` binding: a `deploy-robot` client certificate (issued by an
operator client-CA you control) authenticates as an `issuer`. See
[`docs/authentication.md`](../../docs/authentication.md).

For fully unattended renewal on each host, run the
[host agent](../../docs/agent.md) (EST/ACME) instead of scripting `curl`.

## Notes

- **Short lifetimes are the design.** These profiles default to 7–14 days; a
  global `policy.max_cert_validity_days: 90` caps everything. Renew often and
  automatically rather than issuing long-lived certs.
- **Revocation.** Revoke with `secsy-ca revoke -serial …`; OCSP and CRL are
  served for relying parties (see [`docs/certificate-authority.md`](../../docs/certificate-authority.md)).
- **Least privilege.** The service-account token holds only `issuer`; keep the
  break-glass root disabled in production (`policy.allow_root_basic_auth: false`).
- **Workload identity at scale.** For SPIFFE `spiffe://` SVIDs (X.509 + JWT) with
  a trust-domain allowlist, see [`docs/spiffe.md`](../../docs/spiffe.md).
