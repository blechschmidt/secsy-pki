# Automated internal TLS with ACME

Give internal services and ingress **auto-renewing TLS certificates** with the
standard ACME protocol (RFC 8555) — the same clients you'd point at Let's
Encrypt (certbot, acme.sh, lego, Caddy, Traefik, cert-manager), pointed at your
own HSM-backed CA instead.

| File | Purpose |
|------|---------|
| [`config.yaml`](config.yaml) | Server: ACME enabled against an issuing CA, all three challenge types, rate limiting |

Reference: [`docs/acme.md`](../../docs/acme.md) (EAB, wildcards/dns-01, ARI,
client-selectable profiles, STAR short-lived certs, MPIC).

---

## 1. Provision an issuing CA

Best practice is a root that only signs an intermediate, and an **issuing
intermediate** that signs leaves:

```console
$ secsy-ca -config config.yaml init-root \
      -cn "Example Root" -label "Example Root"
$ secsy-ca -config config.yaml issue-intermediate \
      -parent "Example Root" -cn "Example Issuing CA" -label "Example Issuing CA"
```

`acme.ca_label` in the config points at `Example Issuing CA`.

## 2. Run the server

```console
$ secsy-pki-server -config config.yaml
```

The ACME directory is served at `<base_url>/acme/directory`:

```console
$ curl -s https://pki.example.com/acme/directory | jq
```

Publish the root certificate to your clients' trust stores (it's the anchor the
whole chain verifies to) — e.g. via your OS/base-image config-management.

## 3. Point a client at it

### certbot (http-01)

```console
$ certbot certonly \
    --server https://pki.example.com/acme/directory \
    --standalone -d app.example.com \
    --agree-tos -m ops@example.com
```

### lego (dns-01 — required for wildcards)

```console
$ lego --server https://pki.example.com/acme/directory \
       --email ops@example.com --dns <provider> \
       --domains "*.example.com" run
```

### Caddy (automatic HTTPS)

```caddyfile
# Caddyfile
{
    acme_ca https://pki.example.com/acme/directory
    email ops@example.com
}

app.internal.example.com {
    reverse_proxy localhost:8080
}
```

### cert-manager (Kubernetes)

Use the ready-made issuer manifest in
[`deploy/cert-manager/clusterissuer-acme.yaml`](../../deploy/cert-manager/clusterissuer-acme.yaml)
(set `server:` to `https://pki.example.com/acme/directory`), then request
certificates as usual. See [`docs/kubernetes.md`](../../docs/kubernetes.md).

### The bundled host agent

For non-Kubernetes hosts, [`secsy-agent`](../../docs/agent.md) is a pure-Go
EST/ACME renewal daemon with atomic installs, reload hooks, and ARI-aware
scheduling — a lighter alternative to a full ACME client + cron.

## Restricting who can enroll (recommended for a private ACME server)

A private ACME server usually shouldn't let *any* client register. Turn on
**External Account Binding** so only clients holding a pre-shared key you issued
can create accounts:

```yaml
acme:
  require_eab: true
  eab_hmac_keys:
    team-web: "base64url-or-base64-hmac-key"   # one per team/client, handed out of band
```

```console
$ certbot register \
    --server https://pki.example.com/acme/directory \
    --eab-kid team-web --eab-hmac-key <the-key> \
    --agree-tos -m ops@example.com
```

## Notes

- **Wildcards** require `dns-01` (offered here). `http-01`/`tls-alpn-01` validate
  single names.
- **Renewal** is automatic with any ACME client's timer; the server advertises
  ACME Renewal Information (ARI) so clients renew around the CA's suggested
  window instead of a fixed fraction.
- **Rate limiting** is on in this config — a public ACME endpoint should always
  meter requests and guard the HSM (see [`docs/rate-limiting.md`](../../docs/rate-limiting.md)).
- For **very short-lived** certificates without per-renewal ACME round-trips,
  see ACME STAR (`acme.star`, [`docs/acme.md`](../../docs/acme.md)).
