# Self-managed serving-TLS certificate

The server can **issue its own HTTPS listener certificate from an internal CA**
instead of loading a static `tls_cert`/`tls_key` pair from disk. When
`server.tls.self_issue` is enabled, the PKI dogfoods its own transport security:
the serving certificate is issued through `ca.Manager` (the same HSM-backed path
that issues every other leaf), and a background loop re-issues it before it
expires — swapping it into the live listener without a restart.

Two invariants drive the design:

- **The private key never touches disk.** It is generated in and used through the
  configured key provider (HSM / software / cloud KMS); the TLS stack signs
  handshakes through a provider-backed `crypto.Signer`, so on a PKCS#11 HSM the
  serving key stays **non-extractable** on the token — the same guarantee the CA
  keys enjoy ([HSM configuration](hsm-configuration.md)).
- **Rotation is hitless.** A background loop re-issues the certificate before it
  expires and swaps it through the single `tls.Config.GetCertificate` hook
  (the *Holder*, shared with the OCSP-stapling path), so in-flight and new
  handshakes always see a consistent certificate and the listener never restarts.

This is off by default. It is most useful for **internal / mesh deployments**
where the PKI's own trust chain is already distributed to clients, and for
avoiding a static key pair on disk on every replica.

## Enabling it

```yaml
server:
  tls:
    self_issue:
      enabled: true
      ca_id: "web-ica"             # internal CA that issues the serving cert (required)
      profile: "server"            # serverAuth TLS-leaf profile (default: server)
      common_name: ""              # default: first dnsname, then a stable fallback
      dnsnames: ["pki.example.com", "localhost"]
      ips: ["127.0.0.1"]
      key_label: ""                # provider key label (default: serving-tls-<ca_id>)
      key_type: "ecdsa-sha2-nistp256"
      # Re-issue this long before NotAfter. Empty falls back to a third of the
      # certificate's lifetime remaining (fraction-based, like the monitor).
      renew_before: "720h"         # 30 days
      validity_seconds: 0          # 0 = profile default (serverAuth: 397 days)
```

When `self_issue.enabled` is true it **supersedes** the static `tls_cert`/`tls_key`
pair. `ca_id` is required and must name an internal CA that can issue under a
serverAuth profile. The listener comes up on the freshly issued certificate; if
the very first issuance fails the server fails to start (fail-closed), so a
misconfigured `ca_id`/`profile` surfaces immediately rather than serving a stale
or absent certificate.

### Renewal schedule

The loop re-issues once the remaining validity drops below `renew_before`. When
`renew_before` is empty it falls back to a fraction of the certificate's lifetime
(a third remaining), mirroring the [expiry monitor](expiry-monitoring.md)'s
fraction-based renewal for short-lived certificates. A failed rotation is retried
on a short delay while the **previous certificate keeps being served**, so a
transient issuance failure (e.g. a brief HSM blip) never takes the listener down.

## The serving-tls marker

Each self-issued serving certificate is written to the store with the
`serving-tls` marker, which:

- keeps these operational certificates **out of the expiry monitor and inventory
  reports** (they are self-managed; the monitor must not also try to renew them),
  and
- gives `secsy-ca doctor` and the metrics a well-known handle on "the certificate
  the server is currently serving for its own TLS".

## Observability

- **Metrics** —
  `secsy_serving_cert_expiry_timestamp_seconds` (the `NotAfter` of the
  certificate currently served, as a Unix timestamp — alert when it approaches
  now) and `secsy_serving_cert_rotations_total{result}` (so a run of rotation
  errors is visible even while the old certificate is still served).
- **Doctor** — `secsy-ca doctor` runs a `serving.self_issued` check: skipped when
  the feature is disabled, `warn` when it is enabled but no serving-tls
  certificate is on record yet (server not started, or it has not issued one),
  and otherwise reports the newest serving-tls certificate's serial / CN and its
  freshness (warns as it nears expiry).
- **Startup log** — the server logs the initial issuance
  (`serving-tls: issued initial serving certificate serial=… cn=… not_after=… (key in provider, label=…)`)
  and each rotation.

## Notes

- The serving key lives under its own provider label (`serving-tls-<ca_id>` by
  default); it is a distinct key from any CA key and never leaves the provider.
- Because the certificate is issued by an internal CA, relying clients must trust
  that CA's chain. For a public-facing listener, use ACME
  ([ACME server](acme.md)) or a static publicly-trusted certificate instead.
- The `GetCertificate` Holder is shared with OCSP stapling, so a self-issued
  serving certificate can also be stapled ([OCSP hardening](ocsp-presign-publish.md)).

## See also

- [HSM configuration](hsm-configuration.md) — the key provider the serving key
  is generated in.
- [Certificate authority](certificate-authority.md) — the CA that issues it.
- [Expiry monitoring & auto-renewal](expiry-monitoring.md) — the fraction-based
  renewal model this mirrors (and which the marker excludes it from).
- [Kubernetes deployment](kubernetes.md) — TLS options for the Helm chart.
