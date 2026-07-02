# Certificate Transparency (RFC 6962)

Secsy PKI can optionally submit issued certificates to
[Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) (CT)
logs and embed the resulting **Signed Certificate Timestamps (SCTs)** into the
final certificate. Modern browsers require publicly-trusted TLS server
certificates to carry SCTs, so this is needed for any CA whose leaves must be
accepted by Chrome/Safari without a separate CT delivery mechanism (TLS
extension or stapled OCSP).

CT is **off by default** and enabled **per issuance profile**, so you can run
public, CT-logged TLS profiles alongside private profiles that never touch a log.

## How it works

For a CT-enabled profile, issuance follows RFC 6962 §3:

1. **Precertificate.** The certificate template is built with a critical
   *poison* extension (`1.3.6.1.4.1.11129.2.4.3`, value `NULL`) and signed on the
   HSM. The poison guarantees the object can never be used as a real
   certificate.
2. **Submission.** The precertificate plus its issuer chain is submitted to each
   configured log's `add-pre-chain` endpoint. Each log returns an SCT.
3. **Policy.** The collected SCTs are counted against the profile's
   `min_scts`; the `fail_open` flag decides what happens when the minimum is not
   met (see below).
4. **Embedding & final signature.** The SCTs are serialised into a
   `SignedCertificateTimestampList` and embedded as the SCT list extension
   (`1.3.6.1.4.1.11129.2.4.2`, replacing the poison). The template — identical to
   the precertificate except for that one trailing extension — is re-signed on
   the HSM to produce the certificate returned to the caller.

Because the precertificate and the final certificate differ **only** in the
trailing poison↔SCT-list extension, the `TBSCertificate` a log signs over
(precertificate TBS with the poison removed) is byte-for-byte identical to what
a relying party reconstructs from the final certificate (final TBS with the SCT
list removed). This is what makes the embedded SCTs verify. **Both signatures
happen on the HSM; the CA private key never leaves it.**

The CA key signs precertificates directly (no delegated *precertificate signing
certificate*), so the issuer key hash in each SCT is the SHA-256 of the issuing
CA's `SubjectPublicKeyInfo`.

## Configuring logs

Register the CT logs your profiles may use under `certificate_transparency`:

```yaml
certificate_transparency:
  logs:
    - name: test-log
      url: "https://ct.example.com/testlog"
      # Optional PEM SubjectPublicKeyInfo. When present, every SCT this log
      # returns is cryptographically verified (signature + matching log id)
      # before it is embedded. Strongly recommended.
      public_key: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
    - name: prod-log
      url: "https://ct.googleapis.com/logs/us1/argon2025h1"
      public_key_file: /etc/secsy-pki/ct/argon2025h1.pem
```

- `url` is the log's **base URL**; the `/ct/v1/add-pre-chain` path is appended
  automatically.
- Supplying a log's public key (inline `public_key` or `public_key_file`) enables
  **SCT signature verification**: a returned SCT is only embedded if its
  signature validates against the log key and its log id matches. Without a key,
  SCTs are accepted on count alone — acceptable for a trusted internal test log,
  not for production.
- Supported log key/signature algorithms: ECDSA-P256 and RSA, both with SHA-256
  (the algorithms real CT logs use).

## Enabling CT on a profile

Add a `ct` block to any custom profile:

```yaml
profiles:
  - name: server-ct
    description: "TLS server certificate with Certificate Transparency"
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth]
    default_validity_days: 90
    ct:
      enabled: true
      logs: [test-log, prod-log]   # empty = submit to every registered log
      min_scts: 2                  # minimum SCTs required (default: 1)
      fail_open: false             # see failure modes below
      timeout_seconds: 5           # per-log attempt timeout
      retries: 2                   # extra attempts per log after the first
```

A profile that references an unknown log name, or enables CT when no logs are
configured, is rejected at startup — misconfiguration fails loudly rather than
silently issuing without CT.

Submissions to the selected logs run **concurrently**; each log gets up to
`retries + 1` attempts, each bounded by `timeout_seconds`.

### Failure modes

When fewer than `min_scts` usable SCTs are obtained (logs down, timing out, or
returning SCTs that fail verification):

| `fail_open` | Behaviour |
|-------------|-----------|
| `false` (default, **fail-closed**) | Issuance is **rejected**. Use when a certificate is worthless to you without CT (public TLS). |
| `true` (**fail-open**) | Issuance **proceeds**, embedding whatever SCTs were obtained (possibly none). The certificate is marked `failed_open`. Use when availability matters more than guaranteed CT logging. |

Operator misconfiguration (an unknown log name) is always fatal regardless of
`fail_open`; the flag only covers log **availability**.

## Observing CT status

- **API.** `POST /api/ca/{id}/issue` and `/renew` responses include a `ct`
  object (`enabled`, `embedded`, `sct_count`, `status`, per-log `logs`). Stored
  certificates (`GET /api/ca/{id}/certificates`) carry `ct_status`
  (`none` / `submitted` / `failed_open`), `sct_count`, and `ct_logs`. See the
  [OpenAPI spec](../server/internal/handlers/openapi.yaml).
- **Console.** The certificate list shows a **CT** column: an `N SCT` badge for
  logged certificates (hover for the log names) or a `fail-open` badge, and the
  issuance form reports the CT outcome.
- **Audit log.** `cert.issue` / `cert.renew` events record a CT summary in their
  detail (e.g. `ct=enabled scts=2 logs=2/2`).

You can confirm SCTs in an issued certificate with OpenSSL:

```console
$ openssl x509 -in cert.pem -noout -text | grep -A3 "CT Precertificate SCTs"
```

## Testing with a mock or test log

The implementation is exercised end-to-end without a real log:

- `server/internal/ct` unit tests stand up an in-process RFC 6962 log
  (`httptest`) that signs SCTs with an ECDSA key, then verify submission,
  multi-log fan-out, retries, SCT **embedding**, relying-party **verification**
  (reconstructing the TBS from the final certificate), and rejection of
  mismatched-key SCTs.
- `server/internal/ca` issuance tests (build tag `sqlite`) issue real
  certificates under a CT-enabled profile against mock logs and assert SCT
  embedding, database round-trip of CT status, and **policy enforcement**
  (fail-closed rejects when the log is down; fail-open proceeds and is marked
  `failed_open`).

Run them:

```console
$ cd server
$ go test ./internal/ct/...            # no HSM required
$ go test -tags sqlite ./internal/ca/ -run CT
```

To point at a real test log instead, register it under
`certificate_transparency.logs` with its public key and reference it from a
profile.

## Notes & limitations

- CT applies to the X.509 leaf issuance path (`/api/ca/{id}/issue`, `/renew`,
  and any profile-driven issuance such as ACME when the profile enables CT). It
  does not apply to CA certificates or SSH certificates.
- SCTs are embedded in the certificate (the RFC 6962 §3.3 X.509v3 extension
  method). The TLS and OCSP-stapling SCT delivery methods are not used.
- Precertificates are signed directly by the CA key; delegated *precertificate
  signing certificates* (`1.3.6.1.4.1.11129.2.4.4`) are not required.
