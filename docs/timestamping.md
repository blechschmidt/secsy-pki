# Time-Stamping Authority (RFC 3161)

secsy-pki can act as an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)
Time-Stamp Authority (TSA): it answers a `TimeStampReq` (a hash of some data,
plus an optional nonce and policy) with a signed `TimeStampToken` that binds the
submitted hash to a trusted time. Tokens are signed by a dedicated **HSM-backed
TSA key** routed through the key provider — the private key never leaves the
device.

Typical uses: proving a document/artifact existed at a point in time, signing-
time attestations for code-signing and long-term signature validation (CAdES /
PAdES / XAdES time-stamps), and audit/compliance evidence.

## How it works

```
client ── TimeStampReq (application/timestamp-query) ──▶ POST /tsa
                                                          │
                                        parse + validate (hash alg, nonce, policy)
                                                          │
                                        build TSTInfo (imprint, genTime, serial)
                                                          │
                                        sign a CMS SignedData on the HSM
                                                          │
client ◀─ TimeStampResp (application/timestamp-reply) ────┘
```

A token is a CMS `SignedData` whose encapsulated content is a `TSTInfo`
(`id-ct-TSTInfo`). The single `SignerInfo` carries the ESS
`signing-certificate-v2` attribute (RFC 5035) binding the token to the TSA
certificate, so conforming verifiers — including `openssl ts -verify` — accept
it. The TSA certificate and its issuer chain are embedded only when the request
sets `certReq`.

Key properties:

- **HSM-backed signing.** Every token is signed through `crypto.Signer`; the TSA
  private key is non-extractable on a PKCS#11 token.
- **Nonce echo.** When a request carries a nonce it is copied verbatim into the
  token, defeating replay.
- **Message-imprint echo.** The exact hash algorithm and digest from the request
  are re-emitted in the token, so a verifier can confirm the token covers its
  data.
- **Random serials.** Each token gets a random 128-bit serial number.
- **Rejections are signed-free.** A malformed or unacceptable request yields a
  token-less `TimeStampResp` with the appropriate `PKIFailureInfo`
  (`badAlg`, `badDataFormat`, `unacceptedPolicy`, …), returned with HTTP 200.

The TSA key **must be RSA**: the CMS `SignedData` is signed with RSA PKCS#1 v1.5,
which is what the shared CMS builder produces and what maximizes verifier
interop.

## 1. Provision the TSA key and certificate

The `secsy-ca tsa-key` command generates (or reuses) a dedicated RSA key in the
key provider and issues a TSA certificate under an existing CA. The certificate
carries `id-kp-timeStamping` as its **sole, critical** extended key usage
(RFC 3161 §2.3) and `digitalSignature` key usage.

```console
$ secsy-ca -config config.yaml tsa-key \
    -ca my-intermediate \
    -label tsa-signer \
    -cn "Example TSA" \
    -validity-days 1185 \
    -out tsa.pem -chain
Provisioned TSA certificate: serial=… key=tsa-signer ca=my-intermediate not_after=…
```

Flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `-ca` | *(required)* | Issuing CA id or label |
| `-label` | `tsa` | Provider key label of the TSA signing key |
| `-key-type` | `rsa-2048` | `rsa-2048` or `rsa-4096` (RSA only) |
| `-cn` / `-o` | `Time-Stamp Authority` | Subject common name / organization |
| `-validity-days` | `1185` | Certificate lifetime (capped at the issuing CA's expiry) |
| `-out` | *(stdout)* | Where to write the certificate PEM |
| `-chain` | `false` | Append the issuing CA chain to the output |

Re-running with the same `-label` reuses the existing key and reissues the
certificate (rotate the cert without rotating the key). The command re-parses
and re-validates the issued certificate before writing it, so a bad build fails
loudly at provisioning time.

## 2. Enable the endpoint

Add a `tsa` block to `config.yaml`:

```yaml
tsa:
  enabled: true
  path: /tsa                       # URL the endpoint mounts under
  key_label: tsa-signer            # provider label of the (RSA) TSA key
  certificate_file: /etc/secsy/tsa.pem   # written by `secsy-ca tsa-key`
  ca_label: my-intermediate        # issuer chain source (when the file is leaf-only)
  policy_oid: 1.3.6.1.4.1.99999.1.1  # your owned TSA policy OID
  accuracy_seconds: 1              # genTime accuracy bound (omit block for none)
  accuracy_millis: 0
  accuracy_micros: 0
  ordering: false                  # assert strict time ordering of tokens
  signature_digest: sha256         # CMS signature hash (sha256|sha384|sha512)
  accepted_hashes: [sha256, sha384, sha512]  # message-imprint algs (sha1 opt-in)
  include_tsa_name: false          # embed the signer subject as the tsa GeneralName
```

Notes:

- `certificate_file` may contain just the TSA leaf (the chain is then loaded from
  `ca_id`/`ca_label`) or the full chain (leaf first).
- `policy_oid` defaults to a built-in *example* OID (`2.999.1.1`); set an owned
  OID in production. If a request names a policy, the TSA asserts it only if it
  matches, else rejects with `unacceptedPolicy`.
- `accepted_hashes` defaults to SHA-256/384/512. SHA-1 must be listed explicitly
  to be accepted.
- The endpoint is **anonymous and public** (like OCSP/CRL). It is subject to the
  [rate limiting & HSM concurrency guard](rate-limiting.md); time-stamping is
  gated behind the concurrency guard because it signs on the HSM.

## 3. Request a time-stamp

Any RFC 3161 client works. With OpenSSL:

```console
# 1. Build a query over the data (SHA-256, ask for the TSA cert back).
$ openssl ts -query -data document.pdf -sha256 -cert -out request.tsq

# 2. Submit it to the /tsa endpoint.
$ curl -s -H "Content-Type: application/timestamp-query" \
       --data-binary @request.tsq \
       https://pki.example.com/tsa -o response.tsr

# 3. Inspect the token.
$ openssl ts -reply -in response.tsr -text
Status: Granted.
Policy OID: 1.3.6.1.4.1.99999.1.1
Hash Algorithm: sha256
Serial number: 0x…
Time stamp: … GMT
Accuracy: 0x01 seconds, …

# 4. Verify it against the CA (the chain in tsa.pem or the issuing CA cert).
$ openssl ts -verify -data document.pdf -in response.tsr -CAfile tsa.pem
Verification: OK
```

## Audit & metrics

- Every request appends a `tsa.timestamp` event to the tamper-evident audit log
  (actor `tsa:anonymous`): `success` with the token serial on grant, `denied`
  with the failure reason on rejection.
- Prometheus counter `secsy_timestamp_requests_total{result}` partitions requests
  into `granted` | `rejected` | `error`. The HSM concurrency guard's
  `secsy_hsm_guard_*` metrics also cover the TSA path.

## Standards & interop

- RFC 3161 (Time-Stamp Protocol) and RFC 5816/5035 (ESS `signing-certificate-v2`).
- Transport per RFC 3161 §3.4: `POST /tsa` with `application/timestamp-query`
  request and `application/timestamp-reply` response.
- Verified against `openssl ts -verify` for both software- and SoftHSM-signed
  tokens (see `internal/tsa` tests).
