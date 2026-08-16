# TLS Delegated Credentials (RFC 9345)

A **delegated credential** (DC) is a short-lived credential that a TLS 1.3
end-entity certificate authorizes its key to sign. It lets you hand a front end
(a load balancer, an edge node, a third-party CDN) a credential valid for **at
most seven days** — without ever giving that front end the long-lived
certificate private key, and without a round trip to the CA to rotate it.

The mechanism has two halves, and secsy-pki implements both:

1. **Eligibility** — mint the end-entity certificate so relying parties will
   accept delegated credentials from it. This is a per-profile opt-in that stamps
   the RFC 9345 `DelegationUsage` extension on the leaf.
2. **Minting** — construct and sign a `DelegatedCredential` structure with the
   end-entity certificate's **private key**, and hand the wire form (plus the
   delegated key) to the TLS terminator.

> ## The operator holds the leaf key
>
> **A delegated credential is signed by the end-entity certificate's private
> key — not by any CA or HSM key.** This is the single most important thing to
> understand about minting.
>
> For ordinary CSR-based issuance the subscriber generates its own keypair and
> the CA only ever sees the public half. In that model **secsy-pki cannot mint a
> delegated credential for you**, because it does not have (and by design never
> had) the leaf private key — you do. Run the offline
> `secsy-ca delegated-credential mint` helper on the host that holds the key.
>
> The one case where the *system* can produce the leaf key is a certificate
> whose key it generated server-side: a [PKCS#12 export](../ca/pkcs12.md) whose subject
> key was **escrowed** under the M-of-N recovery policy
> ([key escrow](../secrets/password-encryption.md)). The `POST /api/ca/{id}/delegated-credential`
> endpoint serves exactly that case — it recovers the escrowed key through a
> recovery-agent quorum, signs, and immediately zeroizes the plaintext. It never
> retains the key, and it never accepts a plaintext private key over the wire.

## Making a certificate eligible

Set `delegation_usage: true` on an issuance profile. Every leaf issued under it
then carries the non-critical `id-ce-delegationUsage` extension
(OID `1.3.6.1.4.1.44363.44`, an ASN.1 `NULL`, DER `05 00`), which is the marker
relying parties look for before accepting a delegated credential.

A built-in profile is provided:

| Profile | Shape |
|---|---|
| `server-delegation` | `serverAuth`, `digitalSignature` + `keyEncipherment`, `DelegationUsage`, 397-day max |

Because eligibility is a profile property with no per-request knob, the operator
[console](../operations/web-console.md) surfaces it as a read-only indicator: selecting a
delegation-eligible profile on the **Issue** page flags it (`RFC 9345
delegated-credential eligible`) in the profile policy summary, so an operator
knows the resulting leaf can authorize delegated credentials before issuing it.

Or add your own:

```yaml
profiles:
  - name: edge-delegation
    key_usages: [digitalSignature]
    ext_key_usages: [serverAuth]
    default_validity_days: 7
    max_validity_days: 7
    delegation_usage: true
```

Two rules are enforced **fail-closed** at profile-install time
(`SetCustomProfiles`) so a misconfiguration surfaces at startup, not at issuance:

- **`digitalSignature` is required.** RFC 9345 §4.2 requires the authorizing
  certificate to carry the `digitalSignature` key usage; a `delegation_usage`
  profile without it is rejected.
- **OCSP Must-Staple is forbidden.** RFC 9345 §4.2 forbids combining the
  `DelegationUsage` marker with the RFC 7633
  [OCSP Must-Staple](../ca/overview.md#ocsp-must-staple-rfc-7633) TLS
  Feature. A profile that sets both `delegation_usage: true` **and** either
  `must_staple: true` or `allow_must_staple_override: true` is rejected — the
  latter too, so a per-request override can never sneak Must-Staple onto a
  delegation-eligible leaf.

The issuance path (`buildLeaf`, and the PQC/hybrid paths) also enforces the
mutual exclusion at signing time as defense-in-depth: even if a leaf somehow
reached issuance with both, it is refused before any HSM signature.

Because the eligibility short-circuits DC-key compromise to a seven-day window,
delegation-eligible leaves are typically issued **short-lived and rotated
often** — frequently via the PKCS#12 + escrow path so the system can mint DCs for
them without a human ceremony each time.

## Minting with the CLI (operator holds the leaf key)

The offline helper needs only the leaf certificate and its private key — no
server, no database, no HSM:

```console
$ secsy-ca delegated-credential mint \
    -cert leaf.crt -key leaf.key \
    -valid-for 24h \
    -dc-key-type ecdsa-p256 -dc-key-out dc.key \
    -out dc.bin
Minted server delegated credential
  Signing algorithm:      ecdsa_secp256r1_sha256
  Delegated key scheme:   ecdsa_secp256r1_sha256
  valid_time:             86400 s
  Not after:              2026-07-06T00:28:30Z
  Delegated private key:  dc.key (ecdsa-p256)
  Wire credential:        dc.bin
  Delegated credential (base64):
    AAFRgAQDAABbMFkw...
```

- `-dc-key-out` receives a freshly generated delegated **private** key (PKCS#8
  PEM) — install it on the TLS terminator alongside `dc.bin`. To reuse a key you
  already generated, pass its SPKI with `-dc-pub key.pub` instead (then no key is
  generated and you keep the private half yourself).
- `-dc-alg` / `-sign-alg` override the delegated-key scheme and the leaf-signing
  scheme; by default both are derived from the respective keys (RSA leaves sign
  with RSASSA-PSS, as RFC 9345 requires).
- `-client` mints a client delegated credential; the default is a server one.
- `-o json` emits the credential, key, and metadata as JSON for automation.

Verify a credential against its certificate at any time:

```console
$ secsy-ca delegated-credential verify -cert leaf.crt -dc dc.bin
Delegated credential is VALID (server)
  Signing algorithm:      ecdsa_secp256r1_sha256
  valid_time:             86400 s
  Not after:              2026-07-06T00:28:30Z
  Currently in window:    true
```

## Minting with the API (system recovers an escrowed leaf key)

`POST /api/ca/{id}/delegated-credential` mints a DC for a leaf that was exported
as a PKCS#12 **with escrow**. The caller presents the escrow envelope (returned
at export time) and a quorum of recovery-agent IDs; the server recovers the leaf
key on the HSM, signs, and zeroizes it. It requires the **issue** capability on
the CA's tenant, exactly like the PKCS#12 export it depends on.

```jsonc
POST /api/ca/{id}/delegated-credential
{
  "serial": "141086103…",          // the escrowed leaf's serial
  "escrow_envelope": { … },         // envelope returned by the PKCS#12 export
  "recovery_agents": ["ops-a", "ops-b"],   // a recovery quorum (M-of-N)
  "valid_for_seconds": 86400,
  "dc_key_type": "ecdsa-p256"       // omit dc_public_key to have one generated
}
```

Response (`201`):

```jsonc
{
  "serial": "141086103…",
  "delegated_credential": "AAFRgAQD…",       // base64 RFC 9345 wire form
  "valid_time_seconds": 86400,
  "not_after": "2026-07-06T00:28:30Z",
  "endpoint": "server",
  "algorithm": "ecdsa_secp256r1_sha256",
  "expected_cert_verify_algorithm": "ecdsa_secp256r1_sha256",
  "dc_public_key_pem": "-----BEGIN PUBLIC KEY-----\n…",
  "dc_private_key_pem": "-----BEGIN PRIVATE KEY-----\n…"   // present only when generated
}
```

A leaf that was not issued under a `delegation_usage` profile is refused (`400`),
as is any request whose recovery-agent set does not meet the escrow quorum
(`400`) or whose serial is unknown to the CA (`404`).

## `valid_time` and the seven-day cap

RFC 9345 measures a credential's `valid_time` in seconds **relative to the
certificate's `notBefore`**, and caps it at seven days (604800 s). secsy-pki
computes `valid_time = (now + valid_for) − notBefore` and refuses to mint if that
exceeds the cap. The practical consequence: **mint from a fresh certificate.** A
credential minted from a leaf whose `notBefore` is already several days old has
little (or negative) headroom under the cap; the error names this cause so you
re-issue a short-lived leaf and mint again. This is why the DC workflow pairs so
naturally with short-lived, frequently rotated leaves.

## Signature schemes

Both the leaf-signing algorithm and the delegated key's handshake algorithm are
TLS 1.3 `SignatureScheme` code points (RFC 8446). Supported: `ecdsa_secp256r1_sha256`,
`ecdsa_secp384r1_sha384`, `ecdsa_secp521r1_sha512`, `rsa_pss_rsae_sha256/384/512`,
and `ed25519`. RSA **must** use RSASSA-PSS — RFC 9345 forbids PKCS#1 v1.5 for
delegated-credential signatures, so the PKCS#1 v1.5 schemes are not offered.

## Audit & metrics

- `cert.delegated_credential` audit events record each mint (target = CA, detail
  = serial, endpoint, `valid_time`, schemes); a paired `secret.recover` event
  records the escrow-recovery ceremony behind the API path.
- The mint is counted in the `secsy_certificates_total{operation="delegated_credential"}`
  metric alongside the other issuance operations.

## Deployment

Install the wire credential (`dc.bin` / the `delegated_credential` field) and the
delegated private key into a TLS 1.3 terminator that supports RFC 9345 (recent
OpenSSL, BoringSSL, and rustls builds do). The terminator presents the delegated
credential in its `Certificate` message and uses the delegated key for the
handshake `CertificateVerify`; a supporting client validates it against the
end-entity certificate exactly as `secsy-ca delegated-credential verify` does.
Re-mint before `not_after` — and re-issue the eligible leaf on its own (shorter)
cadence.
```
