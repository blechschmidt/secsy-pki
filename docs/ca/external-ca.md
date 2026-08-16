# Externally-signed subordinate CA (offline / third-party root)

The common enterprise topology: the issuing CA's **private key lives in our
HSM**, but its **parent is external** — an air-gapped corporate root, or a
public/bridge CA operated by someone else. secsy-pki plays the subordinate:
it generates the key, emits a PKCS#10 CSR for the external parent to sign
out-of-band, then validates and installs the certificate that comes back.
From that point the CA issues, renews, revokes, and rotates subordinates
exactly like a locally rooted hierarchy — and its served chain continues past
the local hierarchy to the external trust anchor.

Only the CSR and certificates ever cross the trust boundary. No private key
material travels in either direction: the external parent never sees our key,
and we never hold theirs.

This complements [cross-signing](cross-signing.md): cross-signing re-certifies
an *existing* key under a second issuer we operate, whereas this flow creates a
*new* subordinate whose only issuer is a parent we do **not** operate.

---

## The flow

```
secsy-ca ca csr ─────▶ HSM key + PKCS#10 CSR          CA status: pending
                          │
                          │  (out-of-band ceremony: the offline root
                          │   signs the CSR — days may pass)
                          ▼
secsy-ca ca import-cert ◀─ signed certificate (+ chain)  CA status: active
                          │
                          ▼
        issue / renew / revoke / subordinate CAs / rotation as normal;
        /api/ca/{id}/chain serves ... → our CA cert → external parents → external root
```

1. **`ca csr`** generates the key inside the key provider and emits a CSR whose
   `extensionRequest` attribute carries the CA extensions a parent needs to
   honor: `basicConstraints` cA=TRUE (with the requested path length) and
   `keyUsage keyCertSign, cRLSign, digitalSignature`, both critical — the same
   extensions locally issued CA certificates carry. The CA record is persisted
   **pending**: the key and CSR survive the ceremony, the CSR can be
   re-downloaded at any time, and the CA can issue nothing until activated.
2. The external parent signs the CSR with its own tooling (openssl, a
   commercial CA portal, a ceremony script). What it issues is authoritative —
   it may rewrite the DN or tighten the path length.
3. **`ca import-cert`** validates the result fail-closed (below), stores the
   certificate and the optional external chain, and flips the CA to **active**.

PQC (ML-DSA) key types are rejected for this flow: the external parent signs
with classical tooling. Use a classical key type (`ecdsa-p*`, `rsa-*`,
`ed25519`).

## Import validation

Hard failures (nothing is installed):

| Check | Why |
|---|---|
| Public key ≠ the CA's key **as held by the provider** | the certificate must certify exactly our HSM key (the HSM is authoritative, not the DB record) |
| No `basicConstraints`, or cA=FALSE | not a CA certificate; issuance under it would never verify |
| `keyUsage` present but missing `keyCertSign` | certificates signed by this CA would be rejected by verifiers |
| Expired / not yet valid / inverted validity | a dead-on-arrival CA |
| Self-signed (issuer = subject) | that is a root, not an externally signed subordinate (`init-root` creates roots) |
| Chain supplied but the certificate does not verify against it | never publish a bundle relying parties cannot build a path through |

Warnings (imported anyway; review them):

- `keyUsage` missing entirely, or missing `cRLSign` / `digitalSignature`
  (CRLs / direct OCSP signing will not verify),
- certificate subject differs from the CSR subject (parent rewrote the DN),
- issued path-length constraint differs from the requested one,
- no external chain supplied (the served chain stops at our certificate),
- chain supplied without a self-signed anchor.

The certificate PEM may be a bundle — certificates after the first are treated
as chain material, as commercial CAs commonly return them.

## Chain serving

`GET /api/ca/{id}/chain` (and everything built on `CombinedChainPEM`: rotation
overlap bundles, cross-sign chains, publishing) walks the local hierarchy as
usual and then, when the topmost local CA carries an imported external chain,
appends it — so a leaf's chain reads
`leaf ◀ child intermediate ◀ imported CA ◀ external parents ◀ external root`,
and `openssl verify -CAfile external-root.pem -untrusted chain.pem leaf.pem`
succeeds with **only** the external root as trust anchor.

## Renewal and rotation

- **Renewal (same key):** the stored CSR never expires. Re-download it
  (`ca csr -ca <ref>`), have the external parent sign it again, and install
  with `ca import-cert -replace`. Existing leaves keep validating — the key,
  DN, and Subject Key Identifier are unchanged. `-replace` also lets you add
  the external chain after a chainless first import. A previously imported
  chain is retained when a replace-import supplies none.
- **Rotation (new key):** `rotate-intermediate` refuses the imported CA itself
  (its parent's key is not ours to sign with) and points to the out-of-band
  path: fresh `ca csr` under a new label, external signature, import, then
  redirect issuance. Child intermediates *below* the imported CA rotate
  normally — the imported CA signs their successors on the HSM.

## CLI

```
# 1. Generate the HSM-backed key + CSR (CA is created pending)
secsy-ca ca csr -label corp-issuing -key-type ecdsa-p384 \
    -cn "Corp Issuing CA" -o "Corp" -path-len 1 -out corp-issuing.csr.pem

# (re-download the CSR later)
secsy-ca ca csr -ca corp-issuing -out corp-issuing.csr.pem

# 2. ... external signing ceremony happens out-of-band ...

# 3. Validate + install the certificate and the external chain
secsy-ca ca import-cert -ca corp-issuing -cert signed.pem \
    -chain external-chain.pem -chain-out served-chain.pem

# 4. Business as usual
secsy-ca issue -ca corp-issuing -profile server -csr leaf.csr.pem
```

## REST API

| Endpoint | Purpose |
|---|---|
| `POST /api/ca/csr` | generate key + CSR (step-up gated, `ca:manage`) |
| `GET /api/ca/{id}/csr` | re-download the stored CSR (tenant-scoped read) |
| `POST /api/ca/{id}/import-cert` | validate + install (step-up gated, `ca:manage`); `replace` for renewal |
| `GET /api/ca/{id}/chain` | public combined chain, now reaching the external root |

The console's **Authorities** view has full parity: an *External subordinate CA
(CSR)* panel, the pending CA visible with *CSR* / *Import cert* actions, and a
warning banner surfacing import findings.

## Audit

`ca.csr` records the key generation + CSR emission; `ca.import_cert` records
the validated install (subject, serial, and any warnings in the detail).
Denied and failed attempts are recorded with `denied`/`error` results, as for
the other CA lifecycle operations.

## Testing

`internal/ca/external_test.go` covers the CSR attributes and the full
validation matrix (software provider). `internal/ca/external_openssl_test.go`
is the acceptance test: **openssl plays the offline corporate root** — it
signs the HSM-backed CSR out-of-band (SoftHSM on the `pkcs11` leg), the
certificate + root are imported, and leaves issued by the imported CA, by a
child intermediate, and by a rotated child key must all pass
`openssl verify` against the external root alone. The console e2e
(`internal/e2e/console_test.go`, `ExternalCAFlow`) drives the same flow
through the REST surface the console uses.
