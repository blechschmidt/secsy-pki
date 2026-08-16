# Cross-signing and bridge-CA support

Cross-signing lets an intermediate (or root) public key be certified by **more
than one issuer**, so the same subordinate key holds several valid certificates
and a relying party can be served whichever chain terminates at a trust anchor it
already holds. This complements the [dual-chain rotation overlap](rotation.md)
work: rotation issues a second certificate for a *new* key under the *same*
parent, whereas cross-signing issues a second certificate for the *same* key
under a *different* issuer.

Two topologies motivate it:

- **Bridge CA** — two enterprise PKIs cross-certify each other's roots so leaves
  in one domain validate under the other's trust anchor.
- **Root transition** — a new root is cross-signed by the old root, so relying
  parties that still trust only the old root keep building a chain to the new one
  until they have distributed the new anchor.

---

## The model

A cross-signed certificate is a CA certificate that carries the subject's
**exact distinguished name and public key** (so it is a byte-compatible drop-in
issuer) but is signed by a **different** issuer's HSM-backed key. Because the DN
and Subject Public Key — and therefore the Subject Key Identifier — are
preserved, any leaf already signed by that subordinate key chains equally through
either certificate:

```
root1 ──issues──▶ intermediate ──▶ leaf        (native chain)
root2 ──cross-signs──▶ intermediate            (alternate chain, same key + DN)
```

The subordinate's private key is **never** involved — only its public half is
re-certified. The subject may be supplied three ways:

| Source        | Meaning                                                       |
|---------------|---------------------------------------------------------------|
| `local-ca`    | A CA already in this deployment (its HSM key is untouched)     |
| `certificate` | An externally supplied CA certificate (bridge import)         |
| `csr`         | An externally supplied CA CSR (self-signature verified)       |

Cross-sign relationships are persisted in the store and **tenant-scoped through
their issuer CA**; cross-signing a subject CA from another tenant is refused.
Every certificate for one subject key shares a Subject Key Identifier, which is
the join key for alternate-chain selection.

---

## CLI (`secsy-ca`)

| Command             | Purpose                                                              |
|---------------------|----------------------------------------------------------------------|
| `cross-sign`        | Cross-sign a subject key under an issuer CA's HSM key                 |
| `list-cross-signs`  | List a CA's cross-sign relationships, or its publishable alt-chains   |

Cross-sign a local intermediate under a second root:

```
secsy-ca cross-sign -issuer root2 -subject-ca issuing-ca \
    -out cross.pem -chain-out alt-chain.pem
```

Cross-sign an external root (bridge import) or a CSR:

```
secsy-ca cross-sign -issuer our-root -cert partner-root.pem -validity-days 730
secsy-ca cross-sign -issuer our-root -csr  partner.csr      -validity-days 730
```

Inspect the alternate chains available for a subject CA:

```
secsy-ca list-cross-signs -ca issuing-ca -chains
```

`-path-len` defaults to preserving the subject's constraint (`-2`); use `-1` for
unconstrained or a non-negative value to override. The cross-signed lifetime
reuses the subject's span when `-validity-days` is omitted (required for a CSR)
and is always clamped to the issuer's own expiry.

---

## HTTP API

Creating and listing cross-signs are management operations (`ca:manage`); the
alternate chains they publish are public, like the CRL/OCSP/chain endpoints.

```
POST /api/ca/{id}/cross-signs                      → CrossSignResult   (ca:manage)
GET  /api/ca/{id}/cross-signs                       → { cross_signs }   (ca:manage)
GET  /api/ca/{id}/chains                            → { chains }        (public)
GET  /api/ca/{id}/cross-signs/{csid}/chain          → application/x-pem-file (public)
```

`{id}` on `POST /cross-signs` is the **issuer** CA whose key signs. `GET /chains`
returns every publishable trust path for a **subject** CA — its native
parent-lineage chain plus one chain per active cross-sign — so an operator (or an
automated relying party) can select whichever chain it needs.

---

## Tests

`internal/ca/crosssign_openssl_test.go` is the acceptance test: it cross-signs one
intermediate under two independent roots, issues a leaf, and verifies **both**
resulting chains build and validate with Go's `x509` verifier and with
`openssl verify`. It runs against the software provider and SoftHSM (skipped when
SoftHSM is not configured). `internal/ca/crosssign_test.go` covers the external
certificate, CSR, and root-transition paths plus argument validation.
