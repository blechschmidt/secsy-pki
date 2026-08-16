# Secret & password encryption

*The HSM-backed encryption service that sits alongside the PKI.*

secsy-pki is not only a CA. The secret layer offers envelope encryption for
passwords and small secrets, M-of-N escrow and recovery, format-preserving
tokenization, named signing keys, and a stateless crypto service — all rooted
in the same HSM-held key-encryption key.

| Guide | Covers |
|-------|--------|
| [**Password / secret encryption**](password-encryption.md) | HSM-backed envelope encryption for passwords and small secrets (`secsy-secret`, `/api/secret/*`), plus the stateless **crypto service** (data key, keyed HMAC, CSPRNG random) exposed over REST/gRPC/CLI and the console Secrets page |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
