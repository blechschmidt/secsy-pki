---
title: HSM-backed enterprise PKI
description: >-
  X.509 and SSH certificate authorities, automated enrollment, timestamping and
  secret encryption — with every private key generated inside the hardware.
hide:
  - navigation
  - toc
---

# Secsy PKI

<p class="secsy-tagline" markdown>
An **HSM-backed enterprise PKI**: X.509 and SSH certificate authorities,
automated enrollment, signing and timestamping services, and envelope-based
secret encryption — with every private key generated *inside* the hardware,
and never leaving it.
</p>

<p class="secsy-hero-actions" markdown>
[Deploy it](docs/hsm/configuration.md){ .md-button .md-button--primary }
[Documentation map](docs/README.md){ .md-button }
[Worked examples](examples/README.md){ .md-button }
</p>

---

<div class="grid cards" markdown>

-   :material-key-chain-variant:{ .lg .middle } &nbsp; **Keys never leave the hardware**

    ---

    One key-provider abstraction routes every signing operation to a PKCS#11
    HSM, a cloud KMS, Vault Transit — or SoftHSM for development. Keys are
    generated on the device, marked non-extractable, and can prove it: hardware
    attestation and a remotely verifiable audit log show a third party that a
    given key signed nothing beyond what was published.

    [:octicons-arrow-right-24: HSM & key management](docs/hsm/README.md)

-   :material-certificate-outline:{ .lg .middle } &nbsp; **The whole certificate lifecycle**

    ---

    Bootstrap root and intermediate CAs, issue from profiles, renew, revoke,
    and publish CRLs and OCSP — including delta CRLs, sharding, pre-signed
    responses and CDN offload. Rotate an intermediate with a dual-chain overlap,
    cross-sign for a bridge, or run a subordinate under a third-party root.

    [:octicons-arrow-right-24: Certificate authority](docs/ca/README.md)

-   :material-robot-outline:{ .lg .middle } &nbsp; **Enrollment that runs itself**

    ---

    ACME (RFC 8555) with ARI, profiles, STAR and every challenge type; SCEP,
    EST and CMP for devices and MDM; BRSKI zero-touch onboarding; Windows
    autoenrollment over MS-XCEP/MS-WSTEP; plus a host agent that renews and
    installs certificates on its own.

    [:octicons-arrow-right-24: Enrollment protocols](docs/protocols/README.md)

-   :material-shield-check-outline:{ .lg .middle } &nbsp; **Gates that fail closed**

    ---

    Nothing reaches the HSM before it passes: CA/Browser Forum linting, DNS CAA
    (with `accounturi`), name constraints and policy OIDs, weak- and
    compromised-key checks, Certificate Transparency with inclusion-proof
    monitoring — and a dry-run endpoint that reports the verdict without
    signing anything.

    [:octicons-arrow-right-24: Issuance policy & gates](docs/issuance/README.md)

-   :material-lock-outline:{ .lg .middle } &nbsp; **More than certificates**

    ---

    The same hardware backs envelope encryption for passwords and secrets — with
    M-of-N escrow, KEK rotation and format-preserving tokenization — plus code
    and artifact signing, an RFC 3161 timestamping authority, and long-term
    evidence records.

    [:octicons-arrow-right-24: Secrets](docs/secrets/README.md) &nbsp;·&nbsp;
    [:octicons-arrow-right-24: Signing](docs/signing/README.md)

-   :material-account-lock-outline:{ .lg .middle } &nbsp; **Built to be audited**

    ---

    A hash-chained, RFC 3161-anchored audit log; four-eyes approvals over
    sensitive operations; OIDC SSO, LDAP/AD, mTLS and WebAuthn step-up;
    multi-tenant isolation; FIPS 140-3 mode — and a CP/CPS with its controls
    mapped to the code that enforces them.

    [:octicons-arrow-right-24: Security & governance](docs/security/README.md)

</div>

## Start here

| If you want to… | Go to |
|-----------------|-------|
| **Copy a working setup** | [Worked examples](examples/README.md) — an [SSH PKI](examples/ssh-pki/README.md), [keyless signing from GitHub Actions](examples/github-oidc-signing/README.md), [ACME TLS automation](examples/acme-tls/README.md), a [private mTLS CA](examples/mtls-internal/README.md) |
| **Deploy for the first time** | [HSM configuration](docs/hsm/configuration.md) → [Certificate authority](docs/ca/overview.md) → [RBAC & audit](docs/security/rbac-and-audit.md) |
| **Move to production** | [Production HSM migration](docs/hsm/production-migration.md) → [Key ceremony & DR](docs/hsm/key-ceremony.md) → [Observability](docs/operations/observability.md) |
| **Run it on Kubernetes** | [Kubernetes deployment](docs/deployment/kubernetes.md) → [Multi-replica coordination](docs/deployment/high-availability.md) |
| **Operate a live deployment** | [Operator runbook](docs/operations/runbook.md) — keep it bookmarked |
| **Respond to a key compromise** | [Incident response: mass revocation](docs/operations/incident-response.md) |
| **Prepare for a WebTrust audit** | [Certificate Policy / CPS](docs/compliance/certificate-policy.md) · [control mapping](docs/compliance/compliance-mapping.md) |
| **Understand why it is built this way** | [Architecture](ARCHITECTURE.md) · [decision records](docs/adr/README.md) |

## The tools at a glance

| Binary | Purpose | Build |
|--------|---------|-------|
| `secsy-pki-server` | The HTTP server, web console, and API | `go build -tags sqlite -o secsy-pki-server ./cmd/server` |
| `secsy-ca` | CA setup and certificate lifecycle | `go build -tags sqlite -o secsy-ca ./cmd/secsy-ca` |
| `secsy-secret` | HSM-backed secret encryption | `go build -tags sqlite -o secsy-secret ./cmd/secsy-secret` |
| `secsy-agent` | Host auto-enrollment / renewal daemon | `go build -o secsy-agent ./cmd/secsy-agent` |
| `secsy-ssh` | OIDC SSH client wrapper | `go build -o secsy-ssh ./cmd/secsy-ssh` |
| `secsy-verify` | Offline HSM audit-log verifier | `go build -o secsy-verify ./cmd/verify` |

All CLIs accept `-config config.yaml` and share the server's configuration,
database and key provider. Run any command with `-h` for its flags.

!!! tip "Everything here is generated from the repository"

    These pages are the Markdown under [`docs/`](docs/README.md) in the
    repository, published unchanged. Every page has an **edit** link to its
    source; see [how the site is built](docs/development/documentation-site.md).
