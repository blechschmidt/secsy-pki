# SSH certificate authority

secsy-pki includes an HSM-backed **OpenSSH certificate authority**: it signs
OpenSSH **user** and **host** certificates with CA keys held by the configured
key provider (PKCS#11 HSM, cloud KMS, or the software keystore), and publishes
revocations as OpenSSH **Key Revocation Lists (KRLs)** that `sshd` consumes
directly. The CA private key never leaves the backend — every signature is
produced by the device through `crypto.Signer`.

Why SSH certificates instead of raw `authorized_keys`:

- **One trust anchor instead of key sprawl.** Hosts trust the CA once
  (`TrustedUserCAKeys`); users and automation get short-lived certificates
  instead of long-lived keys copied to every server.
- **Short-lived, policy-shaped credentials.** Profiles pin certificate type,
  validity bounds, permitted principals, extensions, and critical options
  (e.g. `source-address`, `force-command`).
- **Real revocation.** Every certificate carries a store-allocated serial;
  revocations (by serial or by key ID) are served as a KRL over HTTP, the
  artifact `sshd`'s `RevokedKeys` option understands.
- **Enterprise controls.** Signing and revocation are RBAC- and tenant-gated
  exactly like X.509 issuance, and every operation lands in the tamper-evident
  audit log (`ssh.ca_init`, `ssh.sign`, `ssh.revoke`).

## Quick start (CLI)

```console
# 1. Create the CA — the key is generated inside the HSM.
$ secsy-ca ssh ca-init -label ops-ssh-ca -key-type ed25519 > ops-ssh-ca.pub

# 2. Sign a user's public key into a 12h certificate (user-default profile).
$ secsy-ca ssh sign-user -ca ops-ssh-ca -pub ~/.ssh/id_ed25519.pub \
    -key-id alice@corp -principals alice -out ~/.ssh/id_ed25519-cert.pub

# 3. Sign a host key into a host certificate (host-default profile, 90d).
$ secsy-ca ssh sign-host -ca ops-ssh-ca -pub /etc/ssh/ssh_host_ed25519_key.pub \
    -principals web1.example.com,web1 -out /etc/ssh/ssh_host_ed25519_key-cert.pub

# 4. Revoke a certificate and regenerate the KRL.
$ secsy-ca ssh revoke -ca ops-ssh-ca -serial 3 -reason "laptop stolen"
$ secsy-ca ssh krl -ca ops-ssh-ca -out /etc/ssh/ops-ssh-ca.krl

# Inventory and profiles.
$ secsy-ca ssh list -ca ops-ssh-ca
$ secsy-ca ssh profiles
```

`ssh-keygen -L -f id_ed25519-cert.pub` shows exactly what was signed;
`ssh-keygen -Q -f ops-ssh-ca.krl id_ed25519-cert.pub` checks a certificate
against the KRL — the same code path `sshd` uses.

## Deploying trust

**User certificates** — on every host that should accept them
(`/etc/ssh/sshd_config`):

```
TrustedUserCAKeys /etc/ssh/ops-ssh-ca.pub
RevokedKeys /etc/ssh/ops-ssh-ca.krl
```

Fetch both artifacts from the server (public endpoints, no credentials — like
CRL distribution):

```console
$ curl -o /etc/ssh/ops-ssh-ca.pub  https://pki.example.com/api/ssh/cas/<ca-id>/public
$ curl -o /etc/ssh/ops-ssh-ca.krl https://pki.example.com/api/ssh/cas/<ca-id>/krl
```

Refresh the KRL on a timer (cron/systemd) so revocations propagate; the KRL
header carries a monotonically increasing version (the revocation count) and a
generation timestamp.

**Host certificates** — clients pin the CA in `~/.ssh/known_hosts` (or a
global `ssh_known_hosts`):

```
@cert-authority * ssh-ed25519 AAAA... (the CA public key)
```

and each host presents its certificate (`/etc/ssh/sshd_config`):

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

## Signing profiles

A profile is the policy a certificate is signed under. Two built-ins exist:

| Profile | Type | Default / max validity | Notes |
|---|---|---|---|
| `user-default` | user | 12h / 30d | standard `permit-*` extension set; `source-address`, `force-command`, `verify-required` critical options permitted |
| `host-default` | host | 90d / 366d | no extensions or critical options (host certs carry none) |

Custom profiles are defined in config and overlay the built-ins by name:

```yaml
ssh:
  krl_comment: "corp ops CA"          # stamped into generated KRLs
  profiles:
    - name: ci-deploy
      description: CI deploy automation
      cert_type: user
      default_validity: 1h            # Go duration, or 30d / 12w
      max_validity: 24h               # longer requests are clamped
      allowed_principals: ["deploy-*"] # glob patterns; empty = any
      max_principals: 2
      default_extensions:             # applied when the request names none
        permit-pty: ""
      allowed_critical_options:       # request-supplied keys must be listed
        - source-address
    - name: prod-host
      cert_type: host
      default_validity: 90d
      max_validity: 366d
      allowed_principals: ["*.prod.example.com"]
```

Enforcement rules:

- Certificates **must name at least one principal** (a principal-less OpenSSH
  certificate is valid for *every* user/host). Opt out per profile with
  `allow_empty_principals: true` only if you understand the blast radius.
- A request's extensions/critical options **replace** the profile defaults but
  every key must be permitted (a default key or in the `allowed_*` list).
- Requested validity beyond `max_validity` is clamped (matching the X.509
  profile convention). `ValidAfter` is backdated 5 minutes for clock skew.
- Host certificates never carry extensions or critical options; requests that
  ask for them are refused.

## Serials and revocation

Serials are allocated from the CA's monotonic store counter (shared with the
X.509 issuance path, so serials are unique per CA regardless of certificate
kind) — this is what makes serial-based revocation trustworthy.

Revoke by **serial** (one certificate) or by **key ID** (every certificate
issued for an identity):

```console
$ secsy-ca ssh revoke -ca ops-ssh-ca -serial 42
$ secsy-ca ssh revoke -ca ops-ssh-ca -key-id alice@corp
```

The KRL is generated from the revocation store on demand — `secsy-ca ssh krl`
or `GET /api/ssh/cas/{id}/krl` — as a `KRL_SECTION_CERTIFICATES` section bound
to the CA public key (so revoked serials cannot collide with another CA's
serial space), with serial-list and key-ID subsections per OpenSSH's
`PROTOCOL.krl`. Interop is proven in tests against `ssh-keygen -Q`.

## REST API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/ssh/cas` | `ca:manage` (step-up capable) | initialize an SSH CA |
| `GET /api/ssh/profiles` | read role | effective signing profiles |
| `POST /api/ssh/cas/{id}/sign` | issue capability on the CA | sign a user/host certificate |
| `POST /api/ssh/cas/{id}/revoke` | issue capability (step-up capable) | revoke by serial or key ID |
| `GET /api/ssh/cas/{id}/certificates` | read role + tenant membership | inventory |
| `GET /api/ssh/cas/{id}/revocations` | read role + tenant membership | revocation records |
| `GET /api/ssh/cas/{id}/public` | public | CA public key (trust anchor) |
| `GET /api/ssh/cas/{id}/krl` | public | binary KRL for `RevokedKeys` |

Signing example:

```console
$ curl -u root:$PASSWORD -X POST https://pki.example.com/api/ssh/cas/$CA/sign \
    -H 'Content-Type: application/json' \
    -d '{"public_key":"ssh-ed25519 AAAA... alice@laptop",
         "cert_type":"user","principals":["alice"],"key_id":"alice@corp",
         "critical_options":{"source-address":"10.0.0.0/8"}}'
```

Authorization mirrors X.509 issuance: signing/revocation require the issue
capability within the CA's tenant (or a per-CA `SIGN_CERTIFICATE` grant);
cross-tenant access is denied. The full OpenAPI definition lives in the served
spec (`/openapi.yaml`, tag **SSH CA**).

> The legacy `/api/keys/{id}/sign` endpoint (restriction-set based, random
> serials, no revocation) remains for the original `secsy-ssh` client;
> new integrations should use `/api/ssh/*`, which adds store-allocated serials,
> profiles, and KRL revocation.

## Key types

`ed25519` (default), `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`.
Ed25519 requires an EdDSA-capable token (SoftHSM ≥ 2.4, YubiHSM 2); on HSMs
without it use `ecdsa-p256`. RSA CAs sign with `rsa-sha2-512` (never legacy
`ssh-rsa`/SHA-1). The SoftHSM suite exercises all three families end to end,
including `ssh-keygen` interop.

## Audit and metrics

Audit actions: `ssh.ca_init`, `ssh.sign` (serial, type, key ID, principals,
profile in the detail), `ssh.revoke` (target + idempotence). CLI operations
are recorded with actor `cli`.

Metrics: `secsy_ssh_certificates_total{type,result}`,
`secsy_ssh_revocations_total{result}`, `secsy_ssh_krl_requests_total{result}`,
plus the shared HSM operation/duration metrics from the key-provider layer.
