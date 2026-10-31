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
#    -max-validity is optional; it caps every certificate this CA will ever sign.
$ secsy-ca ssh ca-init -label ops-ssh-ca -key-type ed25519 -max-validity 12h > ops-ssh-ca.pub

# 2. Sign a user's public key into a 12h certificate (user-default profile).
$ secsy-ca ssh sign-user -ca ops-ssh-ca -pub ~/.ssh/id_ed25519.pub \
    -key-id alice@corp -principals alice -out ~/.ssh/id_ed25519-cert.pub

# 3. Sign a host key into a host certificate (host-default profile, 90d).
$ secsy-ca ssh sign-host -ca ops-ssh-ca -pub /etc/ssh/ssh_host_ed25519_key.pub \
    -principals web1.example.com,web1 -out /etc/ssh/ssh_host_ed25519_key-cert.pub

# 4. Revoke a certificate and regenerate the KRL.
$ secsy-ca ssh revoke -ca ops-ssh-ca -serial 3 -reason "laptop stolen"
$ secsy-ca ssh krl -ca ops-ssh-ca -out /etc/ssh/ops-ssh-ca.krl

# Inventory, profiles, and the CA's signing ceiling.
$ secsy-ca ssh list -ca ops-ssh-ca
$ secsy-ca ssh profiles
$ secsy-ca ssh ca-max-validity -ca ops-ssh-ca
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

## The CA's maximum signing duration

A profile's `max_validity` bounds the certificates signed *under that profile*.
The **CA-level maximum** bounds every certificate signed by **that CA key**, no
matter which profile, which endpoint, or which client asked:

| | Profile `max_validity` | CA maximum |
|---|---|---|
| Scope | one named profile | one authority, all its profiles |
| Set in | config (`ssh.profiles`), restart/reload to change | the store — change it live from the CLI, the API, or the console |
| Binds the profile *default* | no (the default is already within it) | **yes** — a 90d profile default under a 12h CA is signed for 12h |
| Binds the legacy `/api/keys/{id}/sign` endpoint | no (that path uses restriction sets) | **yes** |

Use it when the authority itself has a policy — "the bastion CA never signs
anything that outlives a shift" — rather than when one certificate shape does.
Because it binds every path through the key, it is the control that cannot be
sidestepped by adding a profile or by loosening a restriction set.

```console
# Set it at creation, or any time afterwards (24h, 30d, 12w, or a Go duration).
$ secsy-ca ssh ca-init -label bastion-ca -max-validity 12h
$ secsy-ca ssh ca-max-validity -ca bastion-ca -set 8h
SSH CA "bastion-ca" now signs no certificate longer than 8h0m0s (was 12h0m0s).
  Existing certificates keep the lifetime they were signed with.

# Read it back (prints "none" when the CA is uncapped).
$ secsy-ca ssh ca-max-validity -ca bastion-ca
8h0m0s

# Remove it; the signing profiles become the only bound again.
$ secsy-ca ssh ca-max-validity -ca bastion-ca -set none
```

Clamping, not refusal: a request for more comes back shorter rather than
failing, so a ceiling can be tightened without breaking the clients that ask for
the old lifetime. The CLI, the API response (`clamped_by_ca_max_validity`,
`ca_max_validity_seconds`) and the console all say when a clamp happened, and
the `ssh.sign` audit event records it.

Over REST:

```console
$ curl -u root:$PASSWORD -X PUT https://pki.example.com/api/ssh/cas/$CA/max-validity \
    -H 'Content-Type: application/json' -d '{"max_validity_seconds":28800}'
{"ca_id":"…","label":"bastion-ca","max_validity_seconds":28800,"previous_max_validity_seconds":43200}
```

`GET /api/ssh/cas` reports each CA's ceiling as `max_ssh_validity_secs` (absent
or `0` = uncapped). In the console it is the **Maximum certificate lifetime
(this CA)** panel on the SSH CA view, and a field on the *Create SSH CA* form.

Two properties worth knowing:

- **Not retroactive.** Tightening the ceiling does not shorten certificates
  already signed — revoke them (and publish the KRL) if that is what you need.
- **Privilege-granting in one direction.** Raising or clearing a ceiling widens
  what the authority may sign, so the change takes `ca:manage` on the CA (not
  the issue capability), is step-up capable, and is audited as `ssh.ca_config`
  with the old and new value plus the direction of the change.

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
| `PUT /api/ssh/cas/{id}/max-validity` | `ca:manage` on the CA (step-up capable) | set/clear the CA's maximum certificate lifetime |
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
profile in the detail — plus the CA ceiling when one clamped the lifetime),
`ssh.revoke` (target + idempotence), and `ssh.ca_config` (a change to the CA's
maximum certificate lifetime: old value, new value, and whether the change
tightened, raised or cleared it). CLI operations are recorded with actor `cli`.

Metrics: `secsy_ssh_certificates_total{type,result}`,
`secsy_ssh_revocations_total{result}`, `secsy_ssh_krl_requests_total{result}`,
plus the shared HSM operation/duration metrics from the key-provider layer.
