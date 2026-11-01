# SSH PKI — an HSM-backed OpenSSH certificate authority

Replace long-lived `authorized_keys` and `known_hosts` sprawl with **one trust
anchor**. Hosts trust the CA once; users and automation present short-lived,
policy-shaped certificates; revocations propagate as OpenSSH KRLs. The CA private
key is generated in, and every signature produced by, the HSM — it never touches
disk.

This example ships:

| File | Purpose |
|------|---------|
| [`config.yaml`](config.yaml) | Server config with three SSH signing profiles (`operator`, `ci-deploy`, `prod-host`) |
| [`sshd_config.d/50-secsy-trusted-user-ca.conf`](sshd_config.d/50-secsy-trusted-user-ca.conf) | Server-side: trust the CA for **user** logins + honor the KRL |
| [`sshd_config.d/60-secsy-host-cert.conf`](sshd_config.d/60-secsy-host-cert.conf) | Server-side: present this host's **host certificate** |
| [`ssh_known_hosts.example`](ssh_known_hosts.example) | Client-side: `@cert-authority` trust for host certificates |
| [`scripts/refresh-krl.sh`](scripts/refresh-krl.sh) | Pull the current KRL from the server (for cron/systemd) |
| [`scripts/enroll-host.sh`](scripts/enroll-host.sh) | Sign a host's key into a host certificate |
| [`systemd/`](systemd) | Timer + service to refresh the KRL periodically |

Full reference: [`docs/ca/ssh-ca.md`](../../docs/ca/ssh-ca.md).

---

## 1. Start the server

```console
$ cp examples/ssh-pki/config.yaml /etc/secsy-pki/config.yaml
# edit pkcs11.module_path / token_label / pin and the profile globs for your org
$ secsy-pki-server -config /etc/secsy-pki/config.yaml
```

## 2. Create the CA (key generated inside the HSM)

`ca-init` writes the CA public key to stdout and prints its id + ready-to-paste
trust lines to stderr. Keep the **id** — the public endpoints are addressed by it.

```console
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh ca-init \
    -label ops-ssh-ca -key-type ed25519 > ops-ssh-ca.pub
SSH CA "ops-ssh-ca" created (id 7f3c…, key type ed25519)
Trust this CA for user certificates (sshd_config):
  TrustedUserCAKeys /etc/ssh/ops-ssh-ca.pub
Trust it for host certificates (known_hosts):
  @cert-authority * ssh-ed25519 AAAA…

$ secsy-ca -config /etc/secsy-pki/config.yaml ssh profiles   # confirm your profiles loaded
```

Optionally give the authority its own ceiling. `-max-validity` caps **every**
certificate this CA will ever sign — whichever profile asks, and over any
endpoint — so a profile added later cannot quietly widen it:

```console
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh ca-init \
    -label ops-ssh-ca -key-type ed25519 -max-validity 24h > ops-ssh-ca.pub

# Change or remove it at any time (the store holds it; no restart):
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh ca-max-validity -ca ops-ssh-ca -set 12h
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh ca-max-validity -ca ops-ssh-ca
12h0m0s
```

> Ed25519 needs an EdDSA-capable token (SoftHSM ≥ 2.4, YubiHSM 2). On a token
> without it, use `-key-type ecdsa-p256`. RSA CAs sign with `rsa-sha2-512`, never
> legacy `ssh-rsa`/SHA-1.

## 3. Trust the CA on every host

Distribute the CA public key and drop the two `sshd_config` snippets in. The user
CA public key and KRL are served from **unauthenticated** endpoints (like CRL
distribution), so hosts can pull them without credentials:

```console
# On each host — replace <ca-id> with the id from step 2, pki.example.com with your server
$ curl -fsSo /etc/ssh/ops-ssh-ca.pub  https://pki.example.com/api/ssh/cas/<ca-id>/public
$ curl -fsSo /etc/ssh/ops-ssh-ca.krl  https://pki.example.com/api/ssh/cas/<ca-id>/krl
$ install -m0644 examples/ssh-pki/sshd_config.d/50-secsy-trusted-user-ca.conf /etc/ssh/sshd_config.d/
$ systemctl reload sshd
```

`50-secsy-trusted-user-ca.conf` sets `TrustedUserCAKeys` (accept user certs signed
by this CA) and `RevokedKeys` (honor the KRL). Keep the KRL fresh with the
[systemd timer](systemd) so revocations take effect — the KRL header carries a
monotonically increasing version (the revocation count).

## 4. Issue a user certificate

```console
# 8-hour interactive operator cert for alice, principal "alice"
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh sign-user \
    -ca ops-ssh-ca -profile operator \
    -pub ~alice/.ssh/id_ed25519.pub -key-id alice@corp -principals alice \
    -out ~alice/.ssh/id_ed25519-cert.pub

# 15-minute CI deploy cert, locked to the runner's egress CIDR
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh sign-user \
    -ca ops-ssh-ca -profile ci-deploy \
    -pub deploy_ed25519.pub -key-id "deploy@$GITHUB_RUN_ID" -principals deploy-web \
    -option source-address=203.0.113.0/24 \
    -out deploy_ed25519-cert.pub

# Inspect exactly what was signed (same parser sshd uses)
$ ssh-keygen -L -f ~alice/.ssh/id_ed25519-cert.pub
```

The client just needs the private key and the `*-cert.pub` beside it; `ssh` sends
the certificate automatically. Nothing is copied into `authorized_keys`.

## 5. Issue host certificates (so clients stop trusting-on-first-use)

Run [`scripts/enroll-host.sh`](scripts/enroll-host.sh) on the server operator's
side for each host, then install `60-secsy-host-cert.conf` on the host:

```console
$ examples/ssh-pki/scripts/enroll-host.sh ops-ssh-ca web1 web1.prod.example.com,web1
# copies ssh_host_ed25519_key-cert.pub to the host; then on the host:
$ install -m0644 examples/ssh-pki/sshd_config.d/60-secsy-host-cert.conf /etc/ssh/sshd_config.d/
$ systemctl reload sshd
```

Clients trust host certificates by pinning the CA once in `known_hosts` — see
[`ssh_known_hosts.example`](ssh_known_hosts.example):

```
@cert-authority *.prod.example.com ssh-ed25519 AAAA…   # the CA public key from step 2
```

## 6. Revoke

Revoke one certificate by **serial**, or every certificate issued for an identity
by **key ID**, then regenerate and republish the KRL:

```console
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh revoke -ca ops-ssh-ca -serial 42 -reason "laptop stolen"
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh revoke -ca ops-ssh-ca -key-id alice@corp

# Hosts pull the refreshed KRL on their timer; to verify locally:
$ secsy-ca -config /etc/secsy-pki/config.yaml ssh krl -ca ops-ssh-ca -out ops-ssh-ca.krl
$ ssh-keygen -Q -f ops-ssh-ca.krl ~alice/.ssh/id_ed25519-cert.pub    # "... is revoked"
```

## Signing profiles in this example

| Profile | Type | Default / max validity | Principals | Notes |
|---------|------|------------------------|------------|-------|
| `operator` | user | 8h / 24h | ≤ 4, any | `permit-pty`, `permit-user-rc`; may pin `source-address` |
| `ci-deploy` | user | 15m / 1h | ≤ 1, `deploy-*` | no PTY; `source-address` / `force-command` allowed |
| `prod-host` | host | 90d / 366d | `*.prod.example.com` | host certs carry no extensions |

Built-in `user-default` (12h) and `host-default` (90d) remain available if a
request names no `-profile`. Requests over `max_validity` are clamped — and so
is anything over the **CA's own ceiling** (`ssh ca-max-validity`), which bounds
every profile in the table above, including their defaults;
certificates must name at least one principal (a principal-less OpenSSH cert is
valid for *everyone* — opt out only via `allow_empty_principals` if you truly
mean it).

## Limits a profile cannot express

A profile fixes a *shape* — these principals, that ceiling, those extensions.
What it cannot say is "never these principals, on any profile", "force-command
is not negotiable", or "a user certificate only for a FIDO-resident key". Those
are [CEL signing rules](../../docs/signing/signing-restrictions.md), evaluated
inside the SSH authority — so they bind on `POST /api/ssh/cas/{id}/sign`,
`secsy-ca ssh sign-user` and the legacy `/api/keys/{id}/sign` alike:

```console
# No certificate for a shared privileged account, on any profile, by anyone.
secsy-ca issuance-policy add -kind signing -name no-privileged-principals     -operations ssh-certificate     -expr 'signing.ssh.principals.filter(p, p.lowerAscii() in ["root", "admin"])
             .map(p, "principal " + p + " is a shared privileged account; use a named account and sudo")'

# A user certificate only for a hardware-resident key (ssh-keygen -t ed25519-sk).
secsy-ca issuance-policy add -kind signing -name ssh-keys-must-be-fido-resident     -operations ssh-certificate -disabled     -expr 'signing.ssh.cert_type == "host" || signing.ssh.public_key.hardware_backed'     -message 'a user SSH certificate is only signed for a FIDO-resident key (ssh-keygen -t ed25519-sk)'
```

The facts a rule sees come from the **resolved** certificate — profile defaults
applied, the CA's ceiling applied — so a rule about a lifetime cannot be fooled
by asking for more than the CA will grant. Write a rule `-disabled` (as the
second one above is) and dry-run it with
`secsy-ca issuance-policy test -kind signing`: a rule is fail-closed, so a wrong
one refuses every certificate in its scope.

## Automating issuance

- **Interactive users:** the [`secsy-ssh`](../../README.md#secsy-ssh-ssh-client-wrapper)
  client wraps OIDC login → sign → connect, caching the cert until it expires.
- **Hosts & agents:** call `POST /api/ssh/cas/{id}/sign` from config management,
  or run the [host agent](../../docs/protocols/agent.md) for unattended renewal.
- The KRL/public endpoints are safe to put behind a CDN; keep `rate_limit`
  enabled if they face untrusted networks.

## Production checklist

- Replace `root_user.password`; prefer OIDC/API-token operators and set
  `policy.allow_root_basic_auth: false`.
- Source the HSM PIN from a secret, not inline `pkcs11.pin`
  ([`docs/hsm/configuration.md`](../../docs/hsm/configuration.md)).
- Give the CA a real serving-TLS certificate (or `server.tls.self_issue`).
- Ship the KRL-refresh [timer](systemd) to every host so revocations converge.
- Keep host and user certificate lifetimes short; short lifetimes are the point.
