# Credentials from files, not from the config

*Every password-shaped setting has a `_file` twin. Name the file; leave the
secret out of the configuration.*

A `config.yaml` is the wrong place for a password, and everything around it
treats it as such. It is rendered by a templating tool into a Kubernetes
ConfigMap, baked into a container image, committed to the repository that
describes the environment, copied into a chat window by an operator debugging a
rollout, and pasted wholesale into a bug report. None of those are things you
want to happen to a CA's HSM password.

Secret *delivery*, meanwhile, is already solved on every platform secsy-pki runs
on — and on all of them it is solved by presenting a **file**:

| Platform | What it gives you |
|----------|-------------------|
| Kubernetes | a projected `Secret` volume, e.g. `/etc/secsy/secrets/hsm-pin` |
| Docker / Compose / Swarm | `secrets:` mounted under `/run/secrets/` |
| systemd | `LoadCredential=` → `$CREDENTIALS_DIRECTORY/<name>` |
| Vault Agent / Secrets Store CSI | a templated file on a `tmpfs` |
| A bare host | root-owned `0600` under `/etc/secsy/` |

So secsy-pki accepts a **file name** anywhere it accepts a credential. Every
password-shaped setting has a sibling key with a `_file` suffix whose value is a
path; the file's contents are the credential.

```yaml
root_user:
  username: admin
  password_file: /run/secrets/root-password      # instead of password: …

yubihsm:
  connector_url: "http://127.0.0.1:12345"
  password_file: /run/secrets/yubihsm-password   # instead of password: …

pkcs11:
  module_path: /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
  token_label: YubiHSM
  pin_file: /run/secrets/hsm-pin                 # instead of pin: …

database:
  driver: postgres
  dsn_file: /run/secrets/database-dsn            # the DSN embeds the password
```

That configuration contains no secrets. It can be committed, templated, logged
and shared.

## The rules

They are the same for every key, so there is one thing to learn.

**Exactly one of the pair.** Setting both `password` and `password_file` is a
load error, not a precedence rule:

```
root_user.password and root_user.password_file are mutually exclusive: set exactly one
```

A deployment that disagrees with itself about where a CA's credential comes from
should be told, not quietly resolved in a direction nobody chose.

**The file's contents are the credential, minus one trailing line terminator.**
So `echo "hunter2" > pw` and `printf %s hunter2 > pw` both work, and `\r\n`
is handled for a file that travelled through Windows. *No other whitespace is
stripped* — a leading space or an interior tab may be part of the password, and
eating it silently would produce an authentication failure that no amount of
staring at the file would explain. An empty file is an error.

**The file must not be readable by group or other.** A credential that any local
account can read has not been externalized, only relocated:

```
root_user.password_file /etc/secsy/root.pw has insecure permissions 0640: a credential
file must not be readable by group or other (chmod 600 /etc/secsy/root.pw), or set
security.allow_insecure_secret_file_perms to override
```

`0640 root:secsy` is the common form of the mistake, not `0644`: it is what a
`chown` plus a default umask produces, and it looks deliberate.

**Container runtimes are why the override exists, and Kubernetes always needs
it.** A projected `Secret` is a per-pod `tmpfs` owned by **root**, so the only
way a non-root container (this image runs as uid 65532) can read a file on it is
through the group or other bits — which is precisely what the check rejects.
`defaultMode: 0400` does not help: it leaves the file root-owned and unreadable
by the process. Adding `fsGroup` makes it readable, but the kubelet does that by
chgrp'ing the volume and OR-ing in the group bits, so the file lands `0440`
root:65532 and the check still fails. Docker Swarm is the same story from the
other side: it mounts `/run/secrets/*` at `0444`.

So on an orchestrator, set the override and let the platform be the boundary:

```yaml
security:
  allow_insecure_secret_file_perms: true
```

That is not a weakening of the deployment, because the permission bits were
never what confined the credential there: the volume is a `tmpfs` created for
one pod, destroyed with it, and visible in no other mount namespace. The check
exists for the deployment shape where the bits *are* the boundary — a CA host
with `/etc/secsy/hsm.pin` on a shared filesystem — and there it should stay
fail-closed.

Where you control the file directly, it passes without an override:

| Delivery | Make it pass |
|----------|--------------|
| A bare host | `chown secsy:secsy /etc/secsy/hsm.pin && chmod 600` |
| systemd `LoadCredential=` | nothing — credentials land `0400` owned by the unit's user |
| Docker/Compose `secrets: { file: … }` | `chown 65532:65532 secrets/* && chmod 600` on the **host** file (the image runs as uid 65532, so a root-owned `0600` file passes the check and is then unreadable) |
| Vault Agent / CSI templating to a `tmpfs` | template with `perms = "0600"` and the agent running as the same user |

**Resolution happens once, at startup.** A path that does not exist, is a
directory, or fails the permission check is a *load* error: the server refuses
to start and `secsy-ca doctor` reports it, rather than binding its listener,
answering `/healthz` with 200, and failing every request that needs the
credential. (That failure mode is not hypothetical — it is why the PKCS#11 PIN
file grew a startup preflight.)

## Every key

| Credential | Inline key | File key |
|------------|-----------|----------|
| Bootstrap operator password | `root_user.password` | `root_user.password_file` |
| YubiHSM authentication-key password | `yubihsm.password` | `yubihsm.password_file` |
| PKCS#11 user PIN | `pkcs11.pin` | `pkcs11.pin_file` |
| PKCS#11 user PIN, per HA token | `pkcs11.tokens[].pin` | `pkcs11.tokens[].pin_file` |
| Database DSN (embeds the DB password) | `database.dsn` | `database.dsn_file` |
| Vault token (Transit backend) | `key_provider.kms.vault.token` | `key_provider.kms.vault.token_file` |
| Vault AppRole secret-id | `key_provider.kms.vault.secret_id` | `key_provider.kms.vault.secret_id_file` |
| Vault token / secret-id of a `vault` PIN source | `…pin_source.vault.token` / `.secret_id` | `…pin_source.vault.token_file` / `.secret_id_file` |
| OIDC confidential-client secret | `auth.oidc.client_secret` | `auth.oidc.client_secret_file` |
| LDAP bind-service-account password | `auth.ldap.bind_password` | `auth.ldap.bind_password_file` |
| ACME anti-replay nonce signing key | `acme.nonce_hmac_key` | `acme.nonce_hmac_key_file` |
| ACME External Account Binding keys | `acme.eab_hmac_keys` | `acme.eab_hmac_keys_file` |
| SMTP password (RFC 8823 email challenge) | `acme.email.smtp.password` | `acme.email.smtp.password_file` |
| IMAP password (RFC 8823 email challenge) | `acme.email.imap.password` | `acme.email.imap.password_file` |
| SCEP challenge password, per grant | `scep.grants[].challenge` | `scep.grants[].challenge_file` |
| EST Basic-auth password, per user | `est.users[].password` | `est.users[].password_file` |
| CMP PBM shared secret, per credential | `cmp.secrets[].secret` | `cmp.secrets[].secret_file` |
| S3 publish credentials | `publish.s3.secret_access_key` / `.session_token` | `publish.s3.secret_access_key_file` / `.session_token_file` |
| S3 backup credentials | `backup.s3.secret_access_key` / `.session_token` | `backup.s3.secret_access_key_file` / `.session_token_file` |

The AWS access-key **id**, the Vault **role-id**, LDAP's **bind DN**, SMTP's
**username** and an EAB **kid** are identifiers, not secrets. They have no file
form on purpose: a redacted config dump keeps them so it can still tell you
*which* principal was configured.

### The ones that are shorthand for a credential source

`pkcs11.pin_file` (per token set and per HA member) and
`auth.ldap.bind_password_file` expand to the equivalent
`file` entry of the richer [credential-source](../hsm/configuration.md#sourcing-the-user-pin-from-a-credential-store-pin_source)
machinery, which also reads from Vault, AWS Secrets Manager, Azure Key Vault,
GCP Secret Manager or an environment variable. These two lines are equivalent:

```yaml
pkcs11:
  pin_file: /run/secrets/hsm-pin
```

```yaml
pkcs11:
  pin_source:
    type: file
    file: { path: /run/secrets/hsm-pin }
```

The shorthand is the one to reach for; drop to the block when you need a
different backend, a non-default field name, or a per-file permission override.
Because they are the same thing, setting both is an error. The PIN is read
lazily at HSM login and never enters the loaded configuration at all — which is
why a dumped config shows the *source* for it and nothing else.

## From the environment instead

The credentials a container is most often handed can come from the environment
too, and each of those variables has a `_FILE` form:

| Credential | Variable | File variable |
|------------|----------|---------------|
| Bootstrap operator password | `SECSY_ROOT_PASSWORD` | `SECSY_ROOT_PASSWORD_FILE` |
| PKCS#11 user PIN | `SECSY_USER_PIN` | `SECSY_USER_PIN_FILE` |
| YubiHSM password | `SECSY_YUBIHSM_PASSWORD` | `SECSY_YUBIHSM_PASSWORD_FILE` |
| Database DSN | `SECSY_DATABASE_DSN` | `SECSY_DATABASE_DSN_FILE` |
| Vault token | `VAULT_TOKEN` | `VAULT_TOKEN_FILE` |
| Vault AppRole secret-id | `SECSY_VAULT_SECRET_ID` | `SECSY_VAULT_SECRET_ID_FILE` |

Prefer the `_FILE` form. An environment variable is not a good place for a
secret either: it is inherited by every child process, readable in `/proc` by
anything that can see the process, and printed by `docker inspect` and a crash
reporter alike.

**Precedence.** An environment variable supersedes the config file, as it does
for every other setting — and it supersedes it *wholesale*: setting
`SECSY_ROOT_PASSWORD` clears a `root_user.password_file` named in the config
rather than colliding with it, so the credential has exactly one origin no
matter how many layers of the deployment have an opinion. If both the direct and
the `_FILE` variable are set, the direct one wins.

**The PKCS#11 PIN is the one exception, deliberately.** It is the only
credential whose config form names a lazily-resolved *source* rather than a
value, and an explicitly configured source has always won over `SECSY_USER_PIN`.
So `pkcs11.pin_file` (and `pkcs11.pin_source`) is **not** cleared by
`SECSY_USER_PIN` — only by `SECSY_USER_PIN_FILE`, which names a source itself
and therefore replaces one. The alternative would be a trap: a production
`pin_file: /run/secrets/hsm-pin` silently defeated by a `SECSY_USER_PIN` left in
the environment — which is not hypothetical, because
`scripts/setup-softhsm.sh --export-env` exports it and CI exports it job-wide —
while the `pin_source` block that `pin_file` is shorthand for would have been
honoured. The shorthand behaves exactly like the block it expands to.

## What a dump shows

`Config.Redacted()` masks every credential the loaded configuration holds —
which is exactly the set listed above, because a credential delivered as a file
lives in the same field an inline one would. The file **paths** are deliberately
kept:

```yaml
root_user:
  username: admin
  password: '***redacted***'
  password_file: /run/secrets/root-password
database:
  driver: postgres
  dsn: postgres://secsy:***redacted***@db.example.com:5432/secsy_pki?sslmode=require
```

A path is not a secret, and a dump that still says where each credential came
from is what makes the redacted form useful for diagnosing a deployment. Note
the DSN: only the password component is masked, so the dump still answers "which
database is this replica talking to?".

## Worked example: Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: secsy-pki
stringData:
  root-password: "a-long-random-string"
  hsm-pin: "0001password"
  database-dsn: "postgres://secsy:pgpw@postgres:5432/secsy_pki?sslmode=require"
---
apiVersion: apps/v1
kind: Deployment
# …
spec:
  template:
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532                  # required: the volume is root-owned
      containers:
        - name: secsy-pki
          volumeMounts:
            - name: config
              mountPath: /etc/secsy
              readOnly: true
            - name: secrets
              mountPath: /etc/secsy/secrets
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: secsy-pki-config      # no secrets in here
        - name: secrets
          secret:
            secretName: secsy-pki
            defaultMode: 0440           # fsGroup makes it 0440 root:65532
```

```yaml
# the ConfigMap's config.yaml
security:
  # The projected Secret is a per-pod tmpfs; the group bit is how uid 65532
  # reads a root-owned volume, not an exposure. See above.
  allow_insecure_secret_file_perms: true
root_user:
  username: admin
  password_file: /etc/secsy/secrets/root-password
database:
  driver: postgres
  dsn_file: /etc/secsy/secrets/database-dsn
pkcs11:
  module_path: /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
  token_label: YubiHSM
  pin_file: /etc/secsy/secrets/hsm-pin
```

Rotating any of those is `kubectl apply` plus a restart — no config change, no
image rebuild. For the PKCS#11 PIN specifically, rotation does not even need the
restart: it is read at HSM login, so a new session pool picks up the new file.

## Worked example: Docker Compose

```yaml
services:
  secsy-pki:
    image: ghcr.io/blechschmidt/secsy-pki:latest-yubihsm
    environment:
      SECSY_ROOT_PASSWORD_FILE: /run/secrets/root_password
      SECSY_USER_PIN_FILE: /run/secrets/hsm_pin
    secrets: [root_password, hsm_pin]
    configs:
      - source: secsy_config
        target: /etc/secsy/config.yaml

secrets:
  root_password:
    file: ./secrets/root-password
  hsm_pin:
    file: ./secrets/hsm-pin
```

Compose (outside Swarm) bind-mounts a `file:`-backed secret with the host file's
own owner and mode, which is the one container case that can satisfy the check
outright — but both halves have to line up, because the container is uid 65532:

```sh
chown 65532:65532 secrets/root-password secrets/hsm-pin
chmod 600         secrets/root-password secrets/hsm-pin
```

Leave them root-owned and the server starts, reads nothing, and tells you so:
`permission denied`. Swarm-managed secrets arrive `0444` regardless and need
`security.allow_insecure_secret_file_perms: true`.

## Related

- [HSM / PKCS#11 configuration](../hsm/configuration.md) — the full `pin_source`
  machinery (Vault, AWS, Azure, GCP, env) that `pin_file` is shorthand for
- [Operator authentication](authentication.md) — the OIDC client secret and LDAP
  bind credential
- [Container deployment](../deployment/container.md) — the image's full
  environment surface
- [Kubernetes deployment](../deployment/kubernetes.md) — the Helm chart's secret
  wiring

---

↩ Back to [security & governance](README.md) · [documentation map](../README.md)
