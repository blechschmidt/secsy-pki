# Keyless software signing from GitHub Actions through OIDC

Sign release artifacts from a GitHub Actions pipeline **without storing any
long-lived credential in the repository**. The job proves its identity with a
short-lived GitHub OIDC token; Secsy PKI verifies it, maps the workflow identity
to the least-privilege `signer` role, and returns an **HSM-backed CMS/PKCS#7
detached signature** with an **RFC 3161 timestamp**. The signing key never leaves
the HSM.

This is the same "workload-identity federation" pattern as PyPI/npm trusted
publishing or cosign keyless — here the trust anchor is *your* PKI.

| File | Purpose |
|------|---------|
| [`config.yaml`](config.yaml) | Server: GitHub OIDC verifier + `signer` role mapping + HSM signing service + TSA |
| [`github-workflow.yml`](github-workflow.yml) | Drop-in `.github/workflows/sign-release.yml` |
| [`verify-signature.sh`](verify-signature.sh) | Downstream `openssl cms` verification (no server needed) |

Reference: [`docs/artifact-signing.md`](../../docs/artifact-signing.md),
[`docs/authentication.md`](../../docs/authentication.md).

---

## How the trust flows

```
GitHub Actions job (id-token: write)
   │  core.getIDToken("secsy-pki-signing")   ← short-lived JWT, audience-scoped
   ▼
POST /api/sign   Authorization: Bearer <github-oidc-jwt>
   │
   ├─ Secsy verifies the JWT against GitHub's JWKS (issuer, signature, expiry, aud)
   ├─ claims.sub = "repo:example-org/example-repo:environment:release"
   ├─ rbac.subjects maps that sub → [signer]  (grants ONLY artifact:sign)
   └─ signs digest on the HSM (code-signing key) + RFC 3161 countersignature
   ▼
{ "signature": "<base64 DER>", "signer_certificate": "...", "timestamped": true }
```

Two independent controls make this safe: GitHub's IdP asserts *which workflow*
is calling (the `sub` claim), and the audience (`aud == client_id`) ensures a
token minted for some other service can't be replayed here.

## The one thing to get right: a **stable** `sub` claim

Role assignment is an **exact match** on the OIDC `sub` claim. GitHub's default
`sub` embeds the git ref — `repo:OWNER/REPO:ref:refs/tags/v1.2.3` — which changes
on every release and can't be pinned in config.

**Use a GitHub Environment.** When a job runs in an environment, `sub` becomes:

```
repo:OWNER/REPO:environment:release
```

stable across every tag and branch. The example workflow declares
`environment: release`; create it under **Settings → Environments** and pin that
exact string in `rbac.subjects`. As a bonus you get environment protection rules
(required reviewers, tag restrictions) gating who can sign.

> Prefer even tighter identity? GitHub also supports customizing the subject
> claim (`repository_id`, `job_workflow_ref`, …) per repo via the API. The
> environment approach needs no API calls and is enough for most teams.

## 1. Provision the signing material (one time, offline)

On an operator host that can reach the HSM:

```console
# A CA to issue the code-signing certificate under (skip if you already have one).
$ secsy-ca -config config.yaml init-root -cn "Example Root" -label "Example Root"

# Generate the code-signing key IN the HSM and issue its certificate under the
# lint-gated code-signing profile (EKU id-kp-codeSigning).
$ secsy-ca -config config.yaml signing-key -ca "Example Root" -label codesign-release \
      -cn "Release Signing" -o "Example Corp" -chain -out /etc/secsy/codesign.pem

# The RSA TSA key for the RFC 3161 countersignature.
$ secsy-ca -config config.yaml tsa-key -ca "Example Root" -label tsa-signer \
      -cn "Example TSA" -out /etc/secsy/tsa.pem
```

## 2. Configure and run the server

Edit [`config.yaml`](config.yaml):

- `oidc.client_id` — the **audience** your workflow requests (here
  `secsy-pki-signing`). It just has to match on both sides.
- `rbac.subjects` — replace `example-org/example-repo` with your repo, keep the
  `:environment:release` suffix.
- Point `signing.signers[].certificate_file` / `tsa.certificate_file` at the
  files written in step 1.

```console
$ secsy-pki-server -config config.yaml
```

The server discovers GitHub's OIDC metadata at
`https://token.actions.githubusercontent.com/.well-known/openid-configuration` on
startup, so it must have outbound network access to GitHub.

## 3. Add the workflow

Copy [`github-workflow.yml`](github-workflow.yml) to
`.github/workflows/sign-release.yml`, set `SECSY_URL` / `SECSY_AUDIENCE`, and
create the `release` environment. On the next published release the job:

1. mints a GitHub OIDC token for the `secsy-pki-signing` audience;
2. hashes the artifact and calls `POST /api/sign` with `{"signer":"release","digest":"…"}`;
3. saves `<artifact>.p7s` (detached CMS, DER) and the signer certificate, and
   attaches them to the release.

Signing **by digest** means the artifact bytes never leave the runner — good for
multi-GB images (the API caps request bodies at 8 MiB regardless).

**CAdES level (optional).** Every signature is at least CAdES-B. If you provision
the [built-in TSA](../../docs/timestamping.md) (`secsy-ca tsa-key` + `tsa.enabled`),
add `"level":"t"` to the request for an embedded RFC 3161 timestamp, or `"level":"lt"`
to additionally embed the chain's CRLs/OCSP for offline **long-term validation** —
so releases stay verifiable after the signer certificate expires. The response
reports the achieved `level`. See [CAdES baseline levels](../../docs/artifact-signing.md#cades-baseline-levels-b--t--lt).

## 4. Verify downstream (no server, no HSM)

Anyone with your **root CA** can verify, offline, with standard tooling:

```console
$ ./verify-signature.sh app-v1.2.3.tar.gz app-v1.2.3.tar.gz.p7s root.pem
OK: app-v1.2.3.tar.gz verifies against root.pem
```

`verify-signature.sh` wraps:

```console
$ openssl cms -verify -binary -inform DER -in app-v1.2.3.tar.gz.p7s \
      -content app-v1.2.3.tar.gz -CAfile root.pem -purpose any -out /dev/null
```

For the full check — including that the embedded timestamp verifies and the
signer has the code-signing shape — use the CLI (also HSM-free):

```console
$ secsy-ca verify-signature -sig app-v1.2.3.tar.gz.p7s -in app-v1.2.3.tar.gz \
      -ca-file root.pem -require-timestamp
```

Add `-require-level t` (or `lt`) to fail unless the signature actually reached that
[CAdES level](../../docs/artifact-signing.md#cades-baseline-levels-b--t--lt) — a
stronger, self-describing gate than `-require-timestamp` alone.

The **timestamp is why this keeps verifying after the signing certificate
expires** — the chain is validated at the token's genTime, not the wall clock.

## Security properties

- **No stored secret.** The credential is a per-run, minutes-long OIDC token.
  Nothing to leak, rotate, or exfiltrate from repo secrets.
- **Least privilege.** The `signer` role grants exactly `artifact:sign` (and
  reading its own audit entries) — **not** certificate issuance. A compromised
  pipeline can sign builds; it can never mint certificates. `signer` is a
  distinct role from `issuer` by design.
- **Auditable.** Every call writes an `artifact.sign` event (signer, artifact
  digest, whether a countersignature was embedded) to the tamper-evident log,
  and `POST /api/sign` is rate-limited + HSM-concurrency-guarded so a runaway
  matrix build can't starve the HSM.
- **Scoped to one workflow identity.** Only the exact `sub` in `rbac.subjects`
  is accepted; other repos/branches/environments resolve to zero roles and are
  rejected.

### Note: the machine-Bearer verifier is global

The top-level `oidc` block is the verifier for **all** `Authorization: Bearer`
machine callers, so pointing it at GitHub dedicates that path to GitHub OIDC. If
human operators also sign in to the console, configure their **corporate IdP**
separately under `auth.oidc.issuer_url` — that interactive-login provider is
independent of this machine-Bearer one (they may be different issuers). See
[`docs/authentication.md`](../../docs/authentication.md).

## Adapting to other CI systems

Any OIDC-issuing CI works the same way — point `oidc.issuer_url` at its issuer,
request a token with the matching audience, and map its `sub` in `rbac.subjects`:

| CI | Issuer | Typical `sub` |
|----|--------|---------------|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `repo:OWNER/REPO:environment:NAME` |
| GitLab CI | `https://gitlab.com` (or self-managed URL) | `project_path:GROUP/PROJECT:ref_type:branch:ref:main` |
| Buildkite | `https://agent.buildkite.com` | `organization:ORG:pipeline:PIPELINE:…` |

Only one machine-Bearer issuer is verified per deployment; run a dedicated
signing deployment (or use scoped [API tokens](../../docs/authentication.md#4-native-scoped-api-tokens-service-accounts))
if you must federate several at once.
