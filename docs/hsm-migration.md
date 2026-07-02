# Production HSM migration: SoftHSM → real HSM

SoftHSM is a software PKCS#11 token — perfect for development, CI, and demos, but
it provides **no hardware protection**: its "protected" keys are ordinary files
on disk. Before secsy-pki guards anything you care about, move the CA keys and
the secret-encryption KEK onto a real HSM (YubiHSM 2, a network HSM, or a cloud
HSM exposing a PKCS#11 module).

The most important thing to understand up front:

> **HSM private keys are non-extractable by design and cannot be copied between
> devices.** You do not "migrate" a key from SoftHSM to a YubiHSM — you generate
> a *new* key on the target HSM and re-establish trust around it. Plan for new CA
> keys (and therefore new CA certificates) and re-encryption of secrets.

## What has to change

| Asset | On SoftHSM | On the real HSM | Migration |
|-------|-----------|-----------------|-----------|
| CA signing keys | Software-backed token objects | Hardware-generated, non-extractable | **Regenerate** on the HSM; re-issue/cross-sign certs |
| Secret KEK | Software-backed RSA key | Hardware-generated RSA key | **Regenerate**, then re-encrypt existing envelopes |
| Issued leaf certs | Valid under the SoftHSM CA | — | Re-issue under the new CA before the old one is retired |
| Config | Points at `libsofthsm2.so` | Points at the vendor module | Update `pkcs11:` block |

Because the trust anchor changes, treat this as **standing up a new production
CA alongside the development one**, then cutting over — not an in-place swap.

## Step 1 — Provision the target HSM

1. Install the vendor PKCS#11 module and tools.
   - YubiHSM 2: `yubihsm-shell`, `yubihsm-connector`, and
     `/usr/lib/pkcs11/yubihsm_pkcs11.so`.
2. Establish the token: set the user PIN / authentication key, create the slot
   or domain the service will use.
3. **YubiHSM: enable forced audit logging before generating any key.** This is
   what makes the hardware hash-chain audit verifiable (see the
   [README](../README.md#audit-verification)). The correct provisioning order is
   *factory reset → audit provisioning → key generation*; the offline verifier
   checks that keys were generated only after forced audit was turned on. Do it
   via `POST /api/hsm/provision-audit` or the UI **before** creating CA keys.

## Step 2 — Point secsy-pki at the HSM

Update `config.yaml` from the SoftHSM module to the vendor module, and prefer
injecting the PIN via the environment rather than the file:

```yaml
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  token_label: "YubiHSM"
  # pin injected via SECSY_USER_PIN
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 1
  # password injected via env / secret manager
```

```bash
export SECSY_USER_PIN='…'         # do not commit PINs
```

Confirm the module loads and the token is visible before proceeding:

```bash
pkcs11-tool --module /usr/lib/pkcs11/yubihsm_pkcs11.so --show-info --list-slots
```

See [HSM / PKCS#11 configuration](hsm-configuration.md) for every setting.

## Step 3 — Generate the production CA on the HSM

Create fresh CA keys **on the device**. Use a distinct label so the new CA is
unambiguous and never collides with a dev key (labels must be unique per token):

```bash
secsy-ca -config config.yaml init-root \
  -label "Prod Root CA" -cn "Example Root CA" -o "Example Inc" -c "US" \
  -key-type ecdsa-p384 -validity-days 3650 -path-len 1

secsy-ca -config config.yaml issue-intermediate \
  -parent "Prod Root CA" -label "Prod Issuing CA" \
  -cn "Example Issuing CA" -key-type ecdsa-p256 -validity-days 1825 -path-len 0
```

Prefer ECDSA for any CA that must serve OCSP (Ed25519 CAs can only publish
CRLs). See the [CA guide](certificate-authority.md) for the full lifecycle.

### Bridging trust (optional)

If you must avoid a hard cutover, **cross-sign**: have the new production root
issue an intermediate whose subject/key matches an existing trust point, or
distribute the new root to relying parties ahead of time. In most deployments
the simpler path is to distribute the new root/chain and re-issue leaf
certificates before retiring the old CA.

## Step 4 — Re-issue end-entity certificates

Leaf certificates signed by the SoftHSM CA are not trusted under the new CA.
Have subscribers submit their CSRs to the new issuing CA (their private keys
never move):

```bash
secsy-ca -config config.yaml issue -ca "Prod Issuing CA" -csr app.csr \
  -profile server -chain -out app.crt
```

Roll these out, then **revoke and publish** the old certificates' status if the
old CA remains reachable during the transition.

## Step 5 — Migrate the secret-encryption KEK

The KEK is RSA and non-extractable, so you generate a new one on the HSM and
**re-wrap** existing secrets. Envelopes are self-describing and record which KEK
and OAEP algorithm sealed them, so decrypt-then-re-encrypt is safe.

```bash
# 1. Create the production KEK on the HSM
secsy-secret -config config.yaml init-kek -kek "prod-kek" -key-type rsa-4096

# 2. For each stored envelope: decrypt with the OLD KEK, re-encrypt with the NEW one
secsy-secret -config config.yaml decrypt -kek "secsy-kek"  -in old.json | \
secsy-secret -config config.yaml encrypt -kek "prod-kek" -out new.json
```

Then set `secret.kek_label: "prod-kek"` (or `SECSY_SECRET_KEK_LABEL`) so the
server and CLI use the new KEK. Note the SoftHSM SHA-1-only OAEP quirk no longer
applies once you are on a SHA-256-capable HSM — new envelopes will use
RSA-OAEP-SHA256. See [password encryption](password-encryption.md).

If secrets are held by callers (not centrally stored), publish the new KEK label
and have each owner re-encrypt on their next rotation.

## Step 6 — Harden and verify

- Set `policy.allow_root_basic_auth: false` once OIDC admins exist, to remove the
  shared-credential superuser. See [RBAC & audit](rbac-and-audit.md).
- Confirm the [tamper-evident event log](rbac-and-audit.md#2-tamper-evident-audit-logging)
  verifies (`GET /api/events/verify`) and, on YubiHSM, that the hardware audit
  log verifies with `secsy-verify` ([README](../README.md#audit-verification)).
- Run the [integration suite](../TESTING.md) against the new provider to confirm
  issue → revoke → CRL/OCSP and secret encrypt/decrypt all work end-to-end.
- Back up the HSM per the vendor's procedure (e.g. YubiHSM wrapped key backup) —
  a non-extractable key means a lost, un-backed-up HSM is an unrecoverable CA.

## Step 7 — Decommission SoftHSM

Only after the new CA is trusted everywhere and secrets are re-wrapped:

1. Stop referencing the SoftHSM module in any config.
2. Retire the old CAs (revoke remaining certs, publish a final CRL, then remove).
3. Securely delete the SoftHSM token directory (default `/tmp/softhsm/tokens`)
   and any exported PINs.

## Rollback

Keep the SoftHSM token and config until the cutover is proven. Because the two
providers use different key labels and different CA records, you can point
`config.yaml` back at SoftHSM to fall back — the old envelopes and old CA remain
usable as long as their keys still exist.

## See also

- [HSM / PKCS#11 configuration](hsm-configuration.md)
- [Certificate authority operations](certificate-authority.md)
- [Password / secret encryption](password-encryption.md)
- [RBAC, audit logging & config](rbac-and-audit.md)
