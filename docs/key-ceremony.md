# Key ceremony, backup & disaster recovery

This guide covers the enterprise HSM key-lifecycle operations that sit around the
CA: the **key ceremony** used to bring a root or intermediate CA into existence
under M-of-N operator control, the **key inventory** for auditing what a token
holds, and the **backup / restore** procedure and **disaster-recovery (DR)
runbook** for recovering a CA after a loss.

Everything here honors one invariant end to end: **private key material never
leaves the HSM.** Ceremonies generate keys *inside* the token, the inventory
reads only public attributes and policy flags, backups export only public
certificates and metadata, and the token's own (still-encrypted) key blobs are
backed up as opaque bytes. No command in this guide can export a private key.

All commands are `secsy-ca` subcommands and share the server's config, database,
and key provider. Build it with:

```bash
go build -tags sqlite -o secsy-ca ./cmd/secsy-ca
```

---

## 1. Key ceremony

A key ceremony is a controlled, witnessed, and audited procedure for creating a
CA's signing key. `secsy-ca ceremony` scripts it:

- generates the CA key **inside the key provider** (the HSM) and signs the
  root/intermediate certificate on the device;
- requires an **M-of-N quorum** of enrolled operators to each confirm their
  participation before any key material is created;
- writes every step to the **tamper-evident audit log** (`ceremony.start`, one
  `ceremony.operator_confirm` per operator, the underlying `ca.init_root` /
  `ca.issue_intermediate`, and `ceremony.complete`); and
- emits a **ceremony transcript** — a public, signed-off JSON artifact recording
  who participated, the resulting certificate, the public-key fingerprint, and
  an audit-log anchor (`seq` + `hash`) for later tamper checks.

The same discipline applies to other long-lived signing credentials: the RFC
3161 TSA key (`secsy-ca tsa-key`) and artifact code-signing keys
(`secsy-ca signing-key`) are generated on-device through the key provider and
never leave it. For release-signing keys specifically, see the dedicated
[key-ceremony notes in artifact-signing.md](artifact-signing.md#key-ceremony-notes-for-signing-keys)
(per-purpose keys, signer-role separation of duties, certificate-vs-key
rotation, and the revocation plan).

### Command

```
secsy-ca ceremony -role <root|intermediate> -label <key-label> -cn <subject-cn> \
    -operators "alice,bob,carol" -quorum 2 \
    [-key-type ecdsa-p384] [-validity-days 3650] [-path-len N] \
    [-parent <ca>]              # required for role=intermediate \
    [-o ORG -ou UNIT -c COUNTRY -st STATE -l LOCALITY] \
    [-transcript-out ceremony.json] \
    [-non-interactive | -confirm-file confirmations.txt]
```

- `-operators` enrolls the **N** operators by name. `-quorum` sets **M** (the
  number of confirmations required). If `-quorum` is omitted it defaults to a
  strict majority (`N/2 + 1`).
- **Interactive mode (default):** each enrolled operator is prompted in turn to
  type a confirmation phrase attesting their presence. Blank input skips that
  operator. The ceremony proceeds as soon as the quorum is reached.
- **Scripted mode:** pass `-confirm-file` (or `-non-interactive` to read stdin)
  with one `name:phrase` line per operator. Lines beginning with `#` are ignored.

Confirmation phrases are **never stored**. The transcript and audit log record
only `SHA-256("name:phrase")` — proof that an operator supplied their secret,
with no way to recover it. A confirmation from an operator who is not enrolled,
or a second confirmation from the same operator, is rejected.

### Example — 2-of-3 root ceremony

```bash
cat > confirm.txt <<'EOF'
alice:correct-horse-battery-staple
bob:hunter2-but-longer
EOF

secsy-ca -config config.yaml ceremony \
    -role root -label "Secsy Root CA" -cn "Secsy Root CA" -o "Secsy" \
    -key-type ecdsa-p384 -validity-days 3650 \
    -operators "alice,bob,carol" -quorum 2 \
    -confirm-file confirm.txt \
    -transcript-out root-ceremony.json
```

Then create an issuing intermediate under it (the parent's key is used on the
HSM to sign the intermediate certificate):

```bash
secsy-ca -config config.yaml ceremony \
    -role intermediate -parent "Secsy Root CA" \
    -label "Secsy Issuing CA" -cn "Secsy Issuing CA" -o "Secsy" \
    -key-type ecdsa-p256 -validity-days 1825 \
    -operators "alice,bob,carol" -quorum 2 \
    -confirm-file confirm.txt \
    -transcript-out issuing-ceremony.json
```

### Ceremony checklist

Run through this for a production root or intermediate ceremony:

**Before**
- [ ] Ceremony date, location, and participants scheduled; the quorum of
      operators (M-of-N) are physically present.
- [ ] The HSM is provisioned and its SO/user PINs are under split control.
- [ ] The target `config.yaml` points at the correct token and database.
- [ ] Key parameters agreed: role, label, subject DN, key type, validity, and
      path-length constraint (`-path-len 0` on an issuing CA that must only sign
      leaves).
- [ ] The ceremony is being recorded (video / written minutes) per your policy.

**During**
- [ ] Run `secsy-ca ceremony …` with the agreed parameters.
- [ ] Each of the M operators enters their confirmation. Sub-quorum aborts are
      expected to fail — that is the control working.
- [ ] Confirm the tool reports **"Non-extractable key verified: true"**.
- [ ] Record the printed **fingerprint** and **audit anchor (seq, hash)**.

**After**
- [ ] Archive the transcript JSON with the ceremony minutes (it contains only
      public data — safe to store widely).
- [ ] Verify the audit chain: `secsy-verify` / `VerifyEventChain` returns valid
      and the head matches the transcript anchor.
- [ ] Publish the root certificate; distribute the intermediate to relying
      parties as needed.
- [ ] Take a fresh **backup** (below) so the new key is captured in DR material.

---

## 2. Key inventory

`secsy-ca inventory` lists every key the configured provider holds, cross-
referenced with the CAs in the database, and surfaces the extractability policy
directly from the token:

```bash
secsy-ca -config config.yaml inventory
```

```
LABEL              KEY TYPE             EXTRACTABLE  SENSITIVE  CA / ROLE
Secsy Issuing CA   ecdsa-sha2-nistp256  no           yes        Secsy Issuing CA
Secsy Root CA      ecdsa-sha2-nistp384  no           yes        Secsy Root CA

2 key(s) on provider "pkcs11".
```

- `EXTRACTABLE = no` and `SENSITIVE = yes` are the desired state for every CA/KEK
  key: the token refuses to release the private value.
- `-strict` makes the command exit non-zero if **any** key is extractable — use
  it in CI/monitoring to assert the non-extractability invariant continuously.
- The **software** provider honestly reports its on-disk keys as extractable;
  that is precisely why production CA/KEK keys belong on an HSM.

The inventory reads only non-sensitive attributes (label, ID, key type) and the
`CKA_EXTRACTABLE` / `CKA_SENSITIVE` policy flags — never private key material.

---

## 3. Backup

Two independent things must be backed up to recover a CA:

1. **CA metadata** — the database (CAs, issued certificates, revocations, and the
   hash-chained audit log). This is public data.
2. **HSM token state** — the token's own encrypted key blobs. These stay
   encrypted and non-extractable; they are only usable by the same HSM (or a
   restored copy of it) with the correct PINs.

`secsy-ca backup` handles the metadata half and writes a DR manifest that ties
the two together:

```bash
secsy-ca -config config.yaml backup -out /secure/backups/secsy-$(date +%F)
```

It produces, under the output directory:

| File | Contents |
|------|----------|
| `manifest.json` | DR anchor: each CA's public-key fingerprint & key label, the key inventory (with extractability flags), the audit-log head `seq`+`hash`, chain-validity, driver, and provider. |
| `metadata.db` | A consistent online SQLite snapshot (`VACUUM INTO`) of the metadata store. *(SQLite driver only.)* |
| `cas.json` | Portable, engine-agnostic export of all CA records (public certs + metadata). |
| `events.json` | The full audit log, for independent chain verification. |

The backup **never** contains private keys. For a Postgres-backed deployment,
`metadata.db` is omitted and you back up the database with `pg_dump`;
`cas.json` / `events.json` remain a portable fallback.

### Backing up the HSM token state

This is HSM-specific and done with the token's own tooling:

- **SoftHSM** (dev/CI): copy the token directory (`directories.tokendir` from
  `SOFTHSM2_CONF`) — e.g. `cp -a /var/lib/softhsm/tokens token-state.bak`. The
  files are the encrypted object store; no plaintext key is present.
- **YubiHSM 2:** use `yubihsm-shell` `backup`/`restore` under a wrap key, or
  maintain a second device kept in sync. See
  [Production HSM migration](hsm-migration.md).
- **Network / cloud HSM:** follow the vendor's key-backup-under-wrap procedure
  or partition mirroring. The wrap key itself must be escrowed under M-of-N.

Store the token backup and the metadata backup with the same (or stronger)
access controls, and keep the HSM PINs under split control — the token blobs are
useless without them.

---

## 4. Restore & disaster-recovery runbook

Recovering a CA is: restore the metadata store, restore the HSM token state, then
**verify** that the two are consistent and the keys are usable.

`secsy-ca restore` performs the verification and, optionally, the metadata load:

```bash
secsy-ca -config config.yaml restore -in /secure/backups/secsy-2026-07-02
```

It checks, for the recovered environment:

- every CA in the manifest exists in the metadata store with a matching stored
  public-key fingerprint;
- the **HSM holds each CA's key** and its public key matches the certificate —
  the decisive proof that the token was restored and the keys are usable;
- the audit chain is intact and **at least as current as** the backup anchor
  (a shorter chain signals log truncation).

It exits non-zero if any check fails, and records an `hsm.restore` audit event.

### Runbook

1. **Stand up the host and dependencies.** Install the same secsy-pki version;
   restore/point `config.yaml` at the (to-be-restored) database and HSM.
2. **Restore the HSM token state** using the token's tooling (SoftHSM: copy the
   token directory back; YubiHSM/cloud: restore under the wrap key). Confirm the
   token is reachable: `secsy-ca inventory` should list the expected key labels.
3. **Restore the metadata store.**
   - *SQLite:* copy `metadata.db` from the backup to the configured DSN path
     (with the service stopped).
   - *Postgres:* `pg_restore` / `psql` from your dump.
   - *Engine-agnostic fallback into an empty store:* run
     `secsy-ca restore -in <dir> -load-metadata`, which repopulates CA records
     from `cas.json` only when the store is empty (it never overwrites live
     data).
4. **Verify:** `secsy-ca restore -in <dir>`. Expect every CA to report
   *"metadata present, HSM key resolves, fingerprint matches"* and the audit log
   *"chain intact"*.
5. **Prove issuance:** issue a throwaway leaf against the recovered issuing CA
   (`secsy-ca issue …`) to confirm the HSM can sign again, then revoke it.
6. **Resume service** and take a fresh backup.

### Tested DR drill

`scripts/dr-drill.sh` runs this entire lifecycle against SoftHSM in an isolated
sandbox and asserts each step — provision → 2-of-3 ceremony (root + intermediate)
→ inventory → backup (metadata + token state) → **simulate total loss** (wipe DB
and token) → restore → verify → prove re-issuance. It also asserts that no
plaintext private key appears anywhere in the backup and that a sub-quorum
ceremony is refused.

```bash
./scripts/dr-drill.sh            # run the drill (cleans up on success)
DR_KEEP=1 ./scripts/dr-drill.sh  # keep the workspace to inspect artifacts
```

Run it in CI and after any change to the ceremony, backup, or key-provider code
to keep the recovery path honest.

---

## What is *never* in a backup or transcript

- Private keys, in any form — they are generated in and confined to the HSM.
- Confirmation phrases — only their SHA-256 digests are recorded.
- HSM PINs — these are managed out of band under split control.

The only "key" bytes that ever leave the token are the HSM's **own encrypted**
blobs, which remain non-extractable and unusable without the device and its PINs.
