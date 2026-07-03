# Incident response — key-compromise mass revocation

This runbook covers the **mass-revocation phase** of a compromise incident:
you have decided a population of certificates must die, and you have a clock —
under the CA/Browser Forum Baseline Requirements a CA must revoke within
**24 hours** of confirming key compromise (5 days for most other reasons).
This is the operational companion to the
[operator runbook's CA-key-compromise section](RUNBOOK.md#suspected-ca-key-compromise),
which covers confirming the compromise and rotating/retiring the CA key
itself. Everything here works while a tenant is suspended and is exempt from
rate limits and tenant quotas — nothing may throttle revocation.

The tooling is one engine with three fronts:

| Surface | Entry point | Notes |
|---------|-------------|-------|
| CLI | `secsy-ca revoke-bulk` | Works directly against the store + HSM; usable while the API is down |
| REST | `POST /api/ca/{id}/revocations:bulk` | `ca:manage` capability in the CA's tenant; WebAuthn step-up eligible (`cert.revoke_bulk`) |
| Console | Certificates page → *Bulk revocation — incident response* | Preview + typed count confirmation |

Every run applies revocations in bounded transactional batches, regenerates
the **base and delta CRL once at the end** (per affected partition when CRL
sharding is on), invalidates cached OCSP responses, refreshes the pre-signed
OCSP set (server path), and appends **one audit event per certificate plus a
summary event**, all tied together by an operation id.

---

## Scenario catalogue — choosing the selection

Scope the revocation with filters. All filters AND together; always dry-run
first (§ Step 2).

| Scenario | Selection |
|----------|-----------|
| **CA key compromised** — every certificate the key signed is suspect | no filter (the whole CA), `-reason keyCompromise`; then rotate/retire the CA per the [runbook](RUNBOOK.md#suspected-ca-key-compromise) |
| **Attacker-issued certificates found** (CT monitoring, `secsy-ca discover`) | `-serials-file` with the observed serials — serials the inventory has never seen are still revoked, as bare CRL entries; that is the point |
| **Issuance-window compromise** — RA/validation bug or intrusion between T₁ and T₂ | `-issued-after T1 -issued-before T2` |
| **Fleet/domain compromise** — one org's namespace must go | `-pattern '*.corp.example.com'` (case-insensitive glob over CN + SANs) |
| **Profile mis-issuance** — a profile shipped with a broken policy | `-profile <name>`, optionally with an issuance window |
| **Tenant off-boarding / compromise** | run per CA of the tenant (list them with `secsy-ca list`); suspension does not block revocation |

Notes on selection semantics:

- Only **not-yet-revoked** certificates are selected; expired ones are skipped
  unless `-include-expired` (an RFC 5280 CRL need not list expired serials).
- A serial list restricts the selection to those serials. Entries found in the
  inventory are additionally checked against the other filters
  (mismatches are reported as `filtered out`); entries the inventory does not
  know are **included regardless** and reported as `unknown`.
- Serial files: one serial per line, `#` comments. Decimal by default;
  `-serial-format hex` (or a `0x` prefix per entry) accepts openssl-style hex,
  colons tolerated.

## Step 0 — contain first

Revocation is cleanup, not containment. If issuance under the affected CA may
still be feeding the attacker, stop it first (suspend the tenant, disable the
profile, or take the enrollment endpoints down — see the
[runbook](RUNBOOK.md#suspected-ca-key-compromise)). Containment also freezes
the selection, which keeps the dry-run count stable for Step 3.

## Step 1 — record the incident parameters

Pick an **operation id** (ticket number, e.g. `IR-2026-042`) and pass it to
every run with `-operation-id`. All per-certificate audit events carry
`bulk_op=<id>` and the summary carries `op=<id>`, so the full set is
reconstructable from the audit chain afterwards — including across resumed
runs.

Reason codes: use `keyCompromise` for subscriber-key or unknown-scope
compromise, `cACompromise` only when the CA key itself signed rogue leaves
(that reason propagates hard failure to relying parties), `superseded` /
`cessationOfOperation` for administrative mass revocations.

## Step 2 — dry run (mandatory)

```bash
secsy-ca -config config.yaml revoke-bulk \
  -ca issuing-ca-1 \
  -pattern '*.corp.example.com' \
  -issued-after 2026-06-28T00:00:00Z \
  -reason keyCompromise \
  -operation-id IR-2026-042 \
  -dry-run
```

The plan reports, before anything is written:

- `WILL REVOKE: N` — the number you must confirm in Step 3;
- `from inventory` vs `unknown serials` (serial-list entries with no
  inventory row — expected during a CA-key compromise);
- `already revoked` (resuming an earlier run), `filtered out`,
  `expired excluded`;
- a 20-entry sample of what dies.

**Read the sample.** A glob that is one character off revokes someone else's
fleet. If the counts surprise you, stop and re-scope.

REST equivalent (the console does exactly this):

```
POST /api/ca/{id}/revocations:bulk
{"dry_run": true, "reason": "keyCompromise",
 "filter": {"pattern": "*.corp.example.com", "issued_after": "2026-06-28T00:00:00Z"}}
```

## Step 3 — execute with the confirmed count

```bash
secsy-ca -config config.yaml revoke-bulk \
  -ca issuing-ca-1 \
  -pattern '*.corp.example.com' \
  -issued-after 2026-06-28T00:00:00Z \
  -reason keyCompromise \
  -operation-id IR-2026-042 \
  -confirm 3117
```

`-confirm` must equal the **live** selection count. If certificates were
issued or revoked since the dry run, the command refuses with the fresh count
and changes nothing — re-check and re-confirm. This is deliberate: under
active attack the population moves, and you must know by how much.
(REST: `confirm_count`; a drift answers `409` with `actual_count`. The console
arms its execute button only when you type the previewed count.)

Two escape hatches, use knowingly:

- `-force` skips the count check (scripted response, or issuance you cannot
  freeze keeps shifting the count). The dry-run plan is still printed first.
- `-batch-size` (default 500) tunes the per-transaction batch if your store
  needs it.

Progress is reported per batch (`revoked 1500/3117...`). The run ends with the
CRL scopes regenerated and the total duration — that duration is what the
`secsy_revocations_bulk_duration_seconds` metric records against your 24-hour
budget.

## Step 4 — interruption and resume

The engine is **resumable by construction**: the selection only ever covers
not-yet-revoked certificates, and already-revoked serials are skipped without
touching their revocation time or re-emitting audit events. If the run dies
(store outage, ctrl-C, pod eviction):

1. Re-run the **same command** with the same `-operation-id`.
2. Dry-run first if you want to see the remainder (`already revoked` counts
   climb, `WILL REVOKE` shrinks).
3. Confirm the *remainder* count (or `-force`).

Revocations already applied before the interruption are permanent and were
audited; a failed run also appends an error summary event so the audit trail
shows the interruption itself. If the failure happened **after** the batches
but during CRL regeneration, either re-run (a zero-remainder run still
succeeds) or regenerate manually: `secsy-ca gen-crl -ca <ca>`.

## Step 5 — verify propagation

Do not declare the incident contained until relying parties can see the
revocations:

```bash
# CRL: entry count and freshness
curl -s https://pki.example.com/api/ca/<id>/crl | openssl crl -inform DER -noout -text | head -40

# Delta CRL references the regenerated base
curl -s https://pki.example.com/api/ca/<id>/crl/delta | openssl crl -inform DER -noout -text | grep -A1 "Delta CRL"

# OCSP now answers "revoked" for a spot-checked serial
openssl ocsp -issuer chain.pem -serial 0x<hex> \
  -url https://pki.example.com/api/ca/<id>/ocsp -resp_text | grep -E "Cert Status|Revocation Reason"
```

- The bulk run already invalidated cached OCSP responses and (server path)
  refreshed the pre-signed set; a `presign refresh: FAILED` warning in the
  output is non-fatal — on-demand responses are already correct, and the next
  scheduled presign batch repairs the cache. Check
  `secsy_ocsp_presign_last_success_timestamp_seconds` if it persists.
- If the static artifact publisher (CDN offload) is enabled, force a snapshot
  so the CDN serves the new CRLs: `secsy-ca publish` (or wait one publish
  interval; the CRL's own `nextUpdate` bounds staleness).
- Audit: `secsy-ca audit verify` still passes, and
  `GET /api/events?action=cert.revoke_bulk` shows the summary with your
  operation id.

## Step 6 — post-incident

- Export the evidence: `secsy-ca audit export -action cert.revoke -since <T>`
  plus the summary event; anchor the chain head (`secsy-ca audit anchor`).
- Metrics for the report: `secsy_revocations_bulk_total`,
  `secsy_revocations_bulk_certificates_total`,
  `secsy_revocations_bulk_duration_seconds` (histogram) — alongside the CRL
  generation counters.
- If the CA key itself was compromised, continue with
  [rotate/retire](RUNBOOK.md#suspected-ca-key-compromise); mass revocation of
  its leaves does not make the key trustworthy again.
- Re-issue replacements only after the compromise vector is closed; the
  expiry monitor and `secsy-agent` fleets re-enroll automatically once
  issuance is re-enabled.

## Obligations quick reference (CA/B Forum BR §4.9.1.1)

| Trigger | Deadline |
|---------|----------|
| Subscriber key compromise (proven) | **24 hours** |
| CA obtains evidence of mis-issuance / validation failure | 24 hours – 5 days depending on cause |
| Certificate no longer compliant with the BRs | 5 days |
| Subscriber request | 24 hours |

The 24-hour clock starts at **confirmation**, not at completion of your
investigation — scope with filters you can defend, revoke, then keep
investigating. Revoking too much is recoverable (re-issue); revoking too late
is not.
