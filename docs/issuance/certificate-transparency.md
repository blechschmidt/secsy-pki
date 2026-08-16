# Certificate Transparency (RFC 6962)

Secsy PKI can optionally submit issued certificates to
[Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) (CT)
logs and embed the resulting **Signed Certificate Timestamps (SCTs)** into the
final certificate. Modern browsers require publicly-trusted TLS server
certificates to carry SCTs, so this is needed for any CA whose leaves must be
accepted by Chrome/Safari without a separate CT delivery mechanism (TLS
extension or stapled OCSP).

CT is **off by default** and enabled **per issuance profile**, so you can run
public, CT-logged TLS profiles alongside private profiles that never touch a log.

## How it works

For a CT-enabled profile, issuance follows RFC 6962 §3:

1. **Precertificate.** The certificate template is built with a critical
   *poison* extension (`1.3.6.1.4.1.11129.2.4.3`, value `NULL`) and signed on the
   HSM. The poison guarantees the object can never be used as a real
   certificate.
2. **Submission.** The precertificate plus its issuer chain is submitted to each
   configured log's `add-pre-chain` endpoint. Each log returns an SCT.
3. **Policy.** The collected SCTs are counted against the profile's
   `min_scts`; the `fail_open` flag decides what happens when the minimum is not
   met (see below).
4. **Embedding & final signature.** The SCTs are serialised into a
   `SignedCertificateTimestampList` and embedded as the SCT list extension
   (`1.3.6.1.4.1.11129.2.4.2`, replacing the poison). The template — identical to
   the precertificate except for that one trailing extension — is re-signed on
   the HSM to produce the certificate returned to the caller.

Because the precertificate and the final certificate differ **only** in the
trailing poison↔SCT-list extension, the `TBSCertificate` a log signs over
(precertificate TBS with the poison removed) is byte-for-byte identical to what
a relying party reconstructs from the final certificate (final TBS with the SCT
list removed). This is what makes the embedded SCTs verify. **Both signatures
happen on the HSM; the CA private key never leaves it.**

The CA key signs precertificates directly (no delegated *precertificate signing
certificate*), so the issuer key hash in each SCT is the SHA-256 of the issuing
CA's `SubjectPublicKeyInfo`.

## Configuring logs

Register the CT logs your profiles may use under `certificate_transparency`:

```yaml
certificate_transparency:
  # Optional: a Google/Chrome-style CT log-list v3 JSON document (a cached copy of
  # log_list.json). Any log below whose `operator` is not set explicitly inherits
  # it from this list by URL match — so operator-diversity policies work without
  # hand-copying every operator name. Explicit `operator` values always win.
  known_logs_file: /etc/secsy-pki/ct/log_list.json
  logs:
    - name: test-log
      url: "https://ct.example.com/testlog"
      operator: "Example Labs"    # organization that runs the log (see below)
      # Optional PEM SubjectPublicKeyInfo. When present, every SCT this log
      # returns is cryptographically verified (signature + matching log id)
      # before it is embedded. Strongly recommended.
      public_key: |
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
    - name: prod-log
      url: "https://ct.googleapis.com/logs/us1/argon2025h1"
      operator: "Google"
      public_key_file: /etc/secsy-pki/ct/argon2025h1.pem
```

- `url` is the log's **base URL**; the `/ct/v1/add-pre-chain` path is appended
  automatically.
- `operator` names the **organization that runs the log** (e.g. `Google`,
  `Cloudflare`, `DigiCert`). CT operator-diversity policies count distinct
  *operators*, not distinct *logs*, so two logs run by the same operator satisfy a
  diversity requirement only once. Optional here — set it, or populate it in bulk
  from `known_logs_file`. See [Operator diversity](#operator-diversity).
- Supplying a log's public key (inline `public_key` or `public_key_file`) enables
  **SCT signature verification**: a returned SCT is only embedded if its
  signature validates against the log key and its log id matches. Without a key,
  SCTs are accepted on count alone — acceptable for a trusted internal test log,
  not for production.
- Supported log key/signature algorithms: ECDSA-P256 and RSA, both with SHA-256
  (the algorithms real CT logs use).

## Enabling CT on a profile

Add a `ct` block to any custom profile:

```yaml
profiles:
  - name: server-ct
    description: "TLS server certificate with Certificate Transparency"
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth]
    default_validity_days: 90
    ct:
      enabled: true
      logs: [test-log, prod-log]   # empty = submit to every registered log
      min_scts: 2                  # minimum SCTs required (default: 1)
      min_distinct_operators: 2    # minimum DISTINCT log operators (0 = off)
      require_operators: [Google]  # each listed operator must contribute an SCT
      fail_open: false             # see failure modes below
      timeout_seconds: 5           # per-log attempt timeout
      retries: 2                   # extra attempts per log after the first
```

A profile that references an unknown log name, or enables CT when no logs are
configured, is rejected at startup — misconfiguration fails loudly rather than
silently issuing without CT.

Submissions to the selected logs run **concurrently**; each log gets up to
`retries + 1` attempts, each bounded by `timeout_seconds`.

### Failure modes

When the SCT policy is not met — fewer than `min_scts` usable SCTs, fewer than
`min_distinct_operators` distinct operators, or a `require_operators` entry with
no SCT (logs down, timing out, or returning SCTs that fail verification):

| `fail_open` | Behaviour |
|-------------|-----------|
| `false` (default, **fail-closed**) | Issuance is **rejected**. Use when a certificate is worthless to you without CT (public TLS). |
| `true` (**fail-open**) | Issuance **proceeds**, embedding whatever SCTs were obtained (possibly none). The certificate is marked `failed_open`. Use when availability matters more than guaranteed CT logging. |

Operator misconfiguration (an unknown log name) is always fatal regardless of
`fail_open`; the flag only covers log **availability** and diversity shortfalls.

## Operator diversity

Modern CT policies (Chrome, Apple) require SCTs from a minimum number of
**distinct log operators**, not merely a minimum SCT count. The reason is a
threat model: a single log operator that is compromised or colludes can hand out
SCTs that all trace back to one organization, so counting SCTs alone can be
satisfied by one bad actor. Requiring SCTs from *independent* operators means no
single operator can unilaterally fake the appearance of public logging.

Two per-profile knobs enforce this, layered on top of `min_scts`:

- **`min_distinct_operators`** — the minimum number of distinct operators that
  must each contribute at least one usable SCT. `0` (default) disables the check.
- **`require_operators`** — an allowlist of operator names that must *each* be
  represented by a usable SCT (e.g. `[Google, Apple]`). Stricter than a bare
  count.

Each usable SCT is mapped to its log's configured `operator`; the number of
distinct operators is enforced alongside `min_scts`, honoring the same
`fail_open` semantics. The achieved operator count is recorded in the CT audit
detail (`operators=N`), the issuance response (`ct.operators`), and the
`secsy_ct_distinct_operators` metric.

### Attributing logs to operators

- Set each log's **`operator`** explicitly under `certificate_transparency.logs`, or
- point **`certificate_transparency.known_logs_file`** at a cached
  Google/Chrome CT log-list v3 JSON (`log_list.json`); any log without an explicit
  `operator` inherits it by URL match. Explicit values always win.

A log with **no** resolved operator cannot participate in a diversity policy: it
is counted as an independent operator (keyed by its own name) but can never
satisfy a `require_operators` entry, and — importantly — **a profile that enables
`min_distinct_operators`/`require_operators` over any candidate log lacking an
operator is rejected at startup**. This is deliberate: a diversity policy whose
logs are not all attributable to a known operator cannot be enforced meaningfully,
so the misconfiguration fails loudly rather than silently under-counting. The same
startup check rejects a policy that requires more operators than the candidate
logs can ever cover, or a `require_operators` name that runs none of them.

> **Note.** Under fail-open, a set of SCTs that meets `min_scts` but not the
> operator minimum is still **embedded** (the SCTs are real) — but the
> certificate is recorded as `failed_open`, not `submitted`, so the shortfall is
> visible in the inventory, console, and reports.

## Observing CT status

- **API.** `POST /api/ca/{id}/issue` and `/renew` responses include a `ct`
  object (`enabled`, `embedded`, `sct_count`, `status`, per-log `logs`). Stored
  certificates (`GET /api/ca/{id}/certificates`) carry `ct_status`
  (`none` / `submitted` / `failed_open`), `sct_count`, and `ct_logs`. See the
  [OpenAPI spec](../../server/internal/handlers/openapi.yaml).
- **Console.** The certificate list shows a **CT** column: an `N SCT` badge for
  logged certificates (hover for the log names) or a `fail-open` badge, and the
  issuance form reports the CT outcome.
- **Audit log.** `cert.issue` / `cert.renew` events record a CT summary in their
  detail (e.g. `ct=enabled scts=2 operators=2 logs=2/2`).
- **Metric.** `secsy_ct_distinct_operators` is a histogram of the distinct
  log-operator count observed per CT-enabled issuance (recorded even when the
  policy fails or ships fail-open). Alert on its lower quantiles falling toward 1
  (`histogram_quantile(0.1, ...)`, or a rising `..._bucket{le="1"}`): the live log
  set has degraded to a single operator even if the raw SCT count is still met.

You can confirm SCTs in an issued certificate with OpenSSL:

```console
$ openssl x509 -in cert.pem -noout -text | grep -A3 "CT Precertificate SCTs"
```

## Testing with a mock or test log

The implementation is exercised end-to-end without a real log:

- `server/internal/ct` unit tests stand up an in-process RFC 6962 log
  (`httptest`) that signs SCTs with an ECDSA key, then verify submission,
  multi-log fan-out, retries, SCT **embedding**, relying-party **verification**
  (reconstructing the TBS from the final certificate), and rejection of
  mismatched-key SCTs.
- `server/internal/ca` issuance tests (build tag `sqlite`) issue real
  certificates under a CT-enabled profile against mock logs and assert SCT
  embedding, database round-trip of CT status, and **policy enforcement**
  (fail-closed rejects when the log is down; fail-open proceeds and is marked
  `failed_open`).

Run them:

```console
$ cd server
$ go test ./internal/ct/...            # no HSM required
$ go test -tags sqlite ./internal/ca/ -run CT
```

To point at a real test log instead, register it under
`certificate_transparency.logs` with its public key and reference it from a
profile.

## Inclusion-proof monitoring (post-issuance)

An SCT is only a **promise**: the log signs "I will merge this certificate into
my Merkle tree within my Maximum Merge Delay (MMD)". A misbehaving or compromised
log can hand out an SCT and then never include the certificate. Embedding SCTs
proves the promise was made; it does not prove the promise was kept.

The optional **inclusion monitor** (a leader-elected background job, so it runs
once across a multi-replica deployment) closes that gap. Once a certificate's SCT
is older than the log's MMD, the monitor:

1. fetches the log's **signed tree head** (`get-sth`) and verifies its signature
   against the configured log public key;
2. requests a **Merkle audit path** (`get-proof-by-hash`) for the certificate's
   leaf hash and verifies the inclusion proof reconstructs the signed tree-head
   root;
3. records the per-SCT outcome (`included` / `pending` / `failed` / `unknown_log`)
   in the `sct_inclusion` table;
4. **alerts on any SCT a log failed to honor** — a missing inclusion proof past
   MMD is treated as log misbehavior / possible mis-issuance and raised on the
   monitor's notification sinks (log/webhook) with a `secsy_ct_inclusion_failed`
   metric and a `ct.inclusion` doctor finding.

### Enabling it

The monitor requires each watched log to have a **public key** (it must verify
the signed tree head) and reuses the same `certificate_transparency.logs`
registry. Add an `mmd_hours` to each log (the deadline it advertises; default 24)
and an `inclusion_monitor` block:

```yaml
certificate_transparency:
  logs:
    - name: prod-log
      url: "https://ct.googleapis.com/logs/us1/argon2025h1"
      public_key_file: /etc/secsy-pki/ct/argon2025h1.pem   # REQUIRED for monitoring
      mmd_hours: 24            # log's Maximum Merge Delay; misbehavior is only
                              # flagged once an SCT is older than this
  inclusion_monitor:
    enabled: true
    interval_minutes: 60      # scan cadence (default 60); runs once on leadership gain
    max_certs_per_run: 500    # oldest-unresolved certs processed per scan (default 500)
    timeout_seconds: 15       # per get-sth / get-proof-by-hash request (default 15)
```

Enabling the monitor with no configured logs, or with a log missing a public
key, is rejected at startup.

### Observing inclusion

- **CLI.** `secsy-ca ct inclusion-status` lists the recorded state (filter with
  `-status included|pending|failed|unknown_log`, `-ca`/`-serial`, `-limit`,
  `-json`). `secsy-ca ct verify-inclusion` triggers an on-demand scan now
  (`-max`, `-json`) instead of waiting for the background loop — useful after
  issuing a batch or when investigating an alert.
- **API / console.** `GET /api/ct/inclusion` returns the state with per-status
  counts; the console **CT** page renders it as a filterable table (status badge,
  log name, tree size, leaf index), with `failed` rows highlighted.
- **Doctor.** `secsy-ca doctor` runs a `ct.inclusion` check: `FAIL` if any SCT is
  in the `failed` state (a log broke its MMD promise), `WARN` if the monitor is
  enabled but has verified nothing yet.
- **Metrics.** `secsy_ct_inclusion_checks_total{result}`,
  `secsy_ct_inclusion_pending`, `secsy_ct_inclusion_failed`,
  `secsy_ct_inclusion_monitor_runs_total{result}`, and
  `secsy_ct_inclusion_monitor_staleness_seconds`. Alert on
  `secsy_ct_inclusion_failed > 0` (log misbehavior) and on rising staleness (the
  monitor stopped running — check leader election).

The operator response to a firing inclusion alert is in the
[runbook](../operations/runbook.md#ct-inclusion-monitoring-log-misbehavior).

## Notes & limitations

- CT applies to the X.509 leaf issuance path (`/api/ca/{id}/issue`, `/renew`,
  and any profile-driven issuance such as ACME when the profile enables CT). It
  does not apply to CA certificates or SSH certificates.
- SCTs are embedded in the certificate (the RFC 6962 §3.3 X.509v3 extension
  method). The TLS and OCSP-stapling SCT delivery methods are not used.
- Precertificates are signed directly by the CA key; delegated *precertificate
  signing certificates* (`1.3.6.1.4.1.11129.2.4.4`) are not required.
