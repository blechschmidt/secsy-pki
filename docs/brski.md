# BRSKI: zero-touch device onboarding (RFC 8995)

BRSKI — Bootstrapping Remote Secure Key Infrastructure — lets a factory-fresh
device join an operator's domain **with no per-device configuration**. The device
ships with a manufacturer birth certificate (an IEEE 802.1AR **IDevID**) and a
pre-installed trust anchor for the manufacturer's signing service. On first power-
up it discovers the domain **registrar**, proves its identity, obtains a signed
**voucher** that tells it which domain now owns it, and then enrolls its
operational certificate (an **LDevID**) over EST — all automatically.

secsy-pki implements the **registrar** (the Join Registrar/Coordinator, JRC) on
top of the existing [EST enrollment](enrollment.md) and the
[hardware-attestation](authentication.md) trust anchors. The LDevID is issued
through the shared HSM-backed CA, so the domain signing key never leaves its
token.

> BRSKI is disabled by default. It requires `est.enabled`, since the operational
> certificate is issued over EST. See the `brski:` block in `config.yaml`.

---

## 1. The actors

| Actor | Who runs it | Role |
|---|---|---|
| **Pledge** | the new device | Holds an IDevID + MASA trust anchor; drives the flow. |
| **Registrar** | **secsy-pki** | Validates the IDevID, relays to the MASA, returns the voucher, hands off to EST. |
| **MASA** | the manufacturer | Signs the voucher that authorizes the pledge→domain binding. |
| **Domain CA** | **secsy-pki** (HSM) | Signs the LDevID via the EST handoff. |

The MASA is **pluggable**: point the registrar at an external manufacturer MASA
over HTTPS (`brski.masa.url`), or run the **minimal built-in MASA**
(`brski.masa.builtin`) for single-vendor / lab deployments where secsy-pki holds
the manufacturer signing key too.

---

## 2. The flow

```
 Pledge                         Registrar (secsy-pki)                 MASA
   │  provisional TLS  ───────────►│                                    │
   │  (pins server cert)           │                                    │
   │                               │                                    │
   │  POST requestvoucher ────────►│  1. verify pledge-request signature│
   │  (signed by IDevID,           │     recover & TRUST the IDevID     │
   │   pins proximity cert)        │     (chain to manufacturer roots)  │
   │                               │  2. check proximity + serial       │
   │                               │  3. sign registrar-request ───────►│  verify pledge & registrar
   │                               │                                    │  requests, pin domain cert,
   │                               │◄──────────── signed voucher ───────│  sign voucher
   │◄──────── voucher ─────────────│  4. authorize pledge for EST       │
   │  verify MASA sig, nonce,      │                                    │
   │  pin domain cert              │                                    │
   │                               │                                    │
   │  POST voucher_status ────────►│  (telemetry)                       │
   │                               │                                    │
   │  EST simpleenroll ───────────►│  authorize by IDevID (TLS client   │
   │  (IDevID as TLS client cert)  │   cert) → issue LDevID on the HSM  │
   │◄──────── LDevID ──────────────│                                    │
   │  POST enrollstatus ──────────►│  (telemetry)                       │
```

**Registrar validation is fail-closed.** A voucher is issued only when:

1. **The IDevID is authentic** — its certificate chains to a configured trusted
   manufacturer root. These are the *same* anchors the
   [attestation gate](authentication.md) uses; the registrar reuses them and any
   additional `brski.trust_anchor_files` you supply.
2. **Proximity holds** — the `proximity-registrar-cert` the pledge pinned from its
   provisional TLS connection equals *this* registrar's domain certificate
   (`require_proximity`, on by default). This is the defense against a pledge
   being steered to an attacker's registrar.
3. **The serial numbers agree** — the pledge's asserted `serial-number` matches
   its IDevID, and the MASA re-checks this against the embedded pledge request.

The **voucher** (RFC 8366) is a small JSON document wrapped in a CMS SignedData
(`application/voucher-cms+json`), built and verified through the shared
[`internal/cms`](enrollment.md) layer. Its `pinned-domain-cert` is the registrar
certificate the pledge connected to, so the pledge can complete its provisional
TLS connection into a fully trusted one.

### The EST handoff

After the voucher exchange the registrar records the pledge as **authorized to
enroll** (keyed by the IDevID public key, bounded by `pledge_ttl_minutes`). The
pledge then calls **EST `simpleenroll`** over the same connection, presenting its
IDevID as the TLS client certificate. The EST server recognizes the authorized
pledge, and the operational LDevID is signed on the HSM. The pledge generates a
*fresh* LDevID key for this CSR — the IDevID authorizes the session, the LDevID is
the new operational identity.

---

## 3. Configuration

```yaml
est:
  enabled: true                     # BRSKI hands off to EST — required
  ca_label: "Secsy Issuing CA"
  profile: client

# Trusted manufacturer roots for the pledge IDevID (reused by BRSKI).
attestation:
  trusted_root_files:
    - /etc/secsy/manufacturer-roots.pem

brski:
  enabled: true
  # base_path: /.well-known/brski           # default
  ca_label: "Secsy Issuing CA"              # domain CA for the LDevID (defaults to the EST CA)
  profile: client                           # issuance profile a pledge enrolls under
  registrar_key_label: brski-registrar      # HSM key that signs registrar voucher-requests
  registrar_cert_file: /etc/secsy/brski/registrar.pem
  # domain_cert_file: /etc/secsy/tls/server.pem   # cert the pledge pins; defaults to the registrar cert
  # trust_anchor_files:                     # extra IDevID roots on top of attestation's
  #   - /etc/secsy/brski/vendor-b-roots.pem
  require_proximity: true
  pledge_ttl_minutes: 10
  masa:
    builtin: true                           # minimal in-process MASA, OR set masa.url
    key_label: brski-masa                   # HSM key that signs vouchers
    cert_file: /etc/secsy/brski/masa.pem    # MASA cert the pledge trusts
    # voucher_validity_hours: 24            # bounds nonceless vouchers
```

**Per-profile enable.** When any issuance profile sets `brski.enabled: true`, the
registrar refuses to onboard under a profile that does not — the per-profile
enable gate. When no profile sets it, the registrar's configured `profile` is
implicitly allowed.

```yaml
profiles:
  - name: iot-device
    brski:
      enabled: true
```

**Registrar vs domain certificate.** The pledge pins the certificate that
terminates its provisional TLS connection. Set `domain_cert_file` to that TLS
server certificate when it differs from the registrar's voucher-request signing
certificate; otherwise the single registrar identity is used for both.

**External MASA.** For a real manufacturer MASA, set `masa.url` (its
`/requestvoucher` lives under that base) instead of `masa.builtin`. Pin the MASA's
server trust anchor at the transport layer in production.

---

## 4. Endpoints

The registrar mounts three endpoints under `base_path` (RFC 8995 §5):

| Method | Path | Body | Purpose |
|---|---|---|---|
| POST | `/.well-known/brski/requestvoucher` | `application/voucher-cms+json` | Submit the pledge voucher-request, receive the signed voucher |
| POST | `/.well-known/brski/voucher_status` | `application/json` | Pledge voucher-processing telemetry |
| POST | `/.well-known/brski/enrollstatus` | `application/json` | Pledge enrollment telemetry |

When the built-in MASA is exposed as a standalone service it additionally serves
`POST <base>/requestvoucher` for the **registrar** voucher-request.

---

## 5. Auditing & metrics

Every registrar action appends to the hash-chained
[audit log](rbac-and-audit.md) under action **`cert.brski`**, actor
`brski-pledge:<serial>`:

| Result | Meaning |
|---|---|
| `success` | Voucher issued and the pledge authorized to enroll; or a telemetry report with `status:true`. |
| `denied` | Fail-closed policy refusal: untrusted IDevID, failed proximity, or serial mismatch. |
| `error` | Malformed request, or the MASA declined to issue a voucher. |

Prometheus metrics:

| Metric | Labels | Meaning |
|---|---|---|
| `secsy_brski_voucher_requests_total` | `result` | Registrar `/requestvoucher` outcomes (`success`/`denied`/`error`). |
| `secsy_brski_vouchers_issued_total` | `result` | Vouchers minted by the built-in MASA. |
| `secsy_brski_status_reports_total` | `kind`, `status` | Pledge `voucher_status`/`enrollstatus` telemetry. |
| `secsy_brski_enroll_authorized_total` | `result` | EST-handoff authorization checks. |

The `/requestvoucher` endpoint is metered and gated behind the
[rate-limit + HSM concurrency guard](rate-limiting.md) like the other signing
endpoints (it signs a registrar voucher-request on the HSM).

---

## 6. Security notes

- **The manufacturer trust anchor is the root of authenticity.** Only IDevIDs
  chaining to a configured manufacturer root are onboarded; treat
  `attestation.trusted_root_files` / `brski.trust_anchor_files` as a deliberate,
  audited trust decision.
- **Keep `require_proximity` on.** Without it a pledge could be relayed to a
  registrar it never connected to. With it, the pledge-pinned cert must be this
  registrar's identity.
- **HSM-backed issuance.** The LDevID is signed on the HSM through EST; the domain
  CA key never leaves its token. The registrar and (built-in) MASA signing keys
  are also provider-backed and sign through the bounded session pool.
- **Nonceful by default.** Live vouchers echo the pledge nonce and cannot be
  replayed. The built-in MASA falls back to a short-lived `expires-on` voucher
  only when a pledge presents no nonce (e.g. a device with no real-time clock).
- **Bounded enrollment window.** A bootstrapped pledge is authorized to EST-enroll
  only for `pledge_ttl_minutes`; enrollment must follow bootstrapping promptly.
- **Serve over TLS.** BRSKI is a TLS protocol; the pledge presents its IDevID as
  the TLS client certificate for the EST handoff, and pins the registrar's TLS
  server certificate as the domain anchor.
