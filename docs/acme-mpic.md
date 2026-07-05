# ACME Multi-Perspective Issuance Corroboration (MPIC / SC-067)

Domain-control validation from a **single network vantage point** is vulnerable
to a *localized* BGP or DNS hijack: an attacker who can intercept the CA's
validation traffic on one path forges a passing http-01 / dns-01 / tls-alpn-01
response, and the CA cannot distinguish the forgery from a real success.

The CA/Browser Forum ballot **SC-067 — Multi-Perspective Issuance Corroboration**
(phasing in through 2025–2026) requires CAs to *corroborate* each domain-control
check from **several independent network perspectives** and to issue only when a
**quorum** of them agree. A hijack confined to one path is then outvoted by the
honest perspectives that reach the real target.

secsy-pki implements MPIC as a pluggable layer over the existing ACME challenge
validator. It is **disabled by default**; when disabled, validation uses the
single primary (local) perspective exactly as before.

- [1. How it works](#1-how-it-works)
- [2. The quorum rule (SC-067)](#2-the-quorum-rule-sc-067)
- [3. Configuration](#3-configuration)
- [4. Perspectives: resolvers and proxies](#4-perspectives-resolvers-and-proxies)
- [5. Fail-closed behavior](#5-fail-closed-behavior)
- [6. Observability](#6-observability)
- [7. Operational notes](#7-operational-notes)

## 1. How it works

Each **perspective** is a network vantage point that can independently perform
all three domain-control checks (an http-01 fetch, a dns-01 TXT lookup, a
tls-alpn-01 dial). There is always a **primary** perspective — the server's own
local view, using `acme.dns_resolver` or the system resolver — plus any number of
operator-configured **remote** perspectives, each resolving names and egressing
traffic from a different location.

For a domain-control challenge the coordinator:

1. Runs the check from the **primary** perspective. If the primary does not pass,
   the challenge fails immediately with the primary's error — there is nothing to
   corroborate. This is identical to pre-MPIC behavior.
2. If the primary passes, runs the **same check** concurrently from every remote
   perspective, each bounded by a per-perspective timeout.
3. Applies the **quorum policy** to the remote results. If the quorum holds the
   challenge is validated; otherwise it fails closed.

Only the three domain-control challenges are corroborated. `device-attest-01`
(hardware key attestation) and `email-reply-00` (RFC 8823 S/MIME) prove something
other than control of a *network* identifier and never route through MPIC.

Each remote result is classified as:

| Outcome | Meaning |
|---|---|
| **corroborated** | the perspective completed the check and agreed it passes |
| **rejected** | the check ran but got a wrong/absent response — the localized-hijack signal, when an honest remote reaches the real target and finds no challenge |
| **unavailable** | the perspective could not complete the check (transport/DNS/TLS error or timeout); not a definitive answer |

## 2. The quorum rule (SC-067)

Corroboration is evaluated over the **remote** perspectives. The number that must
corroborate, and the number that may dissent, scale with how many are used, per
the SC-067 table:

| Remote perspectives used | Max non-corroborations allowed | Min that must corroborate |
|---|---|---|
| 1 | 0 | 1 |
| 2 – 5 | 1 | used − 1 |
| 6 + | 2 | used − 2 |

A non-corroboration is any remote that did not agree — a **rejection** *or* an
**unavailable** — matching SC-067, which treats every non-corroboration alike.

The policy is configurable:

- **`min_perspectives`** (default 2) — the fail-closed floor: at least this many
  remote perspectives must return a *definitive* result (corroboration or
  rejection, not a timeout) before a quorum decision is trusted. Below it,
  corroboration fails closed rather than silently degrade to one vantage.
- **`max_failures`** — override the table's allowed-failure count. Unset or
  negative uses the SC-067 table. (For zero, set `require_all`.)
- **`require_all`** — demand that every attempted remote perspective corroborate.

## 3. Configuration

MPIC lives under `acme.mpic`. It is off unless `enabled: true`.

```yaml
acme:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: "server"
  # ... challenge_types etc ...
  mpic:
    enabled: true
    perspective_timeout_seconds: 10       # per-perspective check budget (default 10)
    quorum:
      min_perspectives: 2                 # fail closed below this many responses
      # max_failures: -1                  # -1 = SC-067 table (1 for 2–5, 2 for 6+)
      # require_all: false
    perspectives:
      - name: eu-west
        dns_resolver: "10.0.1.53:53"      # this perspective's DNS view
        proxy_url: "socks5h://10.0.1.9:1080"
      - name: us-east
        dns_resolver: "10.0.2.53:53"
        proxy_url: "socks5h://10.0.2.9:1080"
      - name: ap-south
        dns_resolver: "10.0.3.53:53"
        proxy_url: "socks5h://10.0.3.9:1080"
```

Validation is fail-fast at startup: enabling MPIC with fewer remote perspectives
than `min_perspectives`, a duplicate or empty perspective name (`primary` is
reserved), a perspective with no distinguishing view, or an unsupported proxy
scheme all abort startup with a clear error.

## 4. Perspectives: resolvers and proxies

A remote perspective differs from the primary by **where it resolves names** and
**where its traffic egresses**. Each perspective must set at least one of:

- **`dns_resolver`** (`host:port`) — pins this perspective's dns-01 TXT lookups
  and, absent a proxy, its http-01 / tls-alpn-01 name resolution to a specific DNS
  server, giving it a distinct DNS view.
- **`proxy_url`** (`socks5://host:port` or `socks5h://host:port`) — routes this
  perspective's http-01 fetches and tls-alpn-01 dials through an outbound **SOCKS5
  proxy** so the TCP connection to the target egresses from the proxy's network
  location — a genuinely remote vantage point. With **`socks5h`** the proxy also
  resolves the destination hostname, so the connection follows the remote site's
  DNS and routing end to end (recommended for http-01 / tls-alpn-01).

Only SOCKS5 is supported for the proxy, because it tunnels arbitrary TCP and so
relocates egress uniformly for both http-01 and tls-alpn-01. `socks5h://user:pass@host:port`
carries optional proxy authentication.

> secsy-pki adds **no real remote infrastructure**. Standing up the remote
> resolvers/proxies (in your own POPs, cloud regions, or a partner MPIC network)
> is a deployment concern; the config above is all the server needs to *use*
> them. The perspective abstraction is what keeps production wiring out of the
> code.

## 5. Fail-closed behavior

MPIC never *weakens* validation. Two distinct failure modes both deny issuance:

- **`failed_quorum`** — too many remote perspectives dissented (rejected or were
  unavailable) for the SC-067 quorum to hold. This is the hijack-detection path.
- **`failed_unresponsive`** — fewer than `min_perspectives` remote perspectives
  returned a definitive result (e.g. the proxies/resolvers are down). Rather than
  fall back to the single primary vantage, corroboration **fails closed**.

In both cases the challenge is marked invalid, the client receives an
`unauthorized` problem naming the dissenting perspectives, and an `acme.mpic`
audit record is written (see below).

## 6. Observability

**Metrics** (Prometheus):

- `secsy_acme_mpic_perspective_checks_total{perspective,challenge,result}` —
  per-perspective outcomes (`result` = `corroborated|rejected|unavailable`). A
  perspective persistently `unavailable` is a broken remote; one that `rejected`
  while others corroborated is the fingerprint of a localized interception of the
  CA's primary path.
- `secsy_acme_mpic_quorum_total{challenge,result}` — quorum decisions
  (`result` = `corroborated|primary_failed|failed_quorum|failed_unresponsive`). A
  rising `failed_quorum` is the primary MPIC alert signal.

**Audit** — on quorum failure an `acme.mpic` event is appended to the
[tamper-evident audit log](rbac-and-audit.md), with the actor set to the ACME
account and a detail naming every perspective's outcome, e.g.:

```
http-01 www.example.com: primary=corroborated remotes=[eu-west=corroborated us-east=rejected ap-south=rejected] result=failed_quorum
```

When MPIC is disabled these series and audit records are not emitted; the existing
`secsy_acme_challenge_validations_total` metric continues to cover the single
perspective.

## 7. Operational notes

- **Start in a staging posture.** A misconfigured or under-provisioned MPIC
  deployment fails issuance closed. Bring perspectives up and watch
  `secsy_acme_mpic_perspective_checks_total` for steady `corroborated` results
  before relying on it in production.
- **Geographic/topological diversity matters.** Perspectives that share an
  upstream network or resolver do not add corroboration value. Spread them across
  distinct ASes/regions.
- **Timeouts.** Distant perspectives may need a longer budget; set a
  per-perspective `timeout_seconds` or raise `perspective_timeout_seconds`. Checks
  run concurrently, so the wall-clock cost is bounded by the slowest perspective,
  not the sum.
- **Internal PKI.** MPIC targets the public-CA hijack threat model. An internal
  ACME deployment on a trusted network generally leaves it disabled.

## See also

- [ACME server](acme.md) — the ACME server this layer extends
- [CAA checking](caa.md) — the other fail-closed pre-issuance DNS gate
- [Observability](observability.md) — scraping the metrics above
- [RBAC & audit](rbac-and-audit.md) — the `acme.mpic` audit event
