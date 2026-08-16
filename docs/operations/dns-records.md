# DANE TLSA & SSHFP DNS record generation

Secsy PKI can generate the DNS pinning records that let relying parties
authenticate a service through DNSSEC instead of (or alongside) the public PKI:

- **DANE TLSA** ([RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698)) —
  pins a TLS service's certificate or issuing CA in a `TLSA` record, so a
  DANE-aware client (mail servers doing MTA-STS/DANE, `openssl s_client -dane_tlsa`)
  can verify the endpoint from DNSSEC-signed DNS.
- **SSHFP** ([RFC 4255](https://datatracker.ietf.org/doc/html/rfc4255)) — pins an
  SSH host key fingerprint in an `SSHFP` record, so `ssh` with
  `VerifyHostKeyDNS=yes` accepts a host on first contact without a manual
  `known_hosts` entry.

Both are **read-only, offline helpers**: they derive records from material this
PKI already issued (a CA certificate, a leaf, or an sshca-signed host cert). No
HSM operation is performed — the records are pure fingerprints of public data —
and nothing is written to DNS. You copy the emitted zone snippet into your
DNSSEC-signed zone yourself.

This closes the loop for the two deployment styles the CA already supports:
X.509 TLS services (TLSA) and the [SSH certificate authority](../ca/ssh-ca.md) (SSHFP).

## DANE TLSA records

### What is generated

For a TLS service at `host:port`, `secsy-ca dns-records tlsa` emits a full set of
`TLSA` records so you can publish whichever DANE usage your policy calls for:

| Certificate usage | Emitted for | Meaning |
|---|---|---|
| `2` (DANE-TA) | the **issuing CA** | "trust anchor assertion" — any leaf chaining to this CA is accepted. Survives leaf renewal, so it is the low-maintenance choice for a CA you control. |
| `0` (PKIX-TA) | the **issuing CA** | as DANE-TA, but the leaf must *also* pass normal PKIX validation. |
| `3` (DANE-EE) | the **leaf** (only when `-serial` is given) | "end-entity assertion" — pins this exact certificate. Must be re-published on every renewal. |

Each usage is emitted across both **selectors** and the two common **matching
types**, so you can pick the granularity you want:

- selector `0` = the full certificate, selector `1` = its SubjectPublicKeyInfo
  (SPKI). SPKI (`1`) is usually preferred: it survives a certificate renewal
  that keeps the same key.
- matching type `1` = SHA-256 of the selected data (the normal choice),
  matching type `0` = the data verbatim (no hash).

The owner name follows RFC 6698: `_<port>._<protocol>.<host>` (protocol
defaults to `tcp`).

### CLI

```console
# CA-level TLSA records (DANE-TA / PKIX-TA) for an HTTPS service on 443:
$ secsy-ca -config config.yaml dns-records tlsa -ca my-intermediate -host www.example.com

_443._tcp.www.example.com. IN TLSA 2 1 1 8cb0...e91   ; DANE-TA  SPKI SHA-256
_443._tcp.www.example.com. IN TLSA 2 0 1 4f2a...b17   ; DANE-TA  full-cert SHA-256
_443._tcp.www.example.com. IN TLSA 0 1 1 8cb0...e91   ; PKIX-TA  SPKI SHA-256
...

# Add the end-entity (DANE-EE 3) record by naming a leaf serial the CA issued:
$ secsy-ca -config config.yaml dns-records tlsa -ca my-intermediate \
    -host www.example.com -serial 6f:a1:... 

# A non-default port / protocol, and JSON output for automation:
$ secsy-ca -config config.yaml dns-records tlsa -ca my-intermediate \
    -host mail.example.com -port 25 -protocol tcp -json
```

Flags: `-ca <id|label>` (required), `-host <fqdn>` (required), `-port` (default
443), `-protocol tcp|udp` (default tcp), `-serial <leaf>` (optional; adds the
DANE-EE records), `-json`.

### API

```
GET /api/ca/{id}/dns-records/tlsa?host=www.example.com&port=443&protocol=tcp&serial=<optional>
```

Returns the structured records and the ready-to-paste zone text. RBAC: any
caller that can read the CA. `serial` must name a leaf issued by `{id}`.

## SSHFP records

`secsy-ca dns-records sshfp` derives `SSHFP` records — fingerprint types `1`
(SHA-1) and `2` (SHA-256, the one clients prefer) — for either a raw SSH host
public key or a host certificate signed by the [SSH CA](../ca/ssh-ca.md). The record
algorithm number is inferred from the key type (1=RSA, 2=DSA, 3=ECDSA,
4=Ed25519).

```console
# From a host's public key file (no CA involvement needed):
$ secsy-ca dns-records sshfp -host host.example.com \
    -key /etc/ssh/ssh_host_ed25519_key.pub

host.example.com. IN SSHFP 4 1 99db...c0f
host.example.com. IN SSHFP 4 2 5f3e...a72

# From an sshca-signed host certificate (the host defaults from the cert's
# first principal if -host is omitted):
$ secsy-ca -config config.yaml dns-records sshfp -ssh-ca host-ca -serial 42
```

Flags: `-host <fqdn>`, and **either** `-key <path>` (an OpenSSH
`authorized_keys`-format public key or certificate) **or** `-ssh-ca <id|label>`
+ `-serial <n>` (a stored sshca host certificate). `-json` emits structured
records plus the zone text.

### API

```
POST /api/ssh/cas/{id}/dns-records/sshfp
{ "host": "host.example.com", "serial": "42" }        # from a stored host cert
{ "host": "host.example.com", "public_key": "ssh-ed25519 AAAA..." }  # from a pasted key
```

## Console

The **DNS Records** page (`/console/`, DNS pinning records) has a **DANE TLSA**
panel (CA + host + port, optional leaf serial) and an **SSHFP** panel (SSH CA +
serial, or a pasted host public key). Each renders the zone-file snippet for
copy-paste. Both call the endpoints above.

## Publishing and verifying

1. **DNSSEC is mandatory for DANE and strongly advised for SSHFP.** A TLSA/SSHFP
   record is only trustworthy if the zone is DNSSEC-signed; without it an
   attacker can forge the pin. Add the records to your signed zone and re-sign.
2. **Match the pin to your renewal cadence.** Prefer usage `2`/`0` (CA-level)
   and selector `1` (SPKI) so records survive leaf renewals. If you publish a
   DANE-EE (`3`) or full-cert (selector `0`) record, you must re-publish it on
   every renewal — automate it against the ARI/monitor renewal event or you will
   break the service when the leaf rotates.
3. **Verify TLSA** once published:
   ```console
   $ openssl s_client -connect www.example.com:443 -dane_tlsa_domain www.example.com \
       -dane_tlsa_rrdata "2 1 1 8cb0...e91"
   ...
   Verification: OK
   DANE TLSA 2 1 1 ...  matched EE certificate at depth 1
   ```
4. **Verify SSHFP** with `ssh -o VerifyHostKeyDNS=yes host.example.com` (the
   host key is accepted from DNS when the SSHFP matches and the zone is signed).

## Testing

`server/internal/dnsrecords` has known-answer tests that cross-check the emitted
fingerprints against `openssl` (TLSA SPKI/cert digests) and `ssh-keygen -r`
(SSHFP), plus owner-name and zone-format tests. The handler tests
(`server/internal/handlers/dnsrecords_handler_test.go`) assert the API surface
end to end. Run them without an HSM:

```console
$ cd server
$ go test ./internal/dnsrecords/...
$ go test -tags sqlite ./internal/handlers/ -run DNSRecords
```
