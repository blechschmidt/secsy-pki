# Fuzz & property testing for parsers and crypto boundaries

secsy-pki ships Go native fuzz tests (`go test -fuzz`) over every surface that
turns **untrusted input** into structured data. These are the places an attacker
gets to hand the server arbitrary bytes, so they are exactly where a panic,
unbounded allocation, or nil-dereference would become a denial-of-service or
worse. The fuzzers back the Task 12 hardening invariants with continuous,
adversarial evidence rather than a one-time review.

## What is fuzzed

| Target | Package | Untrusted surface |
|--------|---------|-------------------|
| `FuzzParseAndVerifyCSR` | `internal/ca` | PEM/DER PKCS#10 CSR decode + self-signature check — the issuance ingress for both the REST API and ACME |
| `FuzzParseCertificatePEM` | `internal/pki` | PEM → DER X.509 certificate parsing (CA config, chain validation) |
| `FuzzParseOCSPRequest` | `internal/pki` | DER OCSP request parsing — public, unauthenticated (POST body and base64 GET path) |
| `FuzzParseJWS` | `internal/acme` | ACME flattened-JSON JOSE/JWS decode + protected-header extraction + JWK thumbprinting (`decodeJWS`) |
| `FuzzACMEPayloads` | `internal/acme` | ACME JSON request payloads (newAccount / newOrder / account-update / keyChange) and the base64url→DER CSR (finalize) and certificate (revoke) decodes |
| `FuzzEnvelopeUnmarshal` | `internal/secret` | JSON secret-envelope parsing (version/algorithm/field validation) |
| `FuzzEnvelopeOpen` | `internal/secret` | Full envelope **decrypt path**: validate → RSA-OAEP unwrap of the DEK → AES-256-GCM open, on adversarial ciphertext material and encryption context |

`FuzzEnvelopeOpen` exercises the real decrypt path against an in-memory RSA
wrapper that mirrors the production HSM-backed wrapper's RSA-OAEP semantics, so
the crypto boundary is fuzzed with **no HSM required** — the same way it runs in
CI.

Each target seeds its corpus with both known-good inputs (a genuine CSR, OCSP
request, signed JWS, sealed envelope, …) and known-malformed inputs (empty,
truncated ASN.1 long-form lengths, wrong PEM block types, undecodable base64,
unknown JSON fields, unsupported versions/algorithms). The invariant asserted is
uniform: **no panic, and never a nil result paired with a nil error.**

## Running locally

One target per invocation is a `go test -fuzz` limitation, so use the helper
that enumerates all of them:

```bash
cd server

# Default: 30s per target.
./scripts/fuzz.sh

# A quick smoke pass (what CI runs).
FUZZTIME=10s ./scripts/fuzz.sh

# A long overnight campaign — the way to actually find deep bugs.
FUZZTIME=30m ./scripts/fuzz.sh

# Drive a single target directly.
./scripts/fuzz.sh ./internal/secret/ FuzzEnvelopeOpen
# …or with raw go:
go test -run '^$' -fuzz='^FuzzEnvelopeOpen$' -fuzztime=5m ./internal/secret/
```

Running the packages as ordinary tests (no `-fuzz`) replays just the seed
corpora — fast and deterministic, and it also reproduces any committed crasher:

```bash
go test ./internal/pki/ ./internal/ca/ ./internal/acme/ ./internal/secret/
```

## When a fuzzer finds a crash

Go writes the offending input to `testdata/fuzz/<Target>/<hash>` under the
target's package and prints a `go test -run=<Target>/<hash>` reproducer.

1. Reproduce and fix the underlying parser/crypto bug.
2. **Commit the `testdata/fuzz/...` file.** It becomes a permanent regression
   seed: from then on the plain `go test` run (and the CI seed-corpora step)
   replays it, so the bug can never silently return.

## CI

`.github/workflows/enterprise-ci.yaml` runs a dedicated `fuzz-smoke` job on
every push/PR to the `main` branch. It needs no SoftHSM (all targets run
in software), and it:

1. replays every seed corpus as unit tests (fails on any committed crasher), then
2. runs each fuzz target for a bounded `FUZZTIME` (20s) to catch regressions the
   mutation engine reaches quickly.

The bounded budget keeps CI fast; deep discovery is the job of the longer local
campaigns above.
