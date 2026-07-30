#!/usr/bin/env bash
# Verify a Secsy PKI release signature with standard tooling — no server, no
# HSM, only public trust anchors. Run this anywhere a consumer wants to confirm
# an artifact was signed by your PKI's code-signing key.
#
# Usage:
#   verify-signature.sh <artifact> <artifact.p7s> <root-ca.pem>
#
# <artifact.p7s> is the DETACHED CMS signature (DER) produced by the workflow;
# <root-ca.pem> is your PKI root (the trust anchor consumers pin out of band).
set -euo pipefail

ARTIFACT="${1:?usage: verify-signature.sh <artifact> <artifact.p7s> <root-ca.pem>}"
SIG="${2:?missing detached signature (.p7s)}"
ROOT="${3:?missing root CA PEM}"

# -binary: don't do S/MIME CRLF canonicalization; the signature is over raw bytes.
# -inform DER: the workflow saved the DER signature.
# -content: the detached artifact whose digest the signature covers.
# -purpose any: openssl's default S/MIME purpose check rejects codeSigning EKUs.
if openssl cms -verify -binary -inform DER -in "$SIG" \
        -content "$ARTIFACT" -CAfile "$ROOT" -purpose any -out /dev/null 2>/tmp/cms.err; then
    echo "OK: $ARTIFACT verifies against $ROOT"
else
    echo "FAIL: signature did not verify" >&2
    cat /tmp/cms.err >&2
    exit 1
fi

# The embedded RFC 3161 timestamp keeps the signature valid after the signing
# certificate expires. `secsy-ca verify-signature` checks it end-to-end and
# prints the token's genTime + TSA chain:
#
#   secsy-ca verify-signature -sig "$SIG" -in "$ARTIFACT" \
#       -ca-file "$ROOT" -require-timestamp
