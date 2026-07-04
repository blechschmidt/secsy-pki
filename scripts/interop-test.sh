#!/usr/bin/env bash
#
# interop-test.sh — External-client interop / conformance suite (Task 102).
#
# Stands up a LIVE secsy-pki server backed by SoftHSM and drives it with real,
# independent, third-party client tools — not this project's own Go test client —
# to catch protocol regressions that ad-hoc openssl one-liners miss. Everything
# it needs (a root + issuing CA on the token, a TSA key, a self-signed server TLS
# cert, an EAB credential, a throwaway config) is provisioned into a temporary
# directory and torn down on exit; nothing is installed system-wide and no
# privileged ports or /etc/hosts edits are required.
#
# Coverage:
#   ACME (acme.sh) ....... http-01, tls-alpn-01, dns-01, External Account Binding
#                          (positive + negative), ARI renewalInfo, IP identifiers
#   EST (curl+openssl) ... /cacerts + /simpleenroll (RFC 7030)
#   CMP (openssl cmp) .... ir enrollment with PBM protection (RFC 9483)
#   OCSP (openssl ocsp) .. good -> revoked transition (RFC 6960)
#   CRL (openssl crl) .... base + delta CRL parse/verify, verify -crl_check
#   TSA (openssl ts) ..... RFC 3161 timestamp request + verification
#
# The ACME challenge validation is made hermetic by a bundled authoritative DNS
# server (internal/interop/dnsd): the server's acme.dns_resolver points at it so
# every http-01 / tls-alpn-01 / dns-01 name resolves to the local challenge
# responder. IP identifiers and ARI use a small helper (internal/interop/
# acmeclient) built on golang.org/x/crypto/acme, since acme.sh cannot drive them.
#
# Usage:
#   ./scripts/interop-test.sh              # run the whole suite
#   KEEP=1 ./scripts/interop-test.sh       # keep the work dir + logs for debugging
#
# Environment knobs (all optional):
#   SECSY_INTEROP_PORT       server HTTPS port          (default 8443)
#   SECSY_INTEROP_HTTP01_PORT http-01 responder port    (default 5002)
#   SECSY_INTEROP_ALPN_PORT  tls-alpn-01 responder port (default 5003)
#   SECSY_INTEROP_DNS_PORT   bundled DNS server port    (default 5354)
#   ACME_SH_TAG              acme.sh git tag to test    (default 3.1.0)
#
# Exit status: 0 if every executed check passed, 1 if any failed. Checks whose
# tooling is unavailable are reported as SKIP and do not fail the run.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"

HOST="127.0.0.1"
PORT="${SECSY_INTEROP_PORT:-8443}"
HTTP01_PORT="${SECSY_INTEROP_HTTP01_PORT:-5002}"
ALPN_PORT="${SECSY_INTEROP_ALPN_PORT:-5003}"
DNS_PORT="${SECSY_INTEROP_DNS_PORT:-5354}"
ACME_SH_TAG="${ACME_SH_TAG:-3.1.0}"
SUFFIX="interop.secsy.test"
BASEURL="https://${HOST}:${PORT}"
DIRURL="${BASEURL}/acme/directory"

# Unique per-run key labels so repeated runs against a shared/reused SoftHSM
# token never collide on a CKA_LABEL (which also avoids the duplicate-label
# ECDSA-verify hazard). The subject DNs stay fixed for readability.
RUN_ID="$(openssl rand -hex 3)"
ROOT_LABEL="Interop Root $RUN_ID"
ISSUING_LABEL="Interop Issuing $RUN_ID"
TSA_LABEL="tsa-signer-$RUN_ID"
ISSUING_CN="Interop Issuing CA"
ISSUING_O="Interop"
ROOT_PW="interop-root-$$"
EST_USER="interop-est"
EST_PW="interop-est-pw"
CMP_REF="interop-cmp"
CMP_SECRET="interop-cmp-shared-secret"
EAB_KID="interop-team"

# ---------------------------------------------------------------------------
# Output helpers and PASS/FAIL bookkeeping.
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[1;34m'; C_0=$'\033[0m'; else C_G=; C_R=; C_Y=; C_B=; C_0=; fi
PASS=0; FAIL=0; SKIP=0
FAILED_CHECKS=()

log()     { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
section() { printf '\n%s========== %s ==========%s\n' "$C_B" "$*" "$C_0"; }
ok()      { PASS=$((PASS+1)); printf '  %s✓ PASS%s %s\n' "$C_G" "$C_0" "$*"; }
bad()     { FAIL=$((FAIL+1)); FAILED_CHECKS+=("$*"); printf '  %s✗ FAIL%s %s\n' "$C_R" "$C_0" "$*"; }
skip()    { SKIP=$((SKIP+1)); printf '  %s- SKIP%s %s\n' "$C_Y" "$C_0" "$*"; }

# assert_ok RC DESC — pass when RC == 0.
assert_ok()  { if [[ "$1" -eq 0 ]]; then ok "$2"; else bad "$2"; fi; }
# assert_fail RC DESC — pass when RC != 0 (a negative test that must be rejected).
assert_fail(){ if [[ "$1" -ne 0 ]]; then ok "$2"; else bad "$2 (expected failure, got success)"; fi; }
# assert_grep FILE PATTERN DESC — pass when PATTERN occurs in FILE.
assert_grep(){ if grep -qiE "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi; }

die() { printf '%sFATAL:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Work directory + teardown.
# ---------------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/secsy-interop.XXXXXX")"
BIN="$WORK/bin"; ZONE="$WORK/zone"; ACME_HOME="$WORK/acme-home"
mkdir -p "$BIN" "$ZONE" "$WORK/certs" "$ACME_HOME"
SERVER_PID=""; DNSD_PID=""

cleanup() {
  local rc=$?
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" >/dev/null 2>&1
  [[ -n "$DNSD_PID"   ]] && kill "$DNSD_PID"   >/dev/null 2>&1
  wait >/dev/null 2>&1
  if [[ "${KEEP:-0}" == "1" ]]; then
    echo "KEEP=1 — leaving work dir: $WORK"
  else
    rm -rf "$WORK"
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

CA(){ "$BIN/secsy-ca" -config "$WORK/config.yaml" "$@"; }

# ---------------------------------------------------------------------------
# 1. Record the client tool versions under test (Task 102 requirement).
# ---------------------------------------------------------------------------
section "Client tool versions"
VERS="$WORK/tool-versions.txt"
: > "$VERS"
record_ver() {
  local name="$1"; shift
  local v
  if command -v "${1%% *}" >/dev/null 2>&1; then
    v="$("$@" 2>&1 | head -1)"
  else
    v="(not found)"
  fi
  printf '%-14s %s\n' "$name" "$v" | tee -a "$VERS"
}
record_ver openssl  openssl version
record_ver curl     curl --version
record_ver socat    socat -V
record_ver softhsm  softhsm2-util --version
command -v dig >/dev/null 2>&1 && record_ver dig dig -v || printf '%-14s %s\n' "dig" "(not found)" | tee -a "$VERS"
# go + acme.sh versions are recorded once they are located/cloned below.

# ---------------------------------------------------------------------------
# 2. Go toolchain (system Go bootstraps go.mod's pinned version via GOTOOLCHAIN).
# ---------------------------------------------------------------------------
[[ -d /usr/local/go/bin ]] && export PATH="/usr/local/go/bin:$PATH"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
command -v go >/dev/null 2>&1 || die "go toolchain not found on PATH"
printf '%-14s %s\n' "go" "$(go version)" | tee -a "$VERS"

# ---------------------------------------------------------------------------
# 3. Provision the SoftHSM token and load the PKCS#11 environment.
# ---------------------------------------------------------------------------
section "SoftHSM token"
"$SCRIPT_DIR/setup-softhsm.sh" >/dev/null 2>&1 || die "setup-softhsm.sh failed"
# shellcheck disable=SC1090
eval "$("$SCRIPT_DIR/setup-softhsm.sh" --export-env)"
[[ -n "${SECSY_PKCS11_MODULE:-}" ]] || die "SoftHSM PKCS#11 module not found"
log "module=$SECSY_PKCS11_MODULE token=${SECSY_TOKEN_LABEL:-}"

# ---------------------------------------------------------------------------
# 4. Build the server + CLI + interop helpers.
# ---------------------------------------------------------------------------
section "Build"
(
  cd "$SERVER_DIR" || exit 1
  go build -tags sqlite -o "$BIN/secsy-pki-server" ./cmd/server &&
  go build -tags sqlite -o "$BIN/secsy-ca"         ./cmd/secsy-ca &&
  go build           -o "$BIN/dnsd"                ./internal/interop/dnsd &&
  go build -tags sqlite -o "$BIN/acmeclient"       ./internal/interop/acmeclient
) || die "build failed"
log "built server, secsy-ca, dnsd, acmeclient"

# ---------------------------------------------------------------------------
# 5. Bootstrap CAs, TSA key, TLS cert, EAB key; assemble the server config.
# ---------------------------------------------------------------------------
section "Provision PKI material"

# Minimal config so the CLI can reach the store + key provider (env-driven).
cat > "$WORK/config.yaml" <<EOF
server:
  host: "$HOST"
  port: $PORT
database:
  driver: "sqlite"
  dsn: "$WORK/secsy.db"
key_provider:
  type: "pkcs11"
root_user:
  username: "root"
  password: "$ROOT_PW"
policy:
  allow_root_basic_auth: true
EOF

CA init-root -label "$ROOT_LABEL" -cn "Interop Root CA" -o "$ISSUING_O" \
  -key-type ecdsa-p384 -validity-days 3650 >/dev/null 2>&1 || die "init-root failed"
CA issue-intermediate -parent "$ROOT_LABEL" -label "$ISSUING_LABEL" -cn "$ISSUING_CN" \
  -o "$ISSUING_O" -key-type ecdsa-p256 -validity-days 1825 >/dev/null 2>&1 || die "issue-intermediate failed"
ISSUING_ID="$(CA list 2>/dev/null | awk -v l="$ISSUING_LABEL" 'index($0,l){print $1; exit}')"
[[ -n "$ISSUING_ID" ]] || die "could not resolve issuing CA id"
log "issuing CA id=$ISSUING_ID"

# TSA signing key + certificate (RSA is mandatory for the RFC 3161 signer). The
# -chain output carries [TSA, issuing, root], which we split into reusable files.
CA tsa-key -ca "$ISSUING_LABEL" -label "$TSA_LABEL" -key-type rsa-2048 -cn "Interop TSA" \
  -out "$WORK/tsa.pem" -chain >/dev/null 2>&1 || die "tsa-key failed"
awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > (dir "/tsachain-" n ".pem")}' dir="$WORK" "$WORK/tsa.pem"
cp "$WORK/tsachain-1.pem" "$WORK/tsa-signer.pem"
cp "$WORK/tsachain-2.pem" "$WORK/issuing.pem"
cat "$WORK/tsachain-2.pem" "$WORK/tsachain-3.pem" > "$WORK/ca-chain.pem"

# Self-signed TLS cert for the server (SAN: localhost + 127.0.0.1). Real clients
# are pointed at it via --cacert / -tls_trusted / --insecure.
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/certs/server.key" -out "$WORK/certs/server.crt" -days 3 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:${HOST}" >/dev/null 2>&1 \
  || die "server TLS cert generation failed"

# EAB HMAC key (base64url), shared between the server config and the clients.
EAB_KEY="$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')"

# Full server config: ACME (all 3 challenges + IP identifiers + EAB, pinned DNS),
# EST, CMP, TSA, delta-capable CRLs. OCSP caching is disabled so a revocation is
# reflected on the very next query (protocol conformance over cache behaviour).
cat > "$WORK/config.yaml" <<EOF
server:
  host: "$HOST"
  port: $PORT
  tls_cert: "$WORK/certs/server.crt"
  tls_key: "$WORK/certs/server.key"
  ocsp_cache_ttl_seconds: -1
database:
  driver: "sqlite"
  dsn: "$WORK/secsy.db"
key_provider:
  type: "pkcs11"
root_user:
  username: "root"
  password: "$ROOT_PW"
policy:
  allow_root_basic_auth: true
acme:
  enabled: true
  base_url: "$BASEURL"
  ca_label: "$ISSUING_LABEL"
  profile: "server"
  challenge_types: ["http-01", "dns-01", "tls-alpn-01"]
  allow_ip_identifiers: true
  require_eab: true
  eab_hmac_keys:
    $EAB_KID: "$EAB_KEY"
  http01_port: $HTTP01_PORT
  tls_alpn01_port: $ALPN_PORT
  dns_resolver: "${HOST}:${DNS_PORT}"
est:
  enabled: true
  ca_label: "$ISSUING_LABEL"
  profile: "client"
  users:
    $EST_USER:
      password: "$EST_PW"
cmp:
  enabled: true
  path: "/cmp"
  ca_label: "$ISSUING_LABEL"
  profile: "client"
  allow_signature_protection: true
  secrets:
    - reference: "$CMP_REF"
      secret: "$CMP_SECRET"
      profile: "client"
tsa:
  enabled: true
  path: "/tsa"
  key_label: "$TSA_LABEL"
  certificate_file: "$WORK/tsa.pem"
  ca_label: "$ISSUING_LABEL"
  accepted_hashes: ["sha256", "sha384", "sha512"]
crl:
  shards: 0
  base_url: "$BASEURL"
  delta_interval_minutes: 60
EOF
log "config assembled"

# ---------------------------------------------------------------------------
# 6. Start the bundled DNS server and the live PKI server.
# ---------------------------------------------------------------------------
section "Start services"
"$BIN/dnsd" -listen "${HOST}:${DNS_PORT}" -zone "$ZONE" >"$WORK/dnsd.log" 2>&1 &
DNSD_PID=$!
"$BIN/secsy-pki-server" -config "$WORK/config.yaml" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 40); do
  if curl -fsS --cacert "$WORK/certs/server.crt" "$BASEURL/healthz" >/dev/null 2>&1; then ready=1; break; fi
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 1
done
[[ "$ready" -eq 1 ]] || { echo "--- server.log ---"; tail -30 "$WORK/server.log"; die "server did not become healthy"; }
log "server healthy at $BASEURL"

CURL=(curl -fsS --cacert "$WORK/certs/server.crt")

# ===========================================================================
# ACME — acme.sh (real, independent shell client)
# ===========================================================================
section "ACME (acme.sh) — http-01 / tls-alpn-01 / dns-01 / EAB"

ACME_SH=""
if command -v git >/dev/null 2>&1 && \
   git clone --depth 1 --branch "$ACME_SH_TAG" https://github.com/acmesh-official/acme.sh \
     "$WORK/acme.sh-src" >"$WORK/acme-clone.log" 2>&1; then
  ACME_SH="$WORK/acme.sh-src/acme.sh"
  printf '%-14s %s\n' "acme.sh" "$("$ACME_SH" --version 2>&1 | grep -E '^v' | head -1)" | tee -a "$VERS"
fi

if [[ -z "$ACME_SH" ]]; then
  skip "acme.sh unavailable (clone failed / git missing) — skipping ACME challenge tests"
elif ! command -v socat >/dev/null 2>&1; then
  skip "socat unavailable — skipping acme.sh standalone/alpn challenge tests"
else
  ACME_RUN=("$ACME_SH" --home "$ACME_HOME" --server "$DIRURL" --insecure)

  # DNS hook for dns-01: publishes the TXT challenge into the dnsd zone dir.
  mkdir -p "$ACME_HOME/dnsapi"
  cat > "$ACME_HOME/dnsapi/dns_secsy.sh" <<'HOOK'
#!/usr/bin/env sh
dns_secsy_add() {
  _d="${SECSY_DNS_ZONE:?}"; _n=$(printf '%s' "$1" | sed 's/\.$//' | tr 'A-Z' 'a-z')
  mkdir -p "$_d"; printf '%s\n' "$2" >> "$_d/$_n"
}
dns_secsy_rm() {
  _d="${SECSY_DNS_ZONE:?}"; _n=$(printf '%s' "$1" | sed 's/\.$//' | tr 'A-Z' 'a-z')
  rm -f "$_d/$_n"
}
HOOK

  # EAB registration — positive.
  "${ACME_RUN[@]}" --register-account --eab-kid "$EAB_KID" --eab-hmac-key "$EAB_KEY" \
    >"$WORK/acme-reg.log" 2>&1
  assert_ok $? "ACME newAccount with valid External Account Binding"

  # EAB registration — negative: a wrong HMAC key must be rejected.
  "$ACME_SH" --home "$WORK/acme-home-bad" --server "$DIRURL" --insecure \
    --register-account --eab-kid "$EAB_KID" --eab-hmac-key "AAAA$(openssl rand 24 | openssl base64 -A | tr '+/' '-_' | tr -d '=')" \
    >"$WORK/acme-reg-bad.log" 2>&1
  assert_fail $? "ACME newAccount with invalid EAB key is rejected"

  # verify_issued DOMAIN CERT DESC — issued leaf must chain to the CA and name it.
  verify_issued() {
    local dom="$1" crt="$2" desc="$3"
    if [[ -f "$crt" ]] && openssl verify -CAfile "$WORK/ca-chain.pem" "$crt" >/dev/null 2>&1 &&
       openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -qi "$dom"; then
      ok "$desc (issued cert verifies + names $dom)"
    else
      bad "$desc"
    fi
  }

  # http-01 (standalone responder on a non-privileged port).
  D="http01.$SUFFIX"
  "${ACME_RUN[@]}" --issue --standalone --httpport "$HTTP01_PORT" -d "$D" --force \
    >"$WORK/acme-http01.log" 2>&1
  verify_issued "$D" "$ACME_HOME/${D}_ecc/${D}.cer" "ACME http-01 issuance"

  # tls-alpn-01 (acme-tls/1 responder on a non-privileged port).
  D="alpn.$SUFFIX"
  "${ACME_RUN[@]}" --issue --alpn --tlsport "$ALPN_PORT" -d "$D" --force \
    >"$WORK/acme-alpn.log" 2>&1
  verify_issued "$D" "$ACME_HOME/${D}_ecc/${D}.cer" "ACME tls-alpn-01 issuance"

  # dns-01 (custom hook -> dnsd; server resolves TXT via acme.dns_resolver).
  D="dns01.$SUFFIX"
  : > "$ZONE/_acme-challenge.$D"
  SECSY_DNS_ZONE="$ZONE" "${ACME_RUN[@]}" --issue --dns dns_secsy -d "$D" --dnssleep 3 --force \
    >"$WORK/acme-dns01.log" 2>&1
  verify_issued "$D" "$ACME_HOME/${D}_ecc/${D}.cer" "ACME dns-01 issuance"

  # ARI renewalInfo for the http-01 cert: valid CertID -> suggestedWindow + Retry-After.
  HTTP01_CERT="$ACME_HOME/http01.${SUFFIX}_ecc/http01.${SUFFIX}.cer"
  if [[ -f "$HTTP01_CERT" ]]; then
    CERTID="$("$BIN/acmeclient" -mode certid -cert "$HTTP01_CERT" 2>/dev/null)"
    if [[ -n "$CERTID" ]] && "${CURL[@]}" -D "$WORK/ari-hdrs.txt" "$BASEURL/acme/renewal-info/$CERTID" -o "$WORK/ari.json" 2>/dev/null; then
      if grep -qi "retry-after" "$WORK/ari-hdrs.txt" && grep -q "suggestedWindow" "$WORK/ari.json"; then
        ok "ACME ARI renewalInfo (suggestedWindow + Retry-After)"
      else
        bad "ACME ARI renewalInfo response shape"
      fi
    else
      bad "ACME ARI renewalInfo request"
    fi
  else
    skip "ACME ARI (no http-01 cert to look up)"
  fi
fi

# IP identifiers (RFC 8738) via the x/crypto/acme helper — acme.sh cannot do these.
if "$BIN/acmeclient" -mode iporder -dir "$DIRURL" -eab-kid "$EAB_KID" -eab-hmac "$EAB_KEY" \
     -ip "$HOST" -http-port "$HTTP01_PORT" -cafile "$WORK/certs/server.crt" \
     -certout "$WORK/ip-cert.pem" >"$WORK/acme-ip.log" 2>&1 &&
   openssl x509 -in "$WORK/ip-cert.pem" -noout -ext subjectAltName 2>/dev/null | grep -qi "IP Address:$HOST"; then
  ok "ACME IP-identifier issuance (RFC 8738, EAB)"
else
  bad "ACME IP-identifier issuance"; tail -3 "$WORK/acme-ip.log" 2>/dev/null | sed 's/^/     /'
fi

# ===========================================================================
# EST (RFC 7030) — curl + openssl as a native client
# ===========================================================================
section "EST (curl + openssl)"

# cacerts: the CA chain as a certs-only PKCS#7 (base64).
if "${CURL[@]}" "$BASEURL/.well-known/est/cacerts" -o "$WORK/est-cacerts.p7.b64" 2>/dev/null &&
   tr -d '\r\n' < "$WORK/est-cacerts.p7.b64" | openssl base64 -d -A 2>/dev/null | \
     openssl pkcs7 -inform DER -print_certs 2>/dev/null | grep -qi "$ISSUING_CN"; then
  ok "EST /cacerts returns the CA chain"
else
  bad "EST /cacerts"
fi

# simpleenroll: base64(DER CSR) with HTTP Basic auth -> base64 PKCS#7 leaf+chain.
openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/est.key" -out "$WORK/est.csr" \
  -subj "/CN=est-device.$SUFFIX" >/dev/null 2>&1
openssl req -in "$WORK/est.csr" -outform DER | openssl base64 -A > "$WORK/est.csr.b64"
EST_CODE="$(curl -s -o "$WORK/est-resp.b64" -w '%{http_code}' --cacert "$WORK/certs/server.crt" \
  -u "$EST_USER:$EST_PW" -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
  --data @"$WORK/est.csr.b64" "$BASEURL/.well-known/est/simpleenroll")"
# EST wraps the response base64 in CRLF lines; strip them before decoding.
tr -d '\r\n' < "$WORK/est-resp.b64" | openssl base64 -d -A 2>/dev/null > "$WORK/est-resp.der"
if [[ "$EST_CODE" == "200" ]] && \
   openssl pkcs7 -inform DER -in "$WORK/est-resp.der" -print_certs -out "$WORK/est-leaf.pem" 2>/dev/null && \
   openssl verify -CAfile "$WORK/ca-chain.pem" "$WORK/est-leaf.pem" >/dev/null 2>&1; then
  ok "EST /simpleenroll issues a verifiable certificate"
else
  bad "EST /simpleenroll (HTTP $EST_CODE)"
fi

# csrattrs: base64 DER SEQUENCE OF AttrOrOID advertising the profile's expected
# CSR attributes. The interop CA uses the "client" profile, so the advertisement
# derives an id-ecPublicKey key-type hint and a clientAuth extended key usage.
if "${CURL[@]}" "$BASEURL/.well-known/est/csrattrs" -o "$WORK/est-csrattrs.b64" 2>/dev/null &&
   tr -d '\r\n' < "$WORK/est-csrattrs.b64" | openssl base64 -d -A 2>/dev/null > "$WORK/est-csrattrs.der" &&
   openssl asn1parse -inform DER -in "$WORK/est-csrattrs.der" 2>/dev/null | grep -q "id-ecPublicKey"; then
  ok "EST /csrattrs advertises CSR attributes (RFC 7030 §4.5)"
else
  bad "EST /csrattrs"
fi

# ===========================================================================
# CMP (RFC 9483) — openssl cmp
# ===========================================================================
section "CMP (openssl cmp)"
if openssl cmp -help >/dev/null 2>&1; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/cmp.key" >/dev/null 2>&1
  openssl cmp -cmd ir \
    -server "$BASEURL/cmp" \
    -ref "$CMP_REF" -secret "pass:$CMP_SECRET" \
    -recipient "/O=$ISSUING_O/CN=$ISSUING_CN" \
    -subject "/CN=cmp-device.$SUFFIX" \
    -newkey "$WORK/cmp.key" -certout "$WORK/cmp.crt" -out_trusted "$WORK/ca-chain.pem" \
    -tls_used -tls_trusted "$WORK/certs/server.crt" \
    -implicit_confirm -msg_timeout 20 >"$WORK/cmp.log" 2>&1
  if [[ -f "$WORK/cmp.crt" ]] && openssl verify -CAfile "$WORK/ca-chain.pem" "$WORK/cmp.crt" >/dev/null 2>&1; then
    ok "CMP ir (PBM) issues a verifiable certificate"
  else
    bad "CMP ir enrollment"; tail -3 "$WORK/cmp.log" | sed 's/^/     /'
  fi
else
  skip "openssl cmp subcommand unavailable"
fi

# ===========================================================================
# OCSP (RFC 6960) — openssl ocsp, good -> revoked
# ===========================================================================
section "OCSP + CRL (openssl ocsp / openssl crl)"

# Issue a fresh leaf to exercise revocation status.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/leaf.key" -out "$WORK/leaf.csr" -subj "/CN=status-leaf.$SUFFIX" >/dev/null 2>&1
CA issue -ca "$ISSUING_LABEL" -csr "$WORK/leaf.csr" -profile server -out "$WORK/leaf.crt" \
  >"$WORK/issue.log" 2>&1 || bad "issue status leaf"
# Hex serial for CRL grepping; decimal serial (taken verbatim from the issuer, so
# a 128-bit value is exact — bash printf would overflow) for the revoke API.
LEAF_HEX="$(openssl x509 -in "$WORK/leaf.crt" -noout -serial 2>/dev/null | cut -d= -f2)"
LEAF_DEC="$(sed -n 's/.*serial=\([0-9][0-9]*\).*/\1/p' "$WORK/issue.log")"

# Prime the base CRL BEFORE revoking: a delta CRL lists changes since the current
# base, so the revocation below must land in the delta rather than be folded into
# a first-ever base generated after the fact.
"${CURL[@]}" "$BASEURL/api/ca/$ISSUING_ID/crl" -o "$WORK/base-pre.crl" 2>/dev/null || true

ocsp_status() { # writes the openssl ocsp text to $1
  openssl ocsp -issuer "$WORK/issuing.pem" -cert "$WORK/leaf.crt" -reqout "$WORK/ocsp-req.der" -no_nonce >/dev/null 2>&1
  "${CURL[@]}" -H "Content-Type: application/ocsp-request" --data-binary @"$WORK/ocsp-req.der" \
    "$BASEURL/api/ca/$ISSUING_ID/ocsp" -o "$WORK/ocsp-resp.der" 2>/dev/null
  openssl ocsp -respin "$WORK/ocsp-resp.der" -issuer "$WORK/issuing.pem" -cert "$WORK/leaf.crt" \
    -CAfile "$WORK/ca-chain.pem" > "$1" 2>&1
}

ocsp_status "$WORK/ocsp-good.txt"
if grep -qi "Response verify OK" "$WORK/ocsp-good.txt" && grep -qiE "leaf.crt: good|: good" "$WORK/ocsp-good.txt"; then
  ok "OCSP reports 'good' for a valid certificate (signature verifies)"
else
  bad "OCSP good status"
fi

# Revoke through the live REST API so the running server invalidates its state.
"${CURL[@]}" -u "root:$ROOT_PW" -H "Content-Type: application/json" -X POST \
  "$BASEURL/api/ca/$ISSUING_ID/revoke" -d "{\"serial\":\"$LEAF_DEC\",\"reason\":\"keyCompromise\"}" \
  >"$WORK/revoke.log" 2>&1
assert_grep "$WORK/revoke.log" '"status":"(revoked|already-revoked)"' "REST revoke accepted"

ocsp_status "$WORK/ocsp-revoked.txt"
if grep -qi "Response verify OK" "$WORK/ocsp-revoked.txt" && grep -qi "revoked" "$WORK/ocsp-revoked.txt"; then
  ok "OCSP reports 'revoked' after revocation"
else
  bad "OCSP revoked status"
fi

# ---- CRL: base signature verify, delta indicator + serial, verify -crl_check ----
if "${CURL[@]}" "$BASEURL/api/ca/$ISSUING_ID/crl" -o "$WORK/base.crl" 2>/dev/null &&
   openssl crl -inform DER -in "$WORK/base.crl" -noout -verify -CAfile "$WORK/ca-chain.pem" >/dev/null 2>&1; then
  ok "CRL base is signed by the issuing CA (openssl crl -verify)"
else
  bad "CRL base signature verification"
fi

if "${CURL[@]}" "$BASEURL/api/ca/$ISSUING_ID/crl/delta" -o "$WORK/delta.crl" 2>/dev/null; then
  openssl crl -inform DER -in "$WORK/delta.crl" -noout -text > "$WORK/delta.txt" 2>&1
  if grep -qi "Delta CRL Indicator" "$WORK/delta.txt" && grep -qi "$LEAF_HEX" "$WORK/delta.txt"; then
    ok "Delta CRL carries the Delta CRL Indicator and lists the revoked serial"
  else
    bad "Delta CRL content (indicator + revoked serial)"
  fi
else
  bad "Delta CRL fetch"
fi

# A freshly generated base CRL (CLI) contains the revocation; openssl must treat
# the leaf as revoked when checked against it.
CA gen-crl -ca "$ISSUING_LABEL" -out "$WORK/fresh-base.crl.pem" >/dev/null 2>&1
openssl verify -crl_check -CAfile "$WORK/ca-chain.pem" -CRLfile "$WORK/fresh-base.crl.pem" "$WORK/leaf.crt" \
  > "$WORK/crlcheck.txt" 2>&1
assert_grep "$WORK/crlcheck.txt" "certificate revoked" "openssl verify -crl_check reports the leaf revoked"

# ===========================================================================
# TSA (RFC 3161) — openssl ts
# ===========================================================================
section "TSA (openssl ts)"
echo "interop timestamp payload $$" > "$WORK/ts-data.txt"
if openssl ts -query -data "$WORK/ts-data.txt" -sha256 -cert -out "$WORK/ts.tsq" >/dev/null 2>&1 &&
   "${CURL[@]}" -H "Content-Type: application/timestamp-query" --data-binary @"$WORK/ts.tsq" \
     "$BASEURL/tsa" -o "$WORK/ts.tsr" 2>/dev/null; then
  openssl ts -reply -in "$WORK/ts.tsr" -text > "$WORK/ts-reply.txt" 2>&1
  if grep -qi "Status: Granted" "$WORK/ts-reply.txt" &&
     openssl ts -verify -data "$WORK/ts-data.txt" -in "$WORK/ts.tsr" -CAfile "$WORK/ca-chain.pem" \
       > "$WORK/ts-verify.txt" 2>&1 &&
     grep -qi "Verification: OK" "$WORK/ts-verify.txt"; then
    ok "TSA timestamp granted and openssl ts -verify succeeds"
  else
    bad "TSA token verification"
  fi
else
  bad "TSA timestamp request"
fi

# ===========================================================================
# Summary
# ===========================================================================
section "Summary"
echo "Client tool versions used:"
sed 's/^/  /' "$VERS"
echo
printf '%sPASS=%d  FAIL=%d  SKIP=%d%s\n' "$C_B" "$PASS" "$FAIL" "$SKIP" "$C_0"
if [[ "$FAIL" -gt 0 ]]; then
  printf '%sFailed checks:%s\n' "$C_R" "$C_0"
  for f in "${FAILED_CHECKS[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "All executed interop checks passed."
exit 0
