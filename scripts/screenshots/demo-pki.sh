#!/usr/bin/env bash
#
# demo-pki.sh — build, seed and run a throwaway secsy-pki for the documentation
# screenshots, then destroy it.
#
#     ./scripts/screenshots/demo-pki.sh up      # prints the base URL on stdout
#     ./scripts/screenshots/demo-pki.sh down
#
# Everything this touches lives under $SHOT_HOME (/tmp/secsy-pki-shots): its own
# SoftHSM token directory and SOFTHSM2_CONF, its own SQLite database, its own
# config file and its own port. A developer's own SoftHSM token, database and
# running server are neither read nor written, so regenerating the screenshots
# cannot photograph — or disturb — real material.
#
# The PKI it builds belongs to an invented company, "Northwind Logistics GmbH",
# under .example names (RFC 2606). Nothing in the images is anyone's.
#
# See README.md in this directory for why the screenshots are taken this way.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

SHOT_HOME=${SHOT_HOME:-/tmp/secsy-pki-shots}
PORT=${SHOT_PORT:-9443}
BASE="https://127.0.0.1:$PORT"

BIN=$SHOT_HOME/bin
WORK=$SHOT_HOME/work                 # throwaway subject keys and CSRs
CONF=$SHOT_HOME/config.yaml
export SOFTHSM2_CONF=$SHOT_HOME/softhsm2.conf

TOKEN_LABEL=secsy-shots
USER_PIN=1234
SO_PIN=5678

# Not a secret: this account exists for the length of one capture run, on a
# listener bound to 127.0.0.1, and is destroyed with the rest of the tree.
ROOT_PASSWORD=${SHOT_ROOT_PASSWORD:-demo-console-password}

CA() { "$BIN/secsy-ca" -config "$CONF" "$@"; }
SECRET() { "$BIN/secsy-secret" -config "$CONF" "$@"; }

log() { echo "==> $*" >&2; }
quiet() { "$@" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# down — stop the server and remove every trace of the demo.
# ---------------------------------------------------------------------------
cmd_down() {
  if [ -f "$SHOT_HOME/server.pid" ]; then
    local pid
    pid=$(cat "$SHOT_HOME/server.pid")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  # Anything still holding the port, or any demo server from a run killed
  # mid-flight. Matched on this demo's own config path so a developer's real
  # secsy-pki server is never a candidate.
  pkill -f "server -config $SHOT_HOME/config.yaml" 2>/dev/null || true
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "$PORT/tcp" >/dev/null 2>&1 || true
  fi
  rm -rf "$SHOT_HOME"
  log "demo PKI removed"
}

# ---------------------------------------------------------------------------
# find_module — locate the SoftHSM PKCS#11 library.
# ---------------------------------------------------------------------------
find_module() {
  local c
  for c in /usr/lib/softhsm/libsofthsm2.so \
           /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
           /usr/lib64/pkcs11/libsofthsm2.so \
           /usr/lib/pkcs11/libsofthsm2.so \
           /usr/local/lib/softhsm/libsofthsm2.so \
           /opt/homebrew/lib/softhsm/libsofthsm2.so; do
    [ -f "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# build — the server and both CLIs, into the demo's own bin directory.
# ---------------------------------------------------------------------------
build() {
  log "building server + CLIs"
  [ -d /usr/local/go/bin ] && export PATH="/usr/local/go/bin:$PATH"
  mkdir -p "$BIN"
  (
    cd "$ROOT/server"
    go build -tags sqlite -o "$BIN/server" ./cmd/server
    go build -tags sqlite -o "$BIN/secsy-ca" ./cmd/secsy-ca
    go build -tags sqlite -o "$BIN/secsy-secret" ./cmd/secsy-secret
  )
}

# ---------------------------------------------------------------------------
# token — a SoftHSM token of the demo's own, in the demo's own directory.
# ---------------------------------------------------------------------------
token() {
  local module
  module=$(find_module) || { echo "SoftHSM not found; install softhsm2" >&2; exit 1; }
  log "initializing SoftHSM token $TOKEN_LABEL"
  mkdir -p "$SHOT_HOME/tokens"
  cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $SHOT_HOME/tokens
objectstore.backend = file
log.level = ERROR
EOF
  quiet softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
    --so-pin "$SO_PIN" --pin "$USER_PIN"
  echo "$module"
}

# ---------------------------------------------------------------------------
# config — the demo server's configuration.
#
# Features are switched on because the console has a page for them and a page
# photographed in its "not configured" state teaches nothing. The serving
# certificate is issued by this PKI's own TLS CA (server.tls.self_issue), which
# is both the production-shaped choice and one less thing to generate.
#
# Written in two stages. `tsa:` and `signing:` point at certificates that
# `secsy-ca tsa-key` / `signing-key` produce, and the config refuses to load
# while they are missing — but those commands need a config that loads. So the
# base config below omits both blocks and config_extend appends them once the
# provisioning has run (see seed_signing).
#
# The listener certificate is issued up front, to files, rather than with
# server.tls.self_issue. self_issue is the better choice in production and one
# line instead of a function — but it generates its key *inside the token at
# startup*, and a SoftHSM file-store write while the server's own session pool is
# already open invalidates the handles that pool holds, which breaks the
# listener minutes later. Issuing it beforehand keeps the token read-only for
# the whole of the capture run.
# ---------------------------------------------------------------------------
config() {
  local module=$1
  log "writing $CONF"
  cat > "$CONF" <<EOF
# Generated by scripts/screenshots/demo-pki.sh. Throwaway: do not copy as a
# production starting point — server/config.yaml is the annotated reference.
server:
  host: "127.0.0.1"
  port: $PORT
  # Issued from this PKI's own TLS CA by seed_serving, which runs before the
  # server does. The CLIs never open these, so naming them here is safe even
  # while they are still missing.
  tls_cert: "$SHOT_HOME/serving.crt"
  tls_key: "$SHOT_HOME/serving.key"

database:
  driver: "sqlite"
  dsn: "$SHOT_HOME/secsy-pki.db"

root_user:
  username: "root"
  password: "$ROOT_PASSWORD"

key_provider:
  type: "pkcs11"

pkcs11:
  module_path: "$module"
  token_label: "$TOKEN_LABEL"
  pin: "$USER_PIN"
  session_pool_size: 8

secret:
  kek_label: "northwind-kek"
  transforms:
    - name: "shipment-ref"
      alphabet: "digits"
      min_length: 8

policy:
  max_cert_validity_days: 397

monitor:
  enabled: true
  warning_days: 30
  critical_days: 7

acme:
  enabled: true
  base_url: "https://pki.northwind.example"
  ca_label: "northwind-issuing-tls"
  challenge_types: ["http-01", "dns-01", "tls-alpn-01"]

spiffe:
  enabled: true
  trust_domains: ["northwind.example"]
  default_ca_id: "northwind-issuing-workload"

ssh:
  krl_comment: "Northwind Logistics ops SSH CA"
  profiles:
    - name: operator
      description: "Interactive operator SSH login"
      cert_type: user
      default_validity: 8h
      max_validity: 24h
      max_principals: 4
      default_extensions:
        permit-pty: ""
      allowed_critical_options: ["source-address"]

crl:
  base_url: "https://crl.northwind.example"
  shards: 2

webhook:
  enabled: true

discovery:
  enabled: false

tenants:
  - id: "forwarding"
    slug: "forwarding"
    name: "Northwind Forwarding (subsidiary)"
EOF
}

# ---------------------------------------------------------------------------
# seed — build the hierarchy and fill it with work.
#
# Everything here goes through the shipped CLIs, so the data in the screenshots
# is data the product produced: real HSM-signed certificates with real serials,
# a real hash-chained audit log, a real CRL.
# ---------------------------------------------------------------------------

# leaf <ca> <profile> <cn> <sans> <validity-days> — generate a subject key and
# CSR, then have the CA sign it. Prints the serial.
leaf() {
  local caid=$1 profile=$2 cn=$3 sans=$4 days=$5
  local stem="$WORK/$(echo "$cn" | tr -cd 'a-zA-Z0-9.@_-')"
  local sanflag=()
  [ -n "$sans" ] && sanflag=(-addext "subjectAltName=$sans")
  quiet openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$stem.key" -out "$stem.csr" \
    -subj "/CN=$cn/O=Northwind Logistics GmbH" "${sanflag[@]}"
  CA issue -ca "$caid" -profile "$profile" -csr "$stem.csr" \
    -validity-days "$days" -out "$stem.crt" >/dev/null 2>&1 || return 1
  openssl x509 -in "$stem.crt" -noout -serial | sed 's/serial=//' |
    python3 -c 'import sys; print(int(sys.stdin.read().strip(), 16))'
}

seed_cas() {
  log "seeding the CA hierarchy"
  quiet CA init-root -label northwind-root \
    -cn "Northwind Logistics Root CA R1" -o "Northwind Logistics GmbH" -c DE \
    -key-type ecdsa-p384 -validity-days 7300

  quiet CA issue-intermediate -parent northwind-root -label northwind-issuing-tls \
    -cn "Northwind Logistics TLS Issuing CA G2" -o "Northwind Logistics GmbH" \
    -ou "Public Trust Services" -c DE -key-type ecdsa-p256 -validity-days 1825
  quiet CA issue-intermediate -parent northwind-root -label northwind-issuing-device \
    -cn "Northwind Logistics Device Issuing CA G1" -o "Northwind Logistics GmbH" \
    -ou "Fleet Operations" -c DE -key-type ecdsa-p256 -validity-days 1825
  quiet CA issue-intermediate -parent northwind-root -label northwind-issuing-workload \
    -cn "Northwind Logistics Workload Issuing CA G1" -o "Northwind Logistics GmbH" \
    -ou "Platform Engineering" -c DE -key-type ecdsa-p256 -validity-days 1825
}

seed_certs() {
  log "issuing end-entity certificates"
  mkdir -p "$WORK"

  # The TLS estate, deliberately spread across the expiry monitor's bands: one
  # inside the critical window, one inside the warning window, the rest clear.
  S_GATEWAY=$(leaf northwind-issuing-tls server-client gateway.northwind.example \
    "DNS:gateway.northwind.example" 5)
  S_API=$(leaf northwind-issuing-tls server api.northwind.example \
    "DNS:api.northwind.example,DNS:api-eu.northwind.example" 25)
  leaf northwind-issuing-tls server wms.northwind.example \
    "DNS:wms.northwind.example,DNS:www.wms.northwind.example" 90 >/dev/null
  leaf northwind-issuing-tls server track.northwind.example \
    "DNS:track.northwind.example" 180 >/dev/null
  leaf northwind-issuing-tls server-muststaple payments.northwind.example \
    "DNS:payments.northwind.example" 365 >/dev/null
  leaf northwind-issuing-tls server-delegation edge.northwind.example \
    "DNS:edge.northwind.example,DNS:edge-fra.northwind.example" 90 >/dev/null
  S_STAGING=$(leaf northwind-issuing-tls server staging.northwind.example \
    "DNS:staging.northwind.example" 90)
  S_LEGACY=$(leaf northwind-issuing-tls server legacy-portal.northwind.example \
    "DNS:legacy-portal.northwind.example" 120)
  S_HOLD=$(leaf northwind-issuing-tls server reporting.northwind.example \
    "DNS:reporting.northwind.example" 150)
  S_RENEW=$(leaf northwind-issuing-tls server depot-fra.northwind.example \
    "DNS:depot-fra.northwind.example" 60)

  # The device fleet: mTLS client certificates for handheld scanners and the
  # trucks' telematics units.
  for n in 0418 0419 0423 0571; do
    leaf northwind-issuing-device client "scanner-$n.fleet.northwind.example" \
      "DNS:scanner-$n.fleet.northwind.example" 365 >/dev/null
  done
  leaf northwind-issuing-device client "telematics-tr-882.fleet.northwind.example" \
    "DNS:telematics-tr-882.fleet.northwind.example" 365 >/dev/null
  S_SCANNER=$(leaf northwind-issuing-device client scanner-0288.fleet.northwind.example \
    "DNS:scanner-0288.fleet.northwind.example" 365)

  # Platform workloads.
  for svc in orders-api inventory-sync label-printer; do
    leaf northwind-issuing-workload server-client "$svc.svc.northwind.example" \
      "DNS:$svc.svc.northwind.example" 30 >/dev/null
  done

  # An S/MIME certificate, so the profile mix is not all serverAuth.
  leaf northwind-issuing-tls smime-sign "m.okonkwo@northwind.example" \
    "email:m.okonkwo@northwind.example" 365 >/dev/null

  # One CSR left deliberately unsigned. The walkthrough photographs the
  # pre-issuance dry run, and a dry run of a request that was already issued
  # would be a dry run of nothing.
  quiet openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$WORK/preview-request.key" -out "$WORK/preview-request.csr" \
    -subj "/CN=depot-ams.northwind.example/O=Northwind Logistics GmbH" \
    -addext "subjectAltName=DNS:depot-ams.northwind.example,DNS:depot-ams-2.northwind.example"
}

seed_lifecycle() {
  log "revoking, suspending and renewing"
  # A decommissioned host and a scanner whose key leaked: two different reasons,
  # so the CRL and the status filters have both to show.
  quiet CA revoke -ca northwind-issuing-tls -serial "$S_LEGACY" -reason cessationOfOperation
  quiet CA revoke -ca northwind-issuing-device -serial "$S_SCANNER" -reason keyCompromise
  # A host taken out of service for an investigation — reversible.
  quiet CA suspend -ca northwind-issuing-tls -serial "$S_HOLD" || true
  # And one renewed, which leaves the superseded serial beside its replacement.
  quiet CA renew -ca northwind-issuing-tls -serial "$S_RENEW" || true

  log "generating CRLs"
  quiet CA gen-crl -ca northwind-issuing-tls || true
  quiet CA gen-crl -ca northwind-issuing-device || true
  quiet CA gen-crl -ca northwind-issuing-workload || true
}

seed_ssh() {
  log "seeding the SSH CA"
  # -max-validity is the CA-level ceiling: whatever a profile or a caller asks
  # for, this authority signs nothing longer-lived than 12h.
  quiet CA ssh ca-init -label northwind-ssh-ops -key-type ed25519 -max-validity 12h || return 0
  mkdir -p "$WORK/ssh"
  for u in m.okonkwo j.lindqvist; do
    quiet ssh-keygen -q -t ed25519 -N '' -C "$u" -f "$WORK/ssh/$u"
    quiet CA ssh sign-user -ca northwind-ssh-ops -profile operator \
      -principals "$u" -pub "$WORK/ssh/$u.pub" -out "$WORK/ssh/$u-cert.pub" || true
  done
  quiet ssh-keygen -q -t ed25519 -N '' -C bastion -f "$WORK/ssh/bastion_host"
  quiet CA ssh sign-host -ca northwind-ssh-ops \
    -principals "bastion.northwind.example" -pub "$WORK/ssh/bastion_host.pub" \
    -out "$WORK/ssh/bastion_host-cert.pub" || true
}

# seed_signing provisions the artifact-signing and timestamping credentials,
# then switches both subsystems on. The order is forced: each key's certificate
# has to exist on disk before the config block naming it will load.
seed_signing() {
  log "provisioning the code-signing and TSA keys"
  quiet CA signing-key -ca northwind-issuing-tls -label northwind-codesign \
    -cn "Northwind Logistics Release Signing" -o "Northwind Logistics GmbH" \
    -out "$SHOT_HOME/codesign.crt" || return 0
  quiet CA tsa-key -ca northwind-issuing-tls -label northwind-tsa \
    -cn "Northwind Logistics Timestamping Authority" \
    -out "$SHOT_HOME/tsa.crt" || return 0
  seed_serving
  config_extend
}

# seed_serving issues the listener certificate from this PKI's own TLS CA. The
# private key is generated by openssl and stays on disk, which is what
# server.tls_cert / tls_key means — and what keeps the token read-only once the
# server is up.
seed_serving() {
  log "issuing the listener certificate"
  quiet openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$SHOT_HOME/serving.key" -out "$WORK/serving.csr" \
    -subj "/CN=localhost/O=Northwind Logistics GmbH" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  CA issue -ca northwind-issuing-tls -profile server -csr "$WORK/serving.csr" \
    -validity-days 90 -chain -out "$SHOT_HOME/serving.crt" >/dev/null 2>&1
}

# config_extend appends the blocks that could not be in the base config.
config_extend() {
  log "enabling the TSA and artifact signing"
  cat >> "$CONF" <<EOF

# Appended once the keys below existed — see the note on config() above.
tsa:
  enabled: true
  key_label: "northwind-tsa"
  certificate_file: "$SHOT_HOME/tsa.crt"
  ca_label: "northwind-issuing-tls"
  policy_oid: "1.3.6.1.4.1.99999.1.1"

signing:
  enabled: true
  signers:
    - name: "release-signing"
      key_label: "northwind-codesign"
      certificate_file: "$SHOT_HOME/codesign.crt"
      ca_label: "northwind-issuing-tls"
      digest: "sha256"
      level: "T"
      timestamp: true
EOF
}

seed_secrets() {
  log "seeding the secret layer"
  # The KEK every stored secret's data key is wrapped under. It is generated
  # inside the token and never leaves it.
  quiet SECRET init-kek -key-type rsa-2048 || true
  # put reads the value from stdin, and arms the TTL / rotation reminders that
  # the Lifecycle attention table is built from.
  head -c 18 /dev/urandom | base64 |
    quiet SECRET put -name "wms/db-password" -rotate-every-days 90 -comment "initial import"
  head -c 18 /dev/urandom | base64 |
    quiet SECRET put -name "carrier-api/dhl-token" -ttl-days 30 -comment "carrier portal token"
  head -c 18 /dev/urandom | base64 |
    quiet SECRET put -name "smtp/relay-password" -rotate-every-days 180
  # A second version of one of them, so the version history and the rollback
  # control have something to act on.
  head -c 18 /dev/urandom | base64 |
    quiet SECRET put -name "wms/db-password" -comment "rotated after staff change"
}

seed_access() {
  log "seeding tokens, grants and subscriptions"
  quiet CA token create -name "deploy-robot" -roles issuer -expires-days 90 || true
  quiet CA token create -name "siem-exporter" -roles auditor -expires-days 30 || true
  # Task 191: a group that administers exactly one sub-CA. Grants name the
  # resource by id, so resolve the label the hierarchy was seeded under.
  local device_ca
  device_ca=$(CA list 2>/dev/null | awk '$2 == "northwind-issuing-device" { print $1 }')
  if [ -n "$device_ca" ]; then
    quiet CA grant add -group fleet-ops -resource "ca/$device_ca" -role ca-admin || true
  fi
  quiet CA webhook create -url "https://events.northwind.example/pki" \
    -events cert.issue,cert.revoke || true
  # A key known to be compromised, refused fail-closed at issuance. The
  # blocklist stores only the SubjectPublicKeyInfo fingerprint, so an invented
  # one needs no key to exist.
  quiet CA blocked-keys add -fingerprint \
    "SHA256:$(printf 'northwind-leaked-demo-key' | openssl dgst -sha256 -binary | base64)" \
    -reason "Reported in vendor advisory NW-2026-0007" || true
}

seed_audit() {
  log "anchoring the audit chain"
  quiet CA audit verify || true
  quiet CA audit anchor || true
}

# ---------------------------------------------------------------------------
# seed_restrictions — the ceiling an SSH signing request may not exceed.
#
# Restriction sets are the one capability with no secsy-ca subcommand: the REST
# API and the console are the whole surface. So this seeds over HTTP, which is
# why it is the only seeder that has to run *after* serve() rather than against
# the database directly like every one above it.
#
# What it writes is a policy with a shape worth photographing: a permissive
# global default for human operators, a far tighter per-CA set for CI, and one
# X.509 set — because the view's standing warning is that X.509 sets are stored
# and enforced by nothing, and a warning with no row under it reads as
# hypothetical.
# ---------------------------------------------------------------------------
RS_API() {
  local method=$1 path=$2
  shift 2
  curl -sk -u "root:$ROOT_PASSWORD" -X "$method" \
    -H 'Content-Type: application/json' "$BASE$path" "$@"
}

# rs_id pulls the created set's id out of the 201 body. The response is the set
# itself and "id" is its first field, so the first match is the right one.
rs_id() { grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4; }

seed_restrictions() {
  log "seeding the SSH restriction sets"

  # The global set: root-only to create, and the fallback that applies to every
  # SSH CA. 8h and user certificates only, with a reason recorded in the key id
  # of every certificate signed under it.
  local operators
  operators=$(RS_API POST /api/restriction-sets -d '{
    "name": "ssh-operators",
    "type": "ssh",
    "max_validity_secs": 28800,
    "allowed_principals": ["*"],
    "allowed_cert_types": ["user"],
    "require_reason": true,
    "deny_critical_options": true
  }' | rs_id)

  # The SSH CA's key id, which is what a CA-scoped set hangs off. Column 1 of
  # `CA list` is the id and column 2 the label, as in seed_access.
  local ssh_ca
  ssh_ca=$(CA list 2>/dev/null | awk '$2 == "northwind-ssh-ops" { print $1 }')

  if [ -n "$ssh_ca" ]; then
    # The tight one: 15 minutes, deploy-* principals, nothing else. This is the
    # set a CI runner's token resolves to.
    quiet RS_API POST "/api/keys/$ssh_ca/restriction-sets" -d '{
      "name": "ssh-ci-deploy",
      "type": "ssh",
      "max_validity_secs": 900,
      "allowed_principals": ["deploy-*"],
      "allowed_cert_types": ["user"],
      "require_reason": true,
      "deny_extensions": true,
      "deny_critical_options": true
    }' || true

    # Make the global set this CA's fallback, so the per-CA defaults table shows
    # a resolved ceiling rather than the "none" that means unrestricted.
    if [ -n "$operators" ]; then
      quiet RS_API PUT "/api/keys/$ssh_ca/default-restriction-set" \
        -d "{\"restriction_set_id\":\"$operators\",\"type\":\"ssh\"}" || true
    fi
  fi

  # One X.509 set, under the TLS issuer, to put a row beneath the warning.
  local tls_ca
  tls_ca=$(CA list 2>/dev/null | awk '$2 == "northwind-issuing-tls" { print $1 }')
  if [ -n "$tls_ca" ]; then
    quiet RS_API POST "/api/keys/$tls_ca/restriction-sets" -d '{
      "name": "x509-leaf-only",
      "type": "x509",
      "allowed_key_usages": ["digitalSignature", "keyEncipherment"],
      "allowed_ext_key_usages": ["serverAuth"],
      "allowed_san_types": ["dns"],
      "allowed_san_patterns": ["*.northwind.example"],
      "deny_ca": true
    }' || true
  fi
}

# ---------------------------------------------------------------------------
# serve — start the server and wait until the console answers.
#
# setsid, and every descriptor pointed somewhere of its own, because the server
# has to outlive this script without holding anything the caller is waiting on.
# A server that merely inherits the script's stdout keeps the caller's pipe open
# for as long as it runs, which deadlocks any `$(demo-pki.sh up)` — it never
# sees end-of-file. The base URL goes to a file for the same reason: capture.sh
# reads it there instead of having to capture this script's output.
# ---------------------------------------------------------------------------
serve() {
  log "starting the server on $BASE"
  ( cd "$SHOT_HOME" && exec setsid "$BIN/server" -config "$CONF" \
      </dev/null >"$SHOT_HOME/server.log" 2>&1 ) &
  local launcher=$!
  disown "$launcher" 2>/dev/null || true

  for _ in $(seq 1 180); do
    if curl -sk -o /dev/null "$BASE/console/" 2>/dev/null; then
      # The listener answers; record the pid that owns it so down can stop it.
      # $! names the subshell, not the exec'd server, so ask the port.
      local pid
      pid=$(ss -ltnp 2>/dev/null |
            sed -n "s/.*127\.0\.0\.1:$PORT .*pid=\([0-9]*\).*/\1/p" | head -1)
      [ -n "$pid" ] && echo "$pid" > "$SHOT_HOME/server.pid"
      echo "$BASE" > "$SHOT_HOME/base-url"
      return 0
    fi
    sleep 0.5
  done
  echo "server did not come up; last log lines:" >&2
  tail -20 "$SHOT_HOME/server.log" >&2
  exit 1
}

cmd_up() {
  cmd_down >/dev/null 2>&1 || true
  mkdir -p "$SHOT_HOME" "$WORK"
  build
  local module
  module=$(token)
  config "$module"
  seed_cas
  seed_certs
  seed_lifecycle
  seed_ssh
  seed_signing
  seed_secrets
  seed_access
  seed_audit
  serve
  # After serve: restriction sets have no CLI, so they go in over HTTP.
  seed_restrictions
  log "ready"
  # Last line of stdout: the base URL, for capture.sh to read.
  echo "$BASE"
}

case "${1:-}" in
  up)   cmd_up ;;
  down) cmd_down ;;
  *)    echo "usage: $(basename "$0") up|down" >&2; exit 2 ;;
esac
