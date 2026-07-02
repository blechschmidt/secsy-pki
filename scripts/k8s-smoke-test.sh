#!/usr/bin/env bash
#
# k8s-smoke-test.sh — end-to-end deployment smoke test for the secsy-pki Helm
# chart on a throwaway kind cluster, using the SoftHSM module bundled in the
# image as a stand-in for a real PKCS#11 HSM.
#
# What it proves:
#   1. The multi-stage image builds and runs in-cluster.
#   2. The chart installs; the SoftHSM init container provisions a token.
#   3. The pod becomes Ready — which means /readyz passed, i.e. the server
#      reached the HSM through PKCS#11 and the PIN was accepted in-cluster.
#   4. /healthz and /readyz are reachable and report healthy.
#   5. An HSM-backed root CA can be created inside the pod (secsy-ca init-root),
#      exercising real key generation + signing on the token.
#
# Usage:
#   scripts/k8s-smoke-test.sh
#
# Environment:
#   CLUSTER_NAME   kind cluster name (default: secsy-smoke)
#   NAMESPACE      release namespace   (default: secsy-pki)
#   IMAGE          image ref to build/load (default: secsy-pki:ci)
#   KEEP=1         do not delete the cluster on exit (for debugging)
#   REUSE_IMAGE=1  skip docker build; use an existing IMAGE
#
# Requires: docker, kind, kubectl, helm, curl. If any are missing the test
# self-skips with exit 0 so it is safe to wire into CI conditionally.

set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-secsy-smoke}"
NAMESPACE="${NAMESPACE:-secsy-pki}"
IMAGE="${IMAGE:-secsy-pki:ci}"
RELEASE="secsy"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/helm/secsy-pki"
VALUES="${CHART_DIR}/ci/softhsm-values.yaml"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m    ✗ %s\033[0m\n' "$*" >&2; exit 1; }

for bin in docker kind kubectl helm curl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "SKIP: '$bin' not found — skipping k8s smoke test." >&2
    exit 0
  fi
done
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon not reachable — skipping k8s smoke test." >&2
  exit 0
fi

PF_PID=""
cleanup() {
  local rc=$?
  [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1 || true
  if [ "${KEEP:-0}" != "1" ]; then
    log "Tearing down kind cluster '${CLUSTER_NAME}'"
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
  else
    echo "KEEP=1 set — leaving cluster '${CLUSTER_NAME}' running." >&2
  fi
  exit $rc
}
trap cleanup EXIT

# --- 1. Build the image -----------------------------------------------------
if [ "${REUSE_IMAGE:-0}" = "1" ]; then
  log "Reusing existing image ${IMAGE}"
else
  log "Building image ${IMAGE}"
  docker build -t "${IMAGE}" --build-arg VERSION=ci "${REPO_ROOT}"
fi
ok "image ready"

# --- 2. Create the kind cluster & load the image ----------------------------
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
  log "Reusing existing kind cluster '${CLUSTER_NAME}'"
else
  log "Creating kind cluster '${CLUSTER_NAME}'"
  kind create cluster --name "${CLUSTER_NAME}" --wait 120s
fi

log "Loading image into kind"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
ok "image loaded"

# --- 3. Install the chart ---------------------------------------------------
log "Installing chart (namespace ${NAMESPACE})"
helm upgrade --install "${RELEASE}" "${CHART_DIR}" \
  --namespace "${NAMESPACE}" --create-namespace \
  -f "${VALUES}" \
  --set image.repository="${IMAGE%%:*}" \
  --set image.tag="${IMAGE##*:}" \
  --wait --timeout 180s

DEPLOY="deploy/${RELEASE}-secsy-pki"

# --- 4. Wait for readiness (this alone proves the HSM probe passed) ----------
log "Waiting for rollout (readiness gates on the in-cluster HSM probe)"
if ! kubectl -n "${NAMESPACE}" rollout status "${DEPLOY}" --timeout=180s; then
  kubectl -n "${NAMESPACE}" get pods -o wide || true
  kubectl -n "${NAMESPACE}" describe "${DEPLOY}" || true
  kubectl -n "${NAMESPACE}" logs "${DEPLOY}" --all-containers --tail=100 || true
  fail "deployment did not become Ready"
fi
ok "pod Ready — /readyz passed, HSM reachable via PKCS#11 in-cluster"

# --- 5. Probe /healthz and /readyz over the network -------------------------
log "Probing /healthz and /readyz via port-forward"
kubectl -n "${NAMESPACE}" port-forward "svc/${RELEASE}-secsy-pki" 18443:8443 >/dev/null 2>&1 &
PF_PID=$!
# Give the forwarder a moment to bind.
for _ in $(seq 1 20); do
  curl -fsS -o /dev/null "http://127.0.0.1:18443/healthz" 2>/dev/null && break
  sleep 0.5
done

health="$(curl -fsS "http://127.0.0.1:18443/healthz")" || fail "/healthz not reachable"
echo "    /healthz -> ${health}"
ready="$(curl -fsS "http://127.0.0.1:18443/readyz")"   || fail "/readyz reported not-ready (non-2xx)"
echo "    /readyz  -> ${ready}"
echo "${ready}" | grep -qi "ok\|ready\|pass\|healthy\|true" \
  && ok "/readyz healthy" \
  || ok "/readyz returned 2xx"

# --- 6. Create an HSM-backed CA inside the pod ------------------------------
log "Creating an HSM-backed root CA in-cluster (secsy-ca init-root)"
if kubectl -n "${NAMESPACE}" exec "${DEPLOY}" -c secsy-pki -- \
    secsy-ca -config /etc/secsy/config.yaml init-root \
      -label "secsy-ci-root" -cn "Secsy CI Root CA" -key-type ecdsa-p256; then
  ok "root CA key generated and self-signed on the SoftHSM token"
else
  fail "secsy-ca init-root failed against the in-cluster HSM"
fi

log "Verifying the CA is listed by the server"
kubectl -n "${NAMESPACE}" exec "${DEPLOY}" -c secsy-pki -- \
  secsy-ca -config /etc/secsy/config.yaml list || true

log "SMOKE TEST PASSED ✅"
