#!/usr/bin/env bash
#
# capture.sh — regenerate docs/screenshots/ from a throwaway demo PKI.
#
#     ./scripts/screenshots/capture.sh
#
# Boots the demo PKI (see demo-pki.sh — an invented company, its own SoftHSM
# token, its own database, its own port), photographs its operator console with
# headless Chromium, tears the PKI down again, and leaves the PNGs in
# docs/screenshots/.
#
# It needs Chromium (or Chrome), node, SoftHSM and a Go toolchain. Those are all
# developer-box tools: this is deliberately not wired into CI, because a
# screenshot that regenerates on every push is a binary diff on every push.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
HERE="$ROOT/scripts/screenshots"
OUT="$ROOT/docs/screenshots"
SHOT_HOME=${SHOT_HOME:-/tmp/secsy-pki-shots}
export SHOT_HOME

find_chrome() {
  local c
  for c in /opt/cft/chrome-linux64/chrome \
           /root/.cache/puppeteer/chrome/linux-*/chrome-linux64/chrome \
           /root/.cache/ms-playwright/chromium-*/chrome-linux64/chrome \
           /root/.cache/ms-playwright/chromium-*/chrome-linux/chrome; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  for c in google-chrome chromium chromium-browser; do
    command -v "$c" >/dev/null 2>&1 && { command -v "$c"; return 0; }
  done
  return 1
}

CHROME=${CHROME:-$(find_chrome || true)}
if [ -z "$CHROME" ]; then
  echo "no Chrome/Chromium found — install one, or set CHROME=/path/to/chrome" >&2
  exit 1
fi
command -v node >/dev/null 2>&1 || { echo "node is required" >&2; exit 1; }

# KEEP_DEMO=1 leaves the PKI running after the capture, which is what you want
# while adding a shot: point a browser at it and find your selectors.
cleanup() {
  if [ "${KEEP_DEMO:-0}" = "1" ]; then
    echo "==> demo PKI left running (KEEP_DEMO=1); stop it with: $HERE/demo-pki.sh down" >&2
  else
    "$HERE/demo-pki.sh" down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Run the build/seed with its progress visible rather than captured — it is the
# slow half, and `demo-pki.sh up` reports the URL in $SHOT_HOME/base-url for
# exactly this reason (see the note on serve() there).
"$HERE/demo-pki.sh" up
BASE=$(cat "$SHOT_HOME/base-url")

echo "==> capturing from $BASE with $CHROME"
node "$HERE/capture.js" "$CHROME" "$BASE" "$OUT" "$SHOT_HOME"
