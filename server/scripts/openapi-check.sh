#!/usr/bin/env bash
#
# CI drift check for the OpenAPI spec and the generated Go client SDK.
#
# The spec (server/internal/handlers/openapi.yaml) is the single source of truth;
# server/pkg/client/client.gen.go is generated from it. This script regenerates
# the client and fails if the working tree changed — i.e. if someone edited the
# spec (or the generator config) without re-running the generator, or hand-edited
# the generated file. Regeneration also parses and validates the spec, so an
# invalid OpenAPI document fails here too.
#
# Run locally with:  server/scripts/openapi-check.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$SERVER_DIR"

GEN_FILE="pkg/client/client.gen.go"

echo "==> Regenerating the client SDK from the OpenAPI spec"
go generate ./pkg/client/...

echo "==> Checking for drift in ${GEN_FILE}"
if ! git diff --quiet -- "$GEN_FILE"; then
	echo
	echo "ERROR: the generated client is out of sync with the OpenAPI spec." >&2
	echo "       Run 'server/scripts/gen-client.sh' and commit the result." >&2
	echo
	git --no-pager diff -- "$GEN_FILE" | head -100
	exit 1
fi

echo "==> Verifying the module builds with the regenerated client"
go build ./...

echo "==> OK: OpenAPI spec and generated client SDK are in sync."
