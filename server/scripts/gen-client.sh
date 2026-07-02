#!/usr/bin/env bash
#
# Regenerate the typed Go client SDK (server/pkg/client) from the canonical
# OpenAPI 3.1 spec at server/internal/handlers/openapi.yaml.
#
# The oapi-codegen generator is pinned as a `tool` dependency in server/go.mod,
# so this runs hermetically via `go tool` — no separate install step and no
# version drift. Run it whenever the spec changes; commit the regenerated
# client.gen.go alongside the spec.
#
# Usage:  server/scripts/gen-client.sh   (or: cd server && go generate ./pkg/client/...)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
cd "$SERVER_DIR"

echo "==> Regenerating pkg/client from internal/handlers/openapi.yaml"
go generate ./pkg/client/...

echo "==> Verifying the module still builds"
go build ./...

echo "==> Done. Generated: server/pkg/client/client.gen.go"
