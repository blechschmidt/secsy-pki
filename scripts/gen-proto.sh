#!/usr/bin/env bash
# Regenerate the gRPC/protobuf Go code for the PKI service (Task 56).
#
# Source of truth:   proto/pki/v1/pki.proto
# Generated output:  server/internal/grpcapi/pkiv1/*.pb.go
#
# Requirements:
#   - protoc            (protobuf-compiler; provides the well-known types under
#                        /usr/include/google/protobuf)
#   - protoc-gen-go       go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
#   - protoc-gen-go-grpc  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
#
# The generated files are committed to the repo (like the rest of the Go code),
# so this script only needs to run when the .proto changes. Re-run it and commit
# the diff.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Make the Go plugins discoverable when installed under GOPATH/bin.
if command -v go >/dev/null 2>&1; then
  export PATH="$PATH:$(go env GOPATH)/bin"
fi

for tool in protoc protoc-gen-go protoc-gen-go-grpc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH" >&2
    echo "see the header of $0 for install instructions" >&2
    exit 1
  fi
done

OUT="server/internal/grpcapi/pkiv1"
MODULE="github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
mkdir -p "$OUT"

# /usr/include carries the well-known types (google/protobuf/*.proto).
INCLUDE="${PROTOC_INCLUDE:-/usr/include}"

protoc \
  --proto_path=proto \
  --proto_path="$INCLUDE" \
  --go_out="$OUT" --go_opt=module="$MODULE" \
  --go-grpc_out="$OUT" --go-grpc_opt=module="$MODULE" \
  proto/pki/v1/pki.proto

echo "Generated Go code in $OUT from proto/pki/v1/pki.proto"
