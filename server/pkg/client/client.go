// Package client is the generated, typed Go SDK for the Secsy PKI REST API.
//
// The bulk of this package (types and request methods) is generated from the
// canonical OpenAPI 3.1 specification at
// server/internal/handlers/openapi.yaml into client.gen.go. Do not edit that
// file by hand — regenerate it with:
//
//	go generate ./pkg/client/...
//
// (from the server module root), or run scripts/gen-client.sh, which installs
// the pinned oapi-codegen and regenerates. CI runs scripts/openapi-check.sh to
// fail the build if the committed client drifts from the spec.
//
// This file adds only small, hand-written conveniences (auth request editors)
// that are stable across regenerations.
package client

import (
	"context"
	"net/http"
)

//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=cfg.yaml ../../internal/handlers/openapi.yaml

// WithBasicAuth returns a ClientOption that authenticates every request with the
// built-in root user's HTTP basic credentials.
func WithBasicAuth(username, password string) ClientOption {
	return WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.SetBasicAuth(username, password)
		return nil
	})
}

// WithBearerToken returns a ClientOption that attaches an OIDC bearer token to
// every request.
func WithBearerToken(token string) ClientOption {
	return WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	})
}
