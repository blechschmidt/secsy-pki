//go:build sqlite

package main

import (
	"context"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// TestBuildSelfIssuedServingCertDisabled verifies the clean fallback: when
// server.tls.self_issue is disabled, buildSelfIssuedServingCert returns (nil,
// nil) without touching the database or key provider, so the caller falls
// through to the static tls_cert/tls_key path (or the insecure-HTTP guard).
// nil db/provider are safe precisely because the disabled branch returns first.
func TestBuildSelfIssuedServingCertDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TLS.SelfIssue.Enabled = false

	si, err := buildSelfIssuedServingCert(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildSelfIssuedServingCert(disabled) error = %v, want nil", err)
	}
	if si != nil {
		t.Fatalf("buildSelfIssuedServingCert(disabled) = %v, want nil (should not self-issue)", si)
	}
}

// TestBuildSelfIssuedServingCertBadConfig verifies configuration errors surface
// before any issuance work (a malformed renew_before is caught after the enabled
// gate but before the CA/provider are used, so nil dependencies still suffice).
func TestBuildSelfIssuedServingCertBadConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TLS.SelfIssue.Enabled = true
	cfg.Server.TLS.SelfIssue.CAID = "ca"
	cfg.Server.TLS.SelfIssue.CommonName = "server"
	cfg.Server.TLS.SelfIssue.RenewBefore = "not-a-duration"

	if _, err := buildSelfIssuedServingCert(context.Background(), cfg, nil, nil); err == nil {
		t.Fatal("buildSelfIssuedServingCert with a bad renew_before should return an error")
	}
}
