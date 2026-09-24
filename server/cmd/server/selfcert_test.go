//go:build sqlite

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
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

// TestResolveCARef covers the id-or-label resolution that server.tls.self_issue's
// ca_id goes through. The label case is the regression: ca_id is documented as
// accepting "an id or label", the issuer addresses CAs by id alone, and a label
// used to reach it unresolved — so a deployment that named its CA the only way it
// could know in advance (the label it chose; the id is a UUID minted later by
// init-root) got a fail-closed `CA "…" not found` at startup.
func TestResolveCARef(t *testing.T) {
	db, err := database.New("sqlite", filepath.Join(t.TempDir(), "resolve.db"))
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	issuer := &models.CA{
		ID:          "11111111-2222-3333-4444-555555555555",
		Label:       "issuing-ca",
		KeyType:     "ecdsa-sha2-nistp256",
		PublicKey:   "stub-public-key",
		Certificate: "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Subject:     "CN=Issuing CA",
	}
	if err := db.CreateCA(issuer); err != nil {
		t.Fatalf("creating the issuing CA: %v", err)
	}
	// An SSH-only CA: a real row with no X.509 certificate. resolveCAID rejects it
	// because it cannot issue a serving certificate, and that rejection must
	// survive the label path too.
	sshOnly := &models.CA{
		ID:        "66666666-7777-8888-9999-000000000000",
		Label:     "ssh-only",
		KeyType:   "ssh-ed25519",
		PublicKey: "stub-public-key",
	}
	if err := db.CreateCA(sshOnly); err != nil {
		t.Fatalf("creating the SSH-only CA: %v", err)
	}

	for _, tc := range []struct {
		name string
		ref  string
		want string // "" = expect an error
	}{
		{name: "by id", ref: issuer.ID, want: issuer.ID},
		{name: "by label", ref: "issuing-ca", want: issuer.ID},
		{name: "unknown", ref: "no-such-ca", want: ""},
		{name: "empty", ref: "", want: ""},
		{name: "whitespace", ref: "   ", want: ""},
		{name: "not an x509 issuer", ref: "ssh-only", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCARef(db, tc.ref, "serving-tls")
			if tc.want == "" {
				if err == nil {
					t.Fatalf("resolveCARef(%q) = %q, want an error", tc.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveCARef(%q) error = %v, want %q", tc.ref, err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("resolveCARef(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}
