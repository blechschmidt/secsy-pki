//go:build sqlite

package ca

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// withProfiles installs a custom profile set for the duration of a test,
// restoring the previous set afterwards.
func withProfiles(t *testing.T, profiles []Profile) {
	t.Helper()
	prev := customProfiles
	if err := SetCustomProfiles(profiles); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { customProfiles = prev })
}

// countLintEvents returns the number of cert.lint audit events with the given
// result recorded so far.
func countLintEvents(t *testing.T, m *Manager, result string) int {
	t.Helper()
	events, _, err := m.db.ListEvents(audit.ActionCertLint, "", 1000, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.Result == result {
			n++
		}
	}
	return n
}

// TestPreIssuanceLintGate proves the lint gate is fail-closed: a certificate
// that violates a profile's (enforce-mode) policy is rejected before the HSM
// signs it — no certificate is recorded — and a cert.lint audit event captures
// the failure. It also proves a compliant request still issues, and that a
// warn-mode policy reports but does not block.
func TestPreIssuanceLintGate(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runLintGate(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runLintGate(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "lint-"+tag)

	withProfiles(t, []Profile{
		{
			Name:            "public-strict",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			Lint:            &LintConfig{Public: true},
		},
		{
			Name:            "public-warn",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			Lint:            &LintConfig{Public: true, Mode: "warn"},
		},
	})

	// --- Fail-closed: an internal name under a public-strict profile is rejected.
	failBefore := countLintEvents(t, mgr, audit.ResultError)
	badCSR := makeCSR(t, "server.local", []string{"server.local"})
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      badCSR,
		Profile:     "public-strict",
		RequestedBy: "tester",
	})
	if err == nil {
		t.Fatal("expected issuance to be rejected by the lint gate, got nil error")
	}
	if !strings.Contains(err.Error(), "lint") {
		t.Fatalf("error should mention the lint gate, got: %v", err)
	}
	if !strings.Contains(err.Error(), "internal_name") {
		t.Fatalf("error should identify the failing check, got: %v", err)
	}

	// Nothing may have been signed or recorded (fail-closed before signing).
	certs, err := mgr.db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no issued certificate after a blocked lint, found %d", len(certs))
	}
	// A cert.lint failure event must have been audited.
	if got := countLintEvents(t, mgr, audit.ResultError); got != failBefore+1 {
		t.Fatalf("expected one new cert.lint error event, got %d (was %d)", got, failBefore)
	}

	// --- Compliant request issues cleanly, with no new lint finding events.
	errBefore := countLintEvents(t, mgr, audit.ResultError)
	okBefore := countLintEvents(t, mgr, audit.ResultSuccess)
	goodCSR := makeCSR(t, "leaf.example.com", []string{"leaf.example.com"})
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      goodCSR,
		Profile:     "public-strict",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("compliant issuance failed: %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("expected a certificate for compliant issuance")
	}
	if got := countLintEvents(t, mgr, audit.ResultError); got != errBefore {
		t.Fatalf("clean pass should not add a lint error event, got %d (was %d)", got, errBefore)
	}
	if got := countLintEvents(t, mgr, audit.ResultSuccess); got != okBefore {
		t.Fatalf("clean pass should not add a lint event at all, got %d (was %d)", got, okBefore)
	}

	// --- Warn mode reports but does not block.
	warnBefore := countLintEvents(t, mgr, audit.ResultSuccess)
	warnCSR := makeCSR(t, "server.local", []string{"server.local"})
	warned, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      warnCSR,
		Profile:     "public-warn",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("warn-mode issuance should not be blocked: %v", err)
	}
	if warned.Certificate == nil {
		t.Fatal("expected a certificate for warn-mode issuance")
	}
	// A cert.lint event with warnings (ResultSuccess) must have been audited.
	if got := countLintEvents(t, mgr, audit.ResultSuccess); got != warnBefore+1 {
		t.Fatalf("expected one new cert.lint warning event, got %d (was %d)", got, warnBefore)
	}

	// Sanity: the successfully issued certificates are retrievable.
	if _, err := mgr.db.GetIssuedCertificate(root.ID, res.Serial.String()); err != nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
}
