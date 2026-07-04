//go:build sqlite && zlint

package ca

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
)

// TestPreIssuanceZLintGate proves the optional zlint backend participates in the
// same fail-closed pre-issuance gate as the hand-rolled checks: with the default
// level mapping an error-level zlint finding blocks issuance before the signer
// runs (no certificate recorded), and remapping zlint errors to warnings lets the
// same request issue while still recording a cert.lint warning event.
//
// It runs only under `-tags "sqlite zlint"`; the default build compiles the
// zlint stub and this file is excluded.
func TestPreIssuanceZLintGate(t *testing.T) {
	if !certlint.ZLintAvailable() {
		t.Fatal("zlint backend not available under the zlint build tag")
	}
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "zlint-gate")

	withProfiles(t, []Profile{
		{
			// zlint enabled, default mapping (error → enforce). A plain serverAuth
			// leaf with no certificatePolicies / AIA trips CA/Browser-Forum errors.
			Name:            "zlint-enforce",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			Lint:            &LintConfig{ZLint: &ZLintConfig{Enabled: true}},
		},
		{
			// Same profile, but zlint errors are remapped to warnings, so issuance
			// proceeds and only a warning event is recorded.
			Name:            "zlint-warn",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			Lint:            &LintConfig{ZLint: &ZLintConfig{Enabled: true, ErrorMode: "warn", NoticeMode: "ignore"}},
		},
	})

	// --- Fail-closed: zlint errors block issuance before signing.
	failBefore := countLintEvents(t, mgr, audit.ResultError)
	csr := makeCSR(t, "leaf.example.com", []string{"leaf.example.com"})
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      csr,
		Profile:     "zlint-enforce",
		RequestedBy: "tester",
	})
	if err == nil {
		t.Fatal("expected issuance to be blocked by the zlint gate, got nil error")
	}
	if !strings.Contains(err.Error(), "lint") || !strings.Contains(err.Error(), certlint.ZLintCodePrefix) {
		t.Fatalf("error should mention the lint gate and a zlint/ code, got: %v", err)
	}
	certs, err := mgr.db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no issued certificate after a blocked zlint gate, found %d", len(certs))
	}
	if got := countLintEvents(t, mgr, audit.ResultError); got != failBefore+1 {
		t.Fatalf("expected one new cert.lint error event, got %d (was %d)", got, failBefore)
	}

	// --- Remapping zlint errors to warnings lets the same request issue.
	warnBefore := countLintEvents(t, mgr, audit.ResultSuccess)
	warnCSR := makeCSR(t, "leaf2.example.com", []string{"leaf2.example.com"})
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      warnCSR,
		Profile:     "zlint-warn",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("warn-mapped zlint issuance should not be blocked: %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("expected a certificate for warn-mapped zlint issuance")
	}
	if got := countLintEvents(t, mgr, audit.ResultSuccess); got != warnBefore+1 {
		t.Fatalf("expected one new cert.lint warning event, got %d (was %d)", got, warnBefore)
	}
}
