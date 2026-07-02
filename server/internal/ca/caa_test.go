//go:build sqlite

package ca

import (
	"context"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// fakeCAAResolver is a deterministic Resolver for the gate test: caa maps a name
// to its published RRset; everything else resolves to no records (permitted).
type fakeCAAResolver struct {
	caa map[string][]caa.Record
}

func (f fakeCAAResolver) LookupCAA(_ context.Context, name string) ([]caa.Record, error) {
	return f.caa[name], nil
}

func (f fakeCAAResolver) LookupCNAME(_ context.Context, _ string) (string, error) {
	return "", nil
}

// withCAAResolver installs a resolver for the duration of a test, restoring the
// previous one afterwards.
func withCAAResolver(t *testing.T, r caa.Resolver) {
	t.Helper()
	prev := caaResolver
	caaResolver = r
	t.Cleanup(func() { caaResolver = prev })
}

// countCAAEvents returns the number of cert.caa audit events with the given
// result recorded so far.
func countCAAEvents(t *testing.T, m *Manager, result string) int {
	t.Helper()
	events, _, err := m.db.ListEvents(audit.ActionCertCAA, "", "", 1000, 0)
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

// TestPreIssuanceCAAGate proves the CAA gate is fail-closed: a certificate whose
// DNS name is forbidden by its CAA RRset is rejected before the HSM signs it —
// nothing is recorded — and a cert.caa audit event captures the failure. It also
// proves an authorized name still issues, and that permissive mode reports but
// does not block. It runs over both key providers so the SoftHSM path is covered.
func TestPreIssuanceCAAGate(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runCAAGate(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runCAAGate(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "caa-"+tag)

	const caIdent = "ca.example.com"
	withProfiles(t, []Profile{
		{
			Name:            "caa-enforce",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			CAA:             &CAAConfig{Mode: "enforce", Identifier: caIdent},
		},
		{
			Name:            "caa-permissive",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     90 * day,
			CAA:             &CAAConfig{Mode: "permissive", Identifier: caIdent},
		},
	})

	// A CAA RRset that authorizes a *different* CA forbids issuance for us.
	withCAAResolver(t, fakeCAAResolver{caa: map[string][]caa.Record{
		"forbidden.example.com": {{Tag: caa.TagIssue, Value: "other-ca.example.net"}},
		// authorized.example.com publishes an issue record naming this CA.
		"authorized.example.com": {{Tag: caa.TagIssue, Value: caIdent}},
	}})

	// --- Fail-closed: a forbidden name under an enforce profile is rejected.
	failBefore := countCAAEvents(t, mgr, audit.ResultError)
	badCSR := makeCSR(t, "forbidden.example.com", []string{"forbidden.example.com"})
	_, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      badCSR,
		Profile:     "caa-enforce",
		RequestedBy: "tester",
	})
	if err == nil {
		t.Fatal("expected issuance to be rejected by the CAA gate, got nil error")
	}
	if !strings.Contains(err.Error(), "CAA") {
		t.Fatalf("error should mention the CAA gate, got: %v", err)
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("error should identify the forbidden name, got: %v", err)
	}

	// Nothing may have been signed or recorded (fail-closed before signing).
	certs, err := mgr.db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected no issued certificate after a blocked CAA check, found %d", len(certs))
	}
	if got := countCAAEvents(t, mgr, audit.ResultError); got != failBefore+1 {
		t.Fatalf("expected one new cert.caa error event, got %d (was %d)", got, failBefore)
	}

	// --- An explicitly authorized name issues cleanly with no finding event.
	errBefore := countCAAEvents(t, mgr, audit.ResultError)
	okBefore := countCAAEvents(t, mgr, audit.ResultSuccess)
	goodCSR := makeCSR(t, "authorized.example.com", []string{"authorized.example.com"})
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      goodCSR,
		Profile:     "caa-enforce",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("authorized issuance failed: %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("expected a certificate for authorized issuance")
	}
	if got := countCAAEvents(t, mgr, audit.ResultError); got != errBefore {
		t.Fatalf("authorized pass should not add a CAA error event, got %d (was %d)", got, errBefore)
	}
	if got := countCAAEvents(t, mgr, audit.ResultSuccess); got != okBefore {
		t.Fatalf("authorized pass should not add a CAA event at all, got %d (was %d)", got, okBefore)
	}

	// --- A name with no CAA policy is permitted (no records → allowed).
	noPolicyCSR := makeCSR(t, "nopolicy.example.org", []string{"nopolicy.example.org"})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      noPolicyCSR,
		Profile:     "caa-enforce",
		RequestedBy: "tester",
	}); err != nil {
		t.Fatalf("issuance for a name with no CAA policy should succeed: %v", err)
	}

	// --- Permissive mode reports a forbidding record but does not block.
	warnBefore := countCAAEvents(t, mgr, audit.ResultSuccess)
	permCSR := makeCSR(t, "forbidden.example.com", []string{"forbidden.example.com"})
	permitted, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      permCSR,
		Profile:     "caa-permissive",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("permissive-mode issuance should not be blocked: %v", err)
	}
	if permitted.Certificate == nil {
		t.Fatal("expected a certificate for permissive-mode issuance")
	}
	if got := countCAAEvents(t, mgr, audit.ResultSuccess); got != warnBefore+1 {
		t.Fatalf("expected one new permissive cert.caa event, got %d (was %d)", got, warnBefore)
	}
}
