//go:build sqlite

package ca

import (
	"context"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/caa"
)

// gateVerdict returns the verdict for a named gate in a preview result.
func gateVerdict(t *testing.T, res *PreviewResult, name string) GateVerdict {
	t.Helper()
	for _, g := range res.Gates {
		if g.Name == name {
			return g
		}
	}
	t.Fatalf("preview has no %q gate verdict (gates: %v)", name, res.Gates)
	return GateVerdict{}
}

// hasExtension reports whether the preview's resolved extensions include an OID.
func hasExtension(res *PreviewResult, oid string) bool {
	for _, e := range res.Extensions {
		if e.OID == oid {
			return true
		}
	}
	return false
}

// countAllEvents returns the total number of audit events recorded so far. The
// preview is required to append none.
func countAllEvents(t *testing.T, m *Manager) int {
	t.Helper()
	_, total, err := m.db.ListEvents("", "", "", 1, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return total
}

// TestPreviewIssuance exercises the single-request pre-issuance preview (Task
// 113): an accepted request reports every gate passing and the resolved leaf
// extensions, and each of the four documented rejection classes (over-max
// validity, lint failure, CAA-forbidden name, name-constraint violation) is
// reported as a fail-closed gate with Decision "reject" — all WITHOUT issuing a
// certificate, allocating a durable serial, or appending any audit event.
func TestPreviewIssuance(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()

	// A root plus a name-constrained intermediate (permitting internal.example.com,
	// excluding secret.internal.example.com) for the name-constraint case.
	root, inter := newConstrainedIntermediate(t, mgr, "preview")

	const caIdent = "ca.example.com"
	withProfiles(t, []Profile{
		{
			Name:            "server",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     397 * day,
		},
		{
			Name:            "server-ms",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     397 * day,
			MustStaple:      true,
		},
		{
			Name:            "caa-enforce",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     397 * day,
			CAA:             &CAAConfig{Mode: "enforce", Identifier: caIdent},
		},
		{
			Name:            "public-strict",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"serverAuth"},
			DefaultValidity: 90 * day,
			MaxValidity:     397 * day,
			Lint:            &LintConfig{Public: true},
		},
	})
	withCAAResolver(t, fakeCAAResolver{caa: map[string][]caa.Record{
		// A CAA RRset authorizing a different CA forbids issuance for us.
		"forbidden.example.com": {{Tag: caa.TagIssue, Value: "other-ca.example.net"}},
	}})

	// Baseline side-effect counters, captured after all CA setup.
	certsRootBefore := countIssued(t, mgr, root.ID)
	certsInterBefore := countIssued(t, mgr, inter.ID)
	eventsBefore := countAllEvents(t, mgr)

	// --- Accept: a valid CSR under the server profile.
	t.Run("accept", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			CSRPEM:      makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
			Profile:     "server",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if !res.WouldIssue || res.Decision != "accept" {
			t.Fatalf("want accept/would_issue, got decision=%q would_issue=%v gates=%v", res.Decision, res.WouldIssue, res.Gates)
		}
		if !res.SubjectKeyProvided {
			t.Error("CSR path should report subject_key_provided=true")
		}
		if res.SubjectKeyID == "" || res.AuthorityKeyID == "" {
			t.Errorf("want resolved SKI and AKI, got ski=%q aki=%q", res.SubjectKeyID, res.AuthorityKeyID)
		}
		if len(res.KeyUsages) == 0 || len(res.ExtKeyUsages) == 0 {
			t.Errorf("want resolved KU/EKU, got ku=%v eku=%v", res.KeyUsages, res.ExtKeyUsages)
		}
		for _, oid := range []string{"2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.14", "2.5.29.35"} {
			if !hasExtension(res, oid) {
				t.Errorf("resolved extensions missing %s (%s)", oid, extensionName(oid))
			}
		}
		if v := gateVerdict(t, res, GateValidity); v.Status != GatePass {
			t.Errorf("validity gate: got %q, want pass", v.Status)
		}
		if v := gateVerdict(t, res, GateNameConstraints); v.Status != GateSkipped {
			t.Errorf("name_constraints gate on unconstrained root: got %q, want skipped", v.Status)
		}
	})

	// --- Accept (keyless): explicit subject/SANs, no CSR — a throwaway key is
	// synthesized so the extension layout still resolves.
	t.Run("accept_keyless", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			Subject:     pkix.Name{CommonName: "leaf.example.com"},
			DNSNames:    []string{"leaf.example.com"},
			Profile:     "server",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if !res.WouldIssue {
			t.Fatalf("keyless preview should still accept, got %q", res.Decision)
		}
		if res.SubjectKeyProvided {
			t.Error("keyless path should report subject_key_provided=false")
		}
		if !hasExtension(res, "2.5.29.17") {
			t.Error("keyless preview should still resolve the SAN extension")
		}
	})

	// --- Must-Staple profile stamps the RFC 7633 TLS Feature extension.
	t.Run("must_staple", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			CSRPEM:      makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
			Profile:     "server-ms",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if !res.MustStaple {
			t.Error("must_staple profile should set MustStaple=true")
		}
		if !hasExtension(res, "1.3.6.1.5.5.7.1.24") {
			t.Error("must_staple profile should stamp the tlsFeature extension")
		}
		if v := gateVerdict(t, res, GateMustStaple); v.Status != GatePass {
			t.Errorf("must_staple gate: got %q, want pass", v.Status)
		}
	})

	// --- Reject: over-max validity.
	t.Run("reject_over_max_validity", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			CSRPEM:      makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
			Profile:     "server",
			Validity:    5 * 365 * day, // profile max is 397 days
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if res.WouldIssue || res.Decision != "reject" {
			t.Fatalf("want reject for over-max validity, got decision=%q", res.Decision)
		}
		if v := gateVerdict(t, res, GateValidity); v.Status != GateFail {
			t.Fatalf("validity gate: got %q, want fail", v.Status)
		}
	})

	// --- Reject: lint failure (internal name under a public-trust profile).
	t.Run("reject_lint", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			CSRPEM:      makeCSR(t, "server.local", []string{"server.local"}),
			Profile:     "public-strict",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if res.WouldIssue || res.Decision != "reject" {
			t.Fatalf("want reject for lint failure, got decision=%q", res.Decision)
		}
		v := gateVerdict(t, res, GateLint)
		if v.Status != GateFail {
			t.Fatalf("lint gate: got %q, want fail", v.Status)
		}
		if !strings.Contains(strings.Join(v.Findings, " "), "internal_name") {
			t.Errorf("lint findings should identify the internal_name check, got %v", v.Findings)
		}
	})

	// --- Reject: a name forbidden by its CAA RRset.
	t.Run("reject_caa", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        root.ID,
			CSRPEM:      makeCSR(t, "forbidden.example.com", []string{"forbidden.example.com"}),
			Profile:     "caa-enforce",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if res.WouldIssue || res.Decision != "reject" {
			t.Fatalf("want reject for CAA-forbidden name, got decision=%q", res.Decision)
		}
		if v := gateVerdict(t, res, GateCAA); v.Status != GateFail {
			t.Fatalf("caa gate: got %q, want fail", v.Status)
		}
	})

	// --- Reject: a name outside the issuing CA's permitted subtrees.
	t.Run("reject_name_constraints", func(t *testing.T) {
		res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
			CAID:        inter.ID,
			CSRPEM:      makeCSR(t, "host.evil.com", []string{"host.evil.com"}),
			Profile:     "server",
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("preview: %v", err)
		}
		if res.WouldIssue || res.Decision != "reject" {
			t.Fatalf("want reject for name-constraint violation, got decision=%q", res.Decision)
		}
		v := gateVerdict(t, res, GateNameConstraints)
		if v.Status != GateFail {
			t.Fatalf("name_constraints gate: got %q, want fail", v.Status)
		}
		if len(v.Findings) == 0 {
			t.Error("name-constraint failure should list the offending name(s)")
		}
	})

	// --- No side effects: no certificate recorded and no audit event appended by
	// any of the previews above (accept or reject).
	if got := countIssued(t, mgr, root.ID); got != certsRootBefore {
		t.Fatalf("preview recorded a certificate on the root: before=%d after=%d", certsRootBefore, got)
	}
	if got := countIssued(t, mgr, inter.ID); got != certsInterBefore {
		t.Fatalf("preview recorded a certificate on the intermediate: before=%d after=%d", certsInterBefore, got)
	}
	if got := countAllEvents(t, mgr); got != eventsBefore {
		t.Fatalf("preview appended audit event(s): before=%d after=%d", eventsBefore, got)
	}
}
