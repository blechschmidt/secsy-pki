//go:build sqlite

// These tests drive MPIC through the live ACME server (software provider,
// SQLite, x/crypto/acme client), so they carry the same sqlite build tag as the
// rest of the end-to-end ACME server tests. The pure coordinator/quorum tests in
// mpic_test.go need no tag and run in the HSM-free suite.

package acme

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// scrapeMetrics renders the default metrics registry to text so a test can
// assert a series was emitted.
func scrapeMetrics(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := metrics.Default.WriteTo(&b); err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	return b.String()
}

// TestMPICServer_QuorumPass drives a full http-01 order to a certificate with
// MPIC enabled and two corroborating remote perspectives, proving the
// coordinator is wired into the live challenge path and a passing quorum issues.
func TestMPICServer_QuorumPass(t *testing.T) {
	env := newTestEnv(t)
	env.srv.SetMPIC(&Coordinator{
		Enabled: true,
		Remotes: remotes(corroborates("eu-west"), corroborates("us-east")),
		Policy:  QuorumPolicy{}.withDefaults(),
	})

	c := env.client(t)
	ctx := context.Background()
	domain := "mpic-pass.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	if _, err := x509.ParseCertificate(der[0]); err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}

	out := scrapeMetrics(t)
	if !strings.Contains(out, "secsy_acme_mpic_quorum_total{") || !strings.Contains(out, `result="corroborated"`) {
		t.Errorf("expected an mpic quorum corroborated metric; got:\n%s", out)
	}
	if !strings.Contains(out, `perspective="eu-west"`) {
		t.Errorf("expected a per-perspective metric for eu-west")
	}
}

// TestMPICServer_QuorumFail proves a passing primary check that the remote
// perspectives do not corroborate fails the challenge closed (the localized
// hijack scenario), marks the authorization invalid, and writes an acme.mpic
// audit record.
func TestMPICServer_QuorumFail(t *testing.T) {
	env := newTestEnv(t)
	env.srv.SetMPIC(&Coordinator{
		Enabled: true,
		Remotes: remotes(rejects("eu-west"), rejects("us-east")),
		Policy:  QuorumPolicy{}.withDefaults(),
	})

	c := env.client(t)
	ctx := context.Background()
	domain := "mpic-fail.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}

	// Locate and satisfy the http-01 challenge so the *primary* check passes; only
	// the remote perspectives dissent.
	var chal *xacme.Challenge
	var authzURL string
	for _, au := range order.AuthzURLs {
		authz, err := c.GetAuthorization(ctx, au)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		for _, ch := range authz.Challenges {
			if ch.Type == "http-01" {
				chal = ch
				authzURL = au
			}
		}
	}
	if chal == nil {
		t.Fatal("no http-01 challenge offered")
	}
	resp, _ := c.HTTP01ChallengeResponse(chal.Token)
	env.httpMu.Lock()
	env.httpResp[chal.Token] = resp
	env.httpMu.Unlock()

	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// The authorization must end invalid: the primary passed but the remote quorum
	// did not corroborate.
	if _, err := c.WaitAuthorization(ctx, authzURL); err == nil {
		t.Fatal("expected the authorization to fail when the remote quorum dissents")
	}

	// An acme.mpic audit record must have been written naming the dissent.
	events, total, err := env.db.ListEvents(audit.ActionACMEMPIC, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if total == 0 {
		t.Fatal("expected an acme.mpic audit record on quorum failure")
	}
	if !strings.Contains(events[0].Detail, "eu-west=rejected") || !strings.Contains(events[0].Detail, "primary=corroborated") {
		t.Errorf("audit detail %q missing the per-perspective breakdown", events[0].Detail)
	}

	out := scrapeMetrics(t)
	if !strings.Contains(out, `result="failed_quorum"`) {
		t.Errorf("expected a failed_quorum quorum metric")
	}
}

// TestMPICServer_DisabledNoSeries proves that with MPIC disabled (the default),
// challenge validation uses the single primary perspective and emits no MPIC
// quorum series for the challenge — behavior is unchanged from pre-MPIC.
func TestMPICServer_DisabledNoSeries(t *testing.T) {
	env := newTestEnv(t) // default: MPIC disabled
	before := strings.Count(scrapeMetrics(t), "secsy_acme_mpic_quorum_total")

	c := env.client(t)
	ctx := context.Background()
	domain := "mpic-off.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	// No new mpic quorum decision should be recorded for a disabled coordinator.
	events, total, err := env.db.ListEvents(audit.ActionACMEMPIC, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if total != 0 {
		t.Fatalf("expected no acme.mpic audit records when disabled, got %d (%+v)", total, events)
	}
	after := strings.Count(scrapeMetrics(t), "secsy_acme_mpic_quorum_total")
	if after != before {
		t.Errorf("mpic quorum series count changed with MPIC disabled (%d -> %d)", before, after)
	}
}
