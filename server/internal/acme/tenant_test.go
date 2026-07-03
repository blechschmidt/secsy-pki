//go:build sqlite

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 61: the tenant gate on the ACME finalize path. The test env's CAs live
// in the built-in default tenant, so lifecycle/quota state is driven directly
// on that tenant record (the store has no default-tenant guard; only the
// admin API/CLI refuse to suspend it).

// acmeProblem unwraps the *xacme.Error out of a client error.
func acmeProblem(t *testing.T, err error) *xacme.Error {
	t.Helper()
	var ae *xacme.Error
	if !errors.As(err, &ae) {
		t.Fatalf("error %v (%T) is not an ACME problem", err, err)
	}
	return ae
}

// TestACME_SuspendedTenantBlocksFinalize: a suspended tenant's ACME finalize is
// refused with an RFC 8555 unauthorized problem (403); reactivation restores
// issuance for a fresh order.
func TestACME_SuspendedTenantBlocksFinalize(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()

	domain := "susp.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	if err := env.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("suspending: %v", err)
	}

	_, _, err = c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true)
	if err == nil {
		t.Fatal("finalize succeeded under a suspended tenant")
	}
	ae := acmeProblem(t, err)
	if ae.StatusCode != http.StatusForbidden {
		t.Errorf("finalize status = %d, want 403", ae.StatusCode)
	}
	if ae.ProblemType != "urn:ietf:params:acme:error:unauthorized" {
		t.Errorf("problem type = %q, want unauthorized", ae.ProblemType)
	}

	// Reactivation restores enrollment end-to-end.
	if err := env.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusActive); err != nil {
		t.Fatalf("reactivating: %v", err)
	}
	domain2 := "reactivated.example.test"
	order2, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain2))
	if err != nil {
		t.Fatalf("AuthorizeOrder(2): %v", err)
	}
	env.solve(t, c, order2, "http-01", domain2)
	if _, err := c.WaitOrder(ctx, order2.URI); err != nil {
		t.Fatalf("WaitOrder(2): %v", err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order2.FinalizeURL, csrFor(t, domain2), true); err != nil {
		t.Fatalf("finalize after reactivation: %v", err)
	}
}

// throttleCapture records the first 429 response and rewrites it into a
// non-retriable 400 for the client under test. A compliant ACME client backs
// off for the full Retry-After (here: until UTC midnight), which would hang
// the test; the capture asserts the real on-the-wire semantics while keeping
// the test fast.
type throttleCapture struct {
	base       http.RoundTripper
	status     int
	retryAfter string
	body       []byte
}

func (c *throttleCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	c.status = resp.StatusCode
	c.retryAfter = resp.Header.Get("Retry-After")
	c.body = body
	resp.StatusCode = http.StatusBadRequest
	resp.Status = "400 Bad Request"
	resp.Header.Del("Retry-After")
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// TestACME_QuotaExhaustedFinalizeRateLimited: an exhausted daily certificate
// quota answers finalize with the RFC 8555 rateLimited problem (429) and a
// Retry-After header, the order stays ready (not invalidated), and lifting
// the quota lets the same order finalize successfully.
func TestACME_QuotaExhaustedFinalizeRateLimited(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// A client whose transport captures (and neutralizes) throttle responses.
	capture := &throttleCapture{base: http.DefaultTransport}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &xacme.Client{Key: key, DirectoryURL: env.dirURL, HTTPClient: &http.Client{Transport: capture}}
	if _, err := c.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Cap the default tenant at 1 cert/day and pre-consume the single unit.
	tn, err := env.db.GetTenant(models.DefaultTenantID)
	if err != nil || tn == nil {
		t.Fatalf("GetTenant(default): %v", err)
	}
	tn.Quotas.MaxCertsPerDay = 1
	if err := env.db.UpdateTenant(tn); err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	if err := env.db.AddTenantUsage(models.DefaultTenantID, database.UsageDay(time.Now()), database.UsageCertsIssued, 1); err != nil {
		t.Fatalf("AddTenantUsage: %v", err)
	}

	domain := "quota.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	if _, _, err = c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true); err == nil {
		t.Fatal("finalize succeeded with an exhausted quota")
	}
	// Assert the real on-the-wire throttle the transport captured.
	if capture.status != http.StatusTooManyRequests {
		t.Fatalf("no 429 was captured on finalize (last err above)")
	}
	if capture.retryAfter == "" || capture.retryAfter == "0" {
		t.Errorf("429 missing positive Retry-After (got %q)", capture.retryAfter)
	}
	if !bytes.Contains(capture.body, []byte("urn:ietf:params:acme:error:rateLimited")) {
		t.Errorf("429 body is not a rateLimited problem: %s", capture.body)
	}

	// A quota throttle is transient: the same order must still be finalizable
	// once the ceiling is lifted (no invalidation).
	tn.Quotas.MaxCertsPerDay = 0
	if err := env.db.UpdateTenant(tn); err != nil {
		t.Fatalf("UpdateTenant(lift): %v", err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true); err != nil {
		t.Fatalf("finalize retry after lifting the quota: %v", err)
	}
}
