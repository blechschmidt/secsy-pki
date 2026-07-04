//go:build sqlite

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/caa"
)

// mapCAAResolver is a deterministic caa.Resolver for the ACME CAA-binding tests:
// LookupCAA returns the RRset published at exactly name, and there are no CNAMEs.
type mapCAAResolver struct {
	mu   sync.Mutex
	recs map[string][]caa.Record
}

func (m *mapCAAResolver) LookupCAA(_ context.Context, name string) ([]caa.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recs[name], nil
}

func (m *mapCAAResolver) LookupCNAME(_ context.Context, _ string) (string, error) { return "", nil }

func (m *mapCAAResolver) set(name string, recs ...caa.Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[name] = recs
}

// withCAAEnforceServerProfile installs a CAA-enforce variant of the built-in
// "server" profile (identifier ca.example.com) and a fresh resolver for the
// duration of the test, restoring the global profile/resolver state afterwards.
func withCAAEnforceServerProfile(t *testing.T, identifier string) *mapCAAResolver {
	t.Helper()
	serverProfile, err := ca.LookupProfile("server")
	if err != nil {
		t.Fatalf("LookupProfile(server): %v", err)
	}
	serverProfile.CAA = &ca.CAAConfig{Mode: "enforce", Identifier: identifier}
	if err := ca.SetCustomProfiles([]ca.Profile{serverProfile}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { _ = ca.SetCustomProfiles(nil) })

	resolver := &mapCAAResolver{recs: map[string][]caa.Record{}}
	ca.SetCAAResolver(resolver)
	t.Cleanup(func() { ca.SetCAAResolver(nil) })
	return resolver
}

// registerAccount registers a fresh ACME account and returns the client together
// with its account URI (the value an RFC 8657 "accounturi" parameter must match).
func registerAccount(t *testing.T, env *testEnv) (*xacme.Client, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := &xacme.Client{Key: key, DirectoryURL: env.dirURL}
	acct, err := c.Register(context.Background(), &xacme.Account{}, xacme.AcceptTOS)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if acct.URI == "" {
		t.Fatal("registered account has no URI")
	}
	return c, acct.URI
}

// TestACME_CAAAccountURIBinding proves the ACME finalize path threads the
// requesting account URI into the CAA gate so an RFC 8657 "accounturi" parameter
// is honored end-to-end: the pinned account issues, a different account is
// rejected before signing.
func TestACME_CAAAccountURIBinding(t *testing.T) {
	env := newTestEnv(t)
	resolver := withCAAEnforceServerProfile(t, "ca.example.com")
	ctx := context.Background()

	boundClient, boundURI := registerAccount(t, env)
	const domain = "bound.example.test"
	// Bind issuance for this domain to the first account, and require dns-01.
	resolver.set(domain, caa.Record{
		Tag:   caa.TagIssue,
		Value: "ca.example.com; accounturi=" + boundURI + "; validationmethods=dns-01",
	})

	// The pinned account, validating via the permitted method, issues cleanly.
	order, err := boundClient.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, boundClient, order, "dns-01", domain)
	if _, err := boundClient.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if _, _, err := boundClient.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true); err != nil {
		t.Fatalf("account-bound issuance should succeed: %v", err)
	}

	// A different account is not authorized by the accounturi binding: finalize is
	// blocked by the CAA gate even though the challenge was solved.
	otherClient, otherURI := registerAccount(t, env)
	if otherURI == boundURI {
		t.Fatal("expected distinct account URIs")
	}
	order2, err := otherClient.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder (other account): %v", err)
	}
	env.solve(t, otherClient, order2, "dns-01", domain)
	if _, err := otherClient.WaitOrder(ctx, order2.URI); err != nil {
		t.Fatalf("WaitOrder (other account): %v", err)
	}
	if _, _, err := otherClient.CreateOrderCert(ctx, order2.FinalizeURL, csrFor(t, domain), true); err == nil {
		t.Fatal("issuance from an account not named by accounturi must be rejected by the CAA gate")
	}
}

// TestACME_CAAValidationMethodBinding proves the finalize path threads the
// per-identifier validation method into the CAA gate so an RFC 8657
// "validationmethods" parameter is honored: a name restricted to dns-01 issues
// when solved via dns-01 and is rejected when solved via http-01.
func TestACME_CAAValidationMethodBinding(t *testing.T) {
	env := newTestEnv(t)
	resolver := withCAAEnforceServerProfile(t, "ca.example.com")
	ctx := context.Background()
	c, _ := registerAccount(t, env)

	const allowed = "dns-ok.example.test"
	const denied = "http-no.example.test"
	// Both names restrict validation to dns-01.
	resolver.set(allowed, caa.Record{Tag: caa.TagIssue, Value: "ca.example.com; validationmethods=dns-01"})
	resolver.set(denied, caa.Record{Tag: caa.TagIssue, Value: "ca.example.com; validationmethods=dns-01"})

	// Solved via the permitted method → issues.
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(allowed))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "dns-01", allowed)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, allowed), true); err != nil {
		t.Fatalf("dns-01 issuance under validationmethods=dns-01 should succeed: %v", err)
	}

	// Solved via a method outside the list → blocked at the CAA gate.
	order2, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(denied))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order2, "http-01", denied)
	if _, err := c.WaitOrder(ctx, order2.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order2.FinalizeURL, csrFor(t, denied), true); err == nil {
		t.Fatal("http-01 issuance under validationmethods=dns-01 must be rejected by the CAA gate")
	}
}
