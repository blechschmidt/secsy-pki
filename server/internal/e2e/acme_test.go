//go:build sqlite

// This file drives the ACME (RFC 8555) server end-to-end against a real,
// HSM-backed CA (SoftHSM in CI), using the golang.org/x/crypto/acme client — a
// full, independent ACME client implementation — as the test harness. It proves
// the complete automated-issuance flow works with a live ACME client:
//
//	register account -> place order -> satisfy http-01 / dns-01 challenge
//	-> finalize with a CSR -> download an HSM-signed certificate -> revoke it.
//
// Every leaf certificate is signed on the token via the shared ca.Manager, so
// this simultaneously exercises the ACME protocol and HSM-backed signing.
//
// It shares the SECSY_* gating and helpers (hsmProvider, uniqueLabel) with
// fullflow_test.go, so a plain `go test ./...` with no HSM stays green.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	acmesrv "github.com/blechschmidt/secsy-pki/server/internal/acme"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeResolver is an in-memory DNS TXT resolver used to satisfy dns-01
// challenges without touching real DNS.
type fakeResolver struct {
	mu   sync.Mutex
	recs map[string][]string
}

func newFakeResolver() *fakeResolver { return &fakeResolver{recs: map[string][]string{}} }

func (f *fakeResolver) set(name string, values []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs[name] = values
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.recs[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// acmeTestEnv holds the wired-up ACME server and its test fixtures.
type acmeTestEnv struct {
	db        *database.DB
	server    *httptest.Server
	dirURL    string
	resolver  *fakeResolver
	httpMu    sync.Mutex
	httpResp  map[string]string // http-01 token -> key authorization
	roots     *x509.CertPool
	interPool *x509.CertPool
	caID      string
}

// setupACME builds an HSM-backed root+intermediate CA, mounts the ACME server on
// an httptest server, and wires validators that resolve http-01 to a local
// listener and dns-01 to the fake resolver.
func setupACME(t *testing.T) *acmeTestEnv {
	t.Helper()
	provider := hsmProvider(t)

	db, err := database.New("sqlite", t.TempDir()+"/acme.db")
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	ctx := context.Background()

	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "acme-root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy ACME Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "acme-inter"),
		KeyType:    keyprovider.KeyTypeECDSAP256,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy ACME Issuing CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	rootCert := mustParse(t, root.Certificate)
	interCert := mustParse(t, inter.Certificate)
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	env := &acmeTestEnv{
		db:        db,
		resolver:  newFakeResolver(),
		httpResp:  map[string]string{},
		roots:     roots,
		interPool: interPool,
		caID:      inter.ID,
	}

	// A local listener that answers http-01 challenge fetches.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	challengeSrv := &http.Server{Handler: http.HandlerFunc(env.serveHTTP01)}
	go challengeSrv.Serve(lis)
	t.Cleanup(func() { challengeSrv.Close() })
	solverAddr := lis.Addr().String()

	// Build the ACME server pointing at the intermediate CA.
	srv := acmesrv.New(db, provider, acmesrv.Config{
		CAID:               inter.ID,
		Profile:            "server",
		ChallengeTypes:     []string{"http-01", "dns-01"},
		AllowIPIdentifiers: false,
	})

	// The validator dials every http-01 fetch to the local solver regardless of
	// the hostname in the URL, so the test can use realistic domain names.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, solverAddr)
		},
	}
	srv.SetValidator(&acmesrv.Validator{
		HTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: transport},
		Resolver:   env.resolver,
		HTTPPort:   80,
	})

	mux := http.NewServeMux()
	srv.Register(mux)
	env.server = httptest.NewServer(mux)
	t.Cleanup(env.server.Close)
	env.dirURL = env.server.URL + "/acme/directory"

	return env
}

func (env *acmeTestEnv) serveHTTP01(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if len(r.URL.Path) <= len(prefix) {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Path[len(prefix):]
	env.httpMu.Lock()
	resp, ok := env.httpResp[token]
	env.httpMu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write([]byte(resp))
}

// newClient registers a fresh ACME account and returns the bound client.
func (env *acmeTestEnv) newClient(t *testing.T) *xacme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &xacme.Client{Key: key, DirectoryURL: env.dirURL}
	if _, err := client.Register(context.Background(), &xacme.Account{
		Contact: []string{"mailto:acme-e2e@example.com"},
	}, xacme.AcceptTOS); err != nil {
		t.Fatalf("account registration failed: %v", err)
	}
	return client
}

// runOrder drives one order for a single domain using the given challenge type,
// returning the issued DER chain (leaf first).
func (env *acmeTestEnv) runOrder(t *testing.T, client *xacme.Client, domain, challType string) [][]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder(%s): %v", domain, err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == challType {
				chal = c
			}
		}
		if chal == nil {
			t.Fatalf("no %s challenge offered for %s", challType, domain)
		}

		switch challType {
		case "http-01":
			resp, err := client.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				t.Fatal(err)
			}
			env.httpMu.Lock()
			env.httpResp[chal.Token] = resp
			env.httpMu.Unlock()
		case "dns-01":
			rec, err := client.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				t.Fatal(err)
			}
			env.resolver.set("_acme-challenge."+domain, []string{rec})
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept(%s): %v", challType, err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}

	// Build a CSR for the domain with a fresh subscriber key.
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, csrKey)
	if err != nil {
		t.Fatal(err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("issued certificate chain is empty")
	}
	return der
}

// verifyIssued parses and chain-verifies the leaf against the HSM-backed roots.
func (env *acmeTestEnv) verifyIssued(t *testing.T, der [][]byte, domain string) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatalf("parsing issued leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         env.roots,
		Intermediates: env.interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("issued certificate does not chain to the HSM root: %v", err)
	}
	found := false
	for _, n := range leaf.DNSNames {
		if n == domain {
			found = true
		}
	}
	if !found {
		t.Errorf("issued leaf SANs %v do not contain the ordered domain %q", leaf.DNSNames, domain)
	}
	if leaf.IsCA {
		t.Error("issued ACME leaf must not be a CA")
	}
	return leaf
}

// TestACMEFullFlow runs the ACME issuance lifecycle against the HSM.
func TestACMEFullFlow(t *testing.T) {
	env := setupACME(t)

	t.Run("HTTP01Order", func(t *testing.T) {
		client := env.newClient(t)
		der := env.runOrder(t, client, "http01.acme.example.test", "http-01")
		env.verifyIssued(t, der, "http01.acme.example.test")
	})

	t.Run("DNS01Order", func(t *testing.T) {
		client := env.newClient(t)
		der := env.runOrder(t, client, "dns01.acme.example.test", "dns-01")
		env.verifyIssued(t, der, "dns01.acme.example.test")
	})

	t.Run("RevokeIssuedCertificate", func(t *testing.T) {
		client := env.newClient(t)
		domain := "revoke.acme.example.test"
		der := env.runOrder(t, client, domain, "http-01")
		leaf := env.verifyIssued(t, der, domain)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Account-authenticated revocation (the account that ordered the cert).
		if err := client.RevokeCert(ctx, nil, der[0], xacme.CRLReasonKeyCompromise); err != nil {
			t.Fatalf("RevokeCert: %v", err)
		}
		// The revocation must now be recorded in the CA's revocation store.
		mgr := ca.NewManager(env.db, hsmProvider(t))
		crlDER, err := mgr.GenerateCRL(ctx, env.caID)
		if err != nil {
			t.Fatalf("GenerateCRL: %v", err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("parsing CRL: %v", err)
		}
		found := false
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				found = true
			}
		}
		if !found {
			t.Error("ACME-revoked certificate is not present in the CA CRL")
		}
	})

	t.Run("AuditAndInventoryRecorded", func(t *testing.T) {
		// Every finalized order writes a tamper-evident audit event.
		events, _, err := env.db.ListEvents("acme.order.finalize", "", 50, 0)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		if len(events) < 3 {
			t.Errorf("expected >=3 acme.order.finalize audit events, got %d", len(events))
		}
		// The tamper-evident event chain must still verify.
		res, err := env.db.VerifyEventChain()
		if err != nil {
			t.Fatalf("VerifyEventChain: %v", err)
		}
		if !res.Valid {
			t.Errorf("event chain invalid after ACME operations: %s", res.Reason)
		}
		// Orders and accounts are visible in the operator inventory.
		orders, err := env.db.ListACMEOrders(100, 0)
		if err != nil {
			t.Fatalf("ListACMEOrders: %v", err)
		}
		if len(orders) < 3 {
			t.Errorf("expected >=3 ACME orders recorded, got %d", len(orders))
		}
		accounts, err := env.db.ListACMEAccounts(100, 0)
		if err != nil {
			t.Fatalf("ListACMEAccounts: %v", err)
		}
		if len(accounts) < 3 {
			t.Errorf("expected >=3 ACME accounts recorded, got %d", len(accounts))
		}
	})
}
