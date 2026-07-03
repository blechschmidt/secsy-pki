//go:build sqlite

package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// gateProvider simulates an HSM outage for the public-responder tests: while
// down, opening a signer (or any key operation) fails.
type gateProvider struct {
	keyprovider.Provider
	mu   sync.Mutex
	down bool
}

func (g *gateProvider) setDown(d bool) { g.mu.Lock(); g.down = d; g.mu.Unlock() }

func (g *gateProvider) gate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.down {
		return fmt.Errorf("simulated HSM outage")
	}
	return nil
}

func (g *gateProvider) Signer(ctx context.Context, ref keyprovider.KeyRef) (keyprovider.Signer, error) {
	if err := g.gate(); err != nil {
		return nil, err
	}
	return g.Provider.Signer(ctx, ref)
}

func (g *gateProvider) FindKey(ctx context.Context, ref keyprovider.KeyRef) (*keyprovider.KeyInfo, error) {
	if err := g.gate(); err != nil {
		return nil, err
	}
	return g.Provider.FindKey(ctx, ref)
}

func (g *gateProvider) GenerateKey(ctx context.Context, spec keyprovider.KeySpec) (*keyprovider.KeyInfo, error) {
	if err := g.gate(); err != nil {
		return nil, err
	}
	return g.Provider.GenerateKey(ctx, spec)
}

// testCSR builds a PEM CSR for one DNS name.
func testCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// ocspHTTP drives the public OCSP endpoint the way a relying party would.
func ocspHTTP(t *testing.T, api *API, caID string, method string, reqDER []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	switch method {
	case http.MethodPost:
		r = httptest.NewRequest(http.MethodPost, "/api/ca/"+caID+"/ocsp", bytes.NewReader(reqDER))
	case http.MethodGet:
		encoded := base64.StdEncoding.EncodeToString(reqDER)
		r = httptest.NewRequest(http.MethodGet, "/api/ca/"+caID+"/ocsp/req", nil)
		r.SetPathValue("req", encoded)
	default:
		t.Fatalf("unsupported method %s", method)
	}
	r.SetPathValue("id", caID)
	rec := httptest.NewRecorder()
	api.OCSPResponder(rec, r)
	return rec
}

// TestOCSPResponderServesPresignedThroughOutage is the end-to-end HSM-offload
// proof at the HTTP layer: with pre-signing enabled, the public responder
// answers GET and POST requests for known serials from the cache while the key
// provider is completely down; nonce-bearing requests correctly degrade to
// tryLater (they must be freshly signed per RFC 8954); and a serial first seen
// during the outage is answered from cache after the next batch because the
// responder tracked it as recently queried.
func TestOCSPResponderServesPresignedThroughOutage(t *testing.T) {
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	sw, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { sw.Close() })
	gated := &gateProvider{Provider: sw}

	api := NewAPI(db, gated, nil, hsm.Config{}, true, "")
	api.SetOCSPPolicy(OCSPPolicy{NonceEnabled: true, NonceMaxAge: time.Minute}, 0, "")

	ctx := context.Background()
	mgr := ca.NewManager(db, gated)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    "presign-http-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Presign HTTP Root"}),
		Validity: 24 * time.Hour * 365,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert, err := pki.ParseCertificatePEM([]byte(root.Certificate))
	if err != nil {
		t.Fatalf("parsing root: %v", err)
	}
	leaf, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:    root.ID,
		CSRPEM:  testCSR(t, "presign.example.com"),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	tracker := ca.NewRecentSerialTracker(0)
	api.SetOCSPRecentTracker(tracker)
	presigner := ca.NewOCSPPresigner(mgr, ca.OCSPPresignerConfig{
		Validity: time.Hour,
		Cache:    api.OCSPCache(),
		Recent:   tracker,
	})
	if _, err := presigner.Run(ctx); err != nil {
		t.Fatalf("presign: %v", err)
	}

	// The HSM goes away entirely.
	gated.setDown(true)

	// Known serial, POST and GET forms: served from the pre-signed cache.
	reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		rec := ocspHTTP(t, api, root.ID, method, reqDER)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s during outage: status %d", method, rec.Code)
		}
		parsed, err := ocsp.ParseResponse(rec.Body.Bytes(), rootCert)
		if err != nil {
			t.Fatalf("%s during outage: response invalid: %v", method, err)
		}
		if parsed.Status != ocsp.Good {
			t.Errorf("%s during outage: status = %d, want good", method, parsed.Status)
		}
		if !parsed.NextUpdate.After(time.Now()) {
			t.Errorf("%s during outage: served an expired response", method)
		}
	}

	// A nonce-bearing request must not be served from cache: with the HSM down
	// it degrades to tryLater rather than replaying an unbound response.
	nonceReq, err := pki.BuildOCSPRequestWithNonce(rootCert, leaf.Serial, bytes.Repeat([]byte{0xA5}, 16))
	if err != nil {
		t.Fatalf("BuildOCSPRequestWithNonce: %v", err)
	}
	rec := ocspHTTP(t, api, root.ID, http.MethodPost, nonceReq)
	if !bytes.Equal(rec.Body.Bytes(), pki.OCSPTryLaterResponse) {
		t.Fatalf("nonce request during outage: got %x, want tryLater", rec.Body.Bytes())
	}

	// An unknown serial misses the cache -> tryLater, but is now tracked as
	// recently queried.
	unknown := big.NewInt(987654321)
	unknownReq, err := pki.BuildOCSPRequestForSerial(rootCert, unknown)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	rec = ocspHTTP(t, api, root.ID, http.MethodPost, unknownReq)
	if !bytes.Equal(rec.Body.Bytes(), pki.OCSPTryLaterResponse) {
		t.Fatalf("unknown serial during outage: got %x, want tryLater", rec.Body.Bytes())
	}

	// HSM returns; the next batch covers the serial queried during the outage.
	gated.setDown(false)
	if _, err := presigner.Run(ctx); err != nil {
		t.Fatalf("presign after recovery: %v", err)
	}
	gated.setDown(true)

	rec = ocspHTTP(t, api, root.ID, http.MethodPost, unknownReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("recently-queried serial after refresh: status %d", rec.Code)
	}
	parsed, err := ocsp.ParseResponse(rec.Body.Bytes(), rootCert)
	if err != nil {
		t.Fatalf("recently-queried serial: response invalid: %v", err)
	}
	if parsed.Status != ocsp.Unknown {
		t.Errorf("recently-queried serial: status = %d, want unknown", parsed.Status)
	}

	// Revocation invalidates the cached entry, so during an outage the status
	// change is not silently masked by a stale "good" — the responder answers
	// tryLater until a fresh (revoked) response can be signed.
	gated.setDown(false)
	if _, err := mgr.RevokeCertificate(ctx, root.ID, leaf.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	api.InvalidateOCSPCache(root.ID, leaf.Serial.String())
	rec = ocspHTTP(t, api, root.ID, http.MethodPost, reqDER)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-revocation: status %d", rec.Code)
	}
	parsed, err = ocsp.ParseResponse(rec.Body.Bytes(), rootCert)
	if err != nil {
		t.Fatalf("post-revocation response invalid: %v", err)
	}
	if parsed.Status != ocsp.Revoked {
		t.Errorf("post-revocation status = %d, want revoked", parsed.Status)
	}
}
