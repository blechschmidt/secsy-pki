//go:build sqlite

package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// newCacheTestAPI stands up an in-memory API backed by a software key provider
// with a root CA and one issued leaf, for exercising the RFC 5019 §6.2 caching
// headers on the public OCSP and CRL handlers (Task 126). Nonce echoing is
// enabled so the no-store invariant can be exercised.
func newCacheTestAPI(t *testing.T) (api *API, rootID string, rootCert *x509.Certificate, leaf *ca.IssueResult) {
	t.Helper()
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

	api = NewAPI(db, sw, nil, hsm.Config{}, true, "")
	api.SetOCSPPolicy(OCSPPolicy{NonceEnabled: true, NonceMaxAge: time.Minute}, 0, "")

	ctx := context.Background()
	mgr := ca.NewManager(db, sw)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    "cache-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Cache Root"}),
		Validity: 24 * time.Hour * 365,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert, err = pki.ParseCertificatePEM([]byte(root.Certificate))
	if err != nil {
		t.Fatalf("parsing root: %v", err)
	}
	leaf, err = mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:    root.ID,
		CSRPEM:  testCSR(t, "cache.example.com"),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	return api, root.ID, rootCert, leaf
}

// doOCSP drives the public OCSP endpoint with the given method, request DER, and
// optional request headers (for conditional requests).
func doOCSP(t *testing.T, api *API, caID, method string, reqDER []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	switch method {
	case http.MethodPost:
		r = httptest.NewRequest(http.MethodPost, "/api/ca/"+caID+"/ocsp", bytes.NewReader(reqDER))
	case http.MethodGet:
		r = httptest.NewRequest(http.MethodGet, "/api/ca/"+caID+"/ocsp/req", nil)
		r.SetPathValue("req", base64.StdEncoding.EncodeToString(reqDER))
	default:
		t.Fatalf("unsupported method %s", method)
	}
	r.SetPathValue("id", caID)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	api.OCSPResponder(rec, r)
	return rec
}

// doCRL drives the public base/delta CRL handlers with optional request headers.
func doCRL(t *testing.T, api *API, caID string, delta bool, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/ca/" + caID + "/crl"
	if delta {
		path += "/delta"
	}
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.SetPathValue("id", caID)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	if delta {
		api.GetDeltaCRL(rec, r)
	} else {
		api.GetCRL(rec, r)
	}
	return rec
}

// parseMaxAge extracts the max-age delta-seconds from a Cache-Control field.
func parseMaxAge(t *testing.T, cacheControl string) int64 {
	t.Helper()
	for _, part := range strings.Split(cacheControl, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				t.Fatalf("unparseable max-age %q: %v", v, err)
			}
			return n
		}
	}
	t.Fatalf("no max-age directive in Cache-Control %q", cacheControl)
	return 0
}

// assertStrongETag fails unless etag is a quoted, non-weak validator.
func assertStrongETag(t *testing.T, etag string) {
	t.Helper()
	if etag == "" {
		t.Fatal("missing ETag")
	}
	if strings.HasPrefix(etag, "W/") {
		t.Errorf("ETag %q is weak, want a strong validator", etag)
	}
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Errorf("ETag %q is not a quoted-string", etag)
	}
}

// TestOCSPResponseCacheHeaders asserts a normal (nonce-less) OCSP response
// carries the RFC 5019 §6.2 caching headers derived from its own validity window.
func TestOCSPResponseCacheHeaders(t *testing.T) {
	api, rootID, rootCert, leaf := newCacheTestAPI(t)
	reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	rec := doOCSP(t, api, rootID, http.MethodGet, reqDER, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := rec.Header()
	if ct := h.Get("Content-Type"); ct != "application/ocsp-response" {
		t.Errorf("Content-Type = %q, want application/ocsp-response", ct)
	}

	cc := h.Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want public + max-age", cc)
	}
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") {
		t.Errorf("Cache-Control = %q, must be cacheable for a nonce-less response", cc)
	}
	if age := parseMaxAge(t, cc); age <= 0 || age > int64(maxOCSPCacheAge/time.Second) {
		t.Errorf("max-age = %d, want in (0, %d]", age, int64(maxOCSPCacheAge/time.Second))
	}

	if _, err := http.ParseTime(h.Get("Expires")); err != nil {
		t.Errorf("Expires = %q not an HTTP date: %v", h.Get("Expires"), err)
	}
	if _, err := http.ParseTime(h.Get("Last-Modified")); err != nil {
		t.Errorf("Last-Modified = %q not an HTTP date: %v", h.Get("Last-Modified"), err)
	}

	// The ETag is a strong validator: the exact SHA-256 of the served body.
	assertStrongETag(t, h.Get("ETag"))
	if got, want := h.Get("ETag"), strongETag(rec.Body.Bytes()); got != want {
		t.Errorf("ETag = %q, want %q (hash of body)", got, want)
	}

	// Sanity: the body is a real OCSP response, undisturbed by the new headers.
	if _, err := ocsp.ParseResponse(rec.Body.Bytes(), rootCert); err != nil {
		t.Errorf("served body is not a valid OCSP response: %v", err)
	}
}

// TestOCSPNonceResponseNoStore is the critical invariant: a nonce-bearing OCSP
// response is request-bound and MUST be marked no-store with no cache validators,
// on both the POST and GET forms.
func TestOCSPNonceResponseNoStore(t *testing.T) {
	api, rootID, rootCert, leaf := newCacheTestAPI(t)
	nonce := bytes.Repeat([]byte{0x5A}, 16)
	reqDER, err := pki.BuildOCSPRequestWithNonce(rootCert, leaf.Serial, nonce)
	if err != nil {
		t.Fatalf("BuildOCSPRequestWithNonce: %v", err)
	}

	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			rec := doOCSP(t, api, rootID, method, reqDER, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			// The HSM is up, so this is a real signed response echoing the nonce,
			// not a tryLater — precisely the case that must never be cached.
			parsed, perr := ocsp.ParseResponse(rec.Body.Bytes(), rootCert)
			if perr != nil {
				t.Fatalf("response invalid: %v", perr)
			}
			if parsed.Status != ocsp.Good {
				t.Errorf("status = %d, want good", parsed.Status)
			}
			echoed, nerr := pki.OCSPResponseNonce(rec.Body.Bytes())
			if nerr != nil || !bytes.Equal(echoed, nonce) {
				t.Fatalf("nonce not echoed (err=%v, got %x), test precondition failed", nerr, echoed)
			}

			h := rec.Header()
			if cc := h.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store for a nonce response", cc)
			}
			for _, k := range []string{"ETag", "Expires", "Last-Modified"} {
				if v := h.Get(k); v != "" {
					t.Errorf("nonce response must not set %s (got %q)", k, v)
				}
			}
		})
	}
}

// TestOCSPConditionalNotModified exercises the 304 conditional-request path for
// OCSP: a matching If-None-Match or a fresh-enough If-Modified-Since yields 304
// with an empty body, while a stale validator still returns the full response.
func TestOCSPConditionalNotModified(t *testing.T) {
	api, rootID, rootCert, leaf := newCacheTestAPI(t)
	reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
	if err != nil {
		t.Fatalf("BuildOCSPRequest: %v", err)
	}
	first := doOCSP(t, api, rootID, http.MethodGet, reqDER, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	lastMod := first.Header().Get("Last-Modified")

	// If-None-Match with the current validator -> 304, empty body, validator kept.
	nm := doOCSP(t, api, rootID, http.MethodGet, reqDER, map[string]string{"If-None-Match": etag})
	if nm.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: status = %d, want 304", nm.Code)
	}
	if nm.Body.Len() != 0 {
		t.Errorf("304 body = %d bytes, want 0", nm.Body.Len())
	}
	if got := nm.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want %q", got, etag)
	}

	// A weak validator matches under the weak comparison If-None-Match requires.
	weak := doOCSP(t, api, rootID, http.MethodGet, reqDER, map[string]string{"If-None-Match": "W/" + etag})
	if weak.Code != http.StatusNotModified {
		t.Errorf("weak If-None-Match: status = %d, want 304", weak.Code)
	}

	// A stale validator falls through to the full 200 response.
	stale := doOCSP(t, api, rootID, http.MethodGet, reqDER, map[string]string{"If-None-Match": `"deadbeef"`})
	if stale.Code != http.StatusOK {
		t.Errorf("stale If-None-Match: status = %d, want 200", stale.Code)
	}

	// If-Modified-Since at thisUpdate (its Last-Modified) -> 304.
	ims := doOCSP(t, api, rootID, http.MethodGet, reqDER, map[string]string{"If-Modified-Since": lastMod})
	if ims.Code != http.StatusNotModified {
		t.Errorf("If-Modified-Since: status = %d, want 304", ims.Code)
	}
}

// TestBaseCRLCacheHeaders asserts the base CRL handler emits caching headers and
// an ETag derived from the CRL number plus the served bytes.
func TestBaseCRLCacheHeaders(t *testing.T) {
	api, rootID, _, _ := newCacheTestAPI(t)
	rec := doCRL(t, api, rootID, false, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	h := rec.Header()
	if ct := h.Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", ct)
	}
	cc := h.Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want public + max-age", cc)
	}
	if age := parseMaxAge(t, cc); age <= 0 || age > int64(maxCRLCacheAge/time.Second) {
		t.Errorf("max-age = %d, want in (0, %d]", age, int64(maxCRLCacheAge/time.Second))
	}
	if _, err := http.ParseTime(h.Get("Expires")); err != nil {
		t.Errorf("Expires = %q not an HTTP date: %v", h.Get("Expires"), err)
	}
	if _, err := http.ParseTime(h.Get("Last-Modified")); err != nil {
		t.Errorf("Last-Modified = %q not an HTTP date: %v", h.Get("Last-Modified"), err)
	}

	assertStrongETag(t, h.Get("ETag"))
	number, _, _, ok := pki.CRLValidity(rec.Body.Bytes())
	if !ok {
		t.Fatal("served base CRL did not parse")
	}
	if got, want := h.Get("ETag"), strongETag(number.Bytes(), rec.Body.Bytes()); got != want {
		t.Errorf("ETag = %q, want %q (CRL number + bytes)", got, want)
	}

	// The ?format=pem variant is equally cacheable; its ETag is over the PEM
	// bytes, so it differs from the DER ETag for the same CRL.
	pemReq := httptest.NewRequest(http.MethodGet, "/api/ca/"+rootID+"/crl?format=pem", nil)
	pemReq.SetPathValue("id", rootID)
	pemRec := httptest.NewRecorder()
	api.GetCRL(pemRec, pemReq)
	if pemRec.Code != http.StatusOK {
		t.Fatalf("PEM status = %d, want 200", pemRec.Code)
	}
	ph := pemRec.Header()
	if ct := ph.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("PEM Content-Type = %q, want application/x-pem-file", ct)
	}
	if cc := ph.Get("Cache-Control"); !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=") {
		t.Errorf("PEM Cache-Control = %q, want public + max-age", cc)
	}
	if got, want := ph.Get("ETag"), strongETag(number.Bytes(), pemRec.Body.Bytes()); got != want {
		t.Errorf("PEM ETag = %q, want %q (CRL number + PEM bytes)", got, want)
	}
	if ph.Get("ETag") == h.Get("ETag") {
		t.Error("PEM and DER ETags must differ (distinct byte encodings)")
	}
}

// TestDeltaCRLCacheHeaders asserts the delta CRL handler emits caching headers,
// an ETag over its own number+bytes, and that the delta and base do not collide.
func TestDeltaCRLCacheHeaders(t *testing.T) {
	api, rootID, _, _ := newCacheTestAPI(t)
	base := doCRL(t, api, rootID, false, nil)
	if base.Code != http.StatusOK {
		t.Fatalf("base status = %d, want 200", base.Code)
	}
	rec := doCRL(t, api, rootID, true, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delta status = %d, want 200", rec.Code)
	}
	h := rec.Header()
	if ct := h.Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", ct)
	}
	cc := h.Get("Cache-Control")
	if !strings.Contains(cc, "public") || !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want public + max-age", cc)
	}
	if age := parseMaxAge(t, cc); age <= 0 {
		t.Errorf("delta max-age = %d, want > 0", age)
	}

	assertStrongETag(t, h.Get("ETag"))
	number, _, _, ok := pki.CRLValidity(rec.Body.Bytes())
	if !ok {
		t.Fatal("served delta CRL did not parse")
	}
	if got, want := h.Get("ETag"), strongETag(number.Bytes(), rec.Body.Bytes()); got != want {
		t.Errorf("delta ETag = %q, want %q (CRL number + bytes)", got, want)
	}
	if h.Get("ETag") == base.Header().Get("ETag") {
		t.Error("delta and base CRL share an ETag; they must be distinguishable")
	}
}

// TestCRLConditionalNotModified exercises the 304 path for CRLs: matching
// If-None-Match (including "*"), a fresh-enough If-Modified-Since.
func TestCRLConditionalNotModified(t *testing.T) {
	api, rootID, _, _ := newCacheTestAPI(t)
	first := doCRL(t, api, rootID, false, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	lastMod := first.Header().Get("Last-Modified")

	nm := doCRL(t, api, rootID, false, map[string]string{"If-None-Match": etag})
	if nm.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: status = %d, want 304", nm.Code)
	}
	if nm.Body.Len() != 0 {
		t.Errorf("304 body = %d bytes, want 0", nm.Body.Len())
	}

	wild := doCRL(t, api, rootID, false, map[string]string{"If-None-Match": "*"})
	if wild.Code != http.StatusNotModified {
		t.Errorf("If-None-Match *: status = %d, want 304", wild.Code)
	}

	ims := doCRL(t, api, rootID, false, map[string]string{"If-Modified-Since": lastMod})
	if ims.Code != http.StatusNotModified {
		t.Errorf("If-Modified-Since: status = %d, want 304", ims.Code)
	}
}
