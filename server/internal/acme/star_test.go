//go:build sqlite

package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// base64CSR builds a fresh CSR for the domain and base64url-encodes its DER for a
// finalize request payload.
func base64CSR(t *testing.T, domain string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(csrFor(t, domain))
}

// These tests cover ACME STAR short-term auto-renewed certificates (Task 136,
// RFC 8739). Like the ACME Profiles and pre-authorization tests they drive the
// raw-JWS client from profile_test.go, since the golang.org/x/crypto/acme client
// has no notion of the "auto-renewal" object, the "star-certificate" URL, or
// order cancellation.

// withStar enables STAR on the test server with the default bounds (1h min
// lifetime, 7d max lifetime, 365d max duration).
func withStar(cfg *Config) { cfg.Star = &StarConfig{} }

// rawStarOrder decodes the STAR-relevant fields of an order object.
type rawStarOrder struct {
	Status          string   `json:"status"`
	Expires         string   `json:"expires"`
	Authorizations  []string `json:"authorizations"`
	Finalize        string   `json:"finalize"`
	Certificate     string   `json:"certificate"`
	StarCertificate string   `json:"star-certificate"`
	AutoRenewal     *struct {
		StartDate           string `json:"start-date"`
		EndDate             string `json:"end-date"`
		Lifetime            int64  `json:"lifetime"`
		AllowCertificateGet bool   `json:"allow-certificate-get"`
	} `json:"auto-renewal"`
}

// newStarOrder posts a newOrder for a single DNS identifier carrying the given
// "auto-renewal" object. It returns the response, raw body, and the order URL.
func (rc *rawClient) newStarOrder(domain string, autoRenewal map[string]any) (*http.Response, []byte, string) {
	rc.t.Helper()
	req := map[string]any{
		"identifiers":  []map[string]string{{"type": "dns", "value": domain}},
		"auto-renewal": autoRenewal,
	}
	payload, _ := json.Marshal(req)
	resp, body := rc.post(rc.dir.NewOrder, payload, false)
	return resp, body, resp.Header.Get("Location")
}

// directoryAutoRenewal fetches the directory and returns its meta.auto-renewal
// advertisement (nil when absent).
func directoryAutoRenewal(t *testing.T, dirURL string) *struct {
	MinLifetime         int64 `json:"min-lifetime"`
	MaxDuration         int64 `json:"max-duration"`
	AllowCertificateGet bool  `json:"allow-certificate-get"`
} {
	t.Helper()
	resp, err := http.Get(dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var dir struct {
		Meta struct {
			AutoRenewal *struct {
				MinLifetime         int64 `json:"min-lifetime"`
				MaxDuration         int64 `json:"max-duration"`
				AllowCertificateGet bool  `json:"allow-certificate-get"`
			} `json:"auto-renewal"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	return dir.Meta.AutoRenewal
}

// starLeaf fetches a PEM certificate chain body, parses the leaf, and returns it.
func starLeaf(t *testing.T, chain []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatalf("star-certificate response is not PEM: %s", chain)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse star leaf: %v", err)
	}
	return leaf
}

// TestACME_STAR_FullFlow drives the whole RFC 8739 lifecycle with the raw-JWS
// client: the directory advertises meta.auto-renewal; a STAR newOrder is placed,
// validated, and finalized into a short-lived certificate exposed at a stable
// star-certificate URL; that URL is fetched via both an unauthenticated GET
// (allow-certificate-get) and an authenticated POST-as-GET; the background renewer
// re-issues a fresh certificate at the same URL; and canceling the order stops
// renewal and makes the star-certificate URL answer 403.
func TestACME_STAR_FullFlow(t *testing.T) {
	env := newTestEnv(t, withStar)

	// 1. The directory advertises meta.auto-renewal with the configured bounds.
	meta := directoryAutoRenewal(t, env.dirURL)
	if meta == nil {
		t.Fatal("directory does not advertise meta.auto-renewal with STAR enabled")
	}
	if meta.MinLifetime != int64((time.Hour).Seconds()) {
		t.Errorf("meta.auto-renewal.min-lifetime = %d, want %d", meta.MinLifetime, int64((time.Hour).Seconds()))
	}
	if !meta.AllowCertificateGet {
		t.Error("meta.auto-renewal.allow-certificate-get = false, want true")
	}

	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "star.example.test"
	endDate := time.Now().Add(30 * 24 * time.Hour).UTC()

	// 2. Place a STAR order (1h certificates, unauthenticated GET allowed).
	resp, body, orderURL := rc.newStarOrder(domain, map[string]any{
		"end-date":              endDate.Format(time.RFC3339),
		"lifetime":              3600,
		"allow-certificate-get": true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("STAR newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	var order rawStarOrder
	if err := json.Unmarshal(body, &order); err != nil {
		t.Fatalf("decode STAR order: %v (%s)", err, body)
	}
	if order.AutoRenewal == nil {
		t.Fatalf("STAR order did not echo auto-renewal: %s", body)
	}
	if order.AutoRenewal.Lifetime != 3600 || !order.AutoRenewal.AllowCertificateGet {
		t.Errorf("echoed auto-renewal = %+v, want lifetime 3600 + allow-certificate-get", order.AutoRenewal)
	}

	// The order must be persisted as a STAR order.
	orderID := orderURL[strings.LastIndex(orderURL, "/")+1:]
	stored, err := env.db.GetACMEOrder(orderID)
	if err != nil || stored == nil || stored.AutoRenewal == nil {
		t.Fatalf("stored order is not a STAR order: %+v (%v)", stored, err)
	}

	// 3. Validate the single authorization and finalize.
	rc.solveHTTP01(env, order.Authorizations[0])
	rc.waitStatus(orderURL, "ready")
	csr := base64CSR(t, domain)
	fresp, fbody := rc.post(order.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d, want 200: %s", fresp.StatusCode, fbody)
	}
	var finalized rawStarOrder
	if err := json.Unmarshal(fbody, &finalized); err != nil {
		t.Fatalf("decode finalized STAR order: %v", err)
	}
	if finalized.Status != "valid" {
		t.Fatalf("finalized STAR order status = %q, want valid: %s", finalized.Status, fbody)
	}
	// A STAR order exposes star-certificate, NOT the one-shot certificate URL.
	if finalized.StarCertificate == "" {
		t.Fatalf("finalized STAR order has no star-certificate URL: %s", fbody)
	}
	if finalized.Certificate != "" {
		t.Errorf("finalized STAR order also carries a one-shot certificate URL %q, want only star-certificate", finalized.Certificate)
	}
	// expires reflects the recurrence horizon (end-date).
	if finalized.Expires[:19] != endDate.Format(time.RFC3339)[:19] {
		t.Errorf("STAR order expires = %q, want the end-date %q", finalized.Expires, endDate.Format(time.RFC3339))
	}
	starURL := finalized.StarCertificate

	// 4a. Fetch the star-certificate with an unauthenticated GET (§3.4) and verify
	//     it chains to the test roots and names the domain.
	getResp, err := http.Get(starURL)
	if err != nil {
		t.Fatalf("GET star-certificate: %v", err)
	}
	getBody, _ := io.ReadAll(getResp.Body)
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("unauthenticated GET star-certificate status = %d, want 200: %s", getResp.StatusCode, getBody)
	}
	leaf1 := starLeaf(t, getBody)
	if _, err := leaf1.Verify(x509.VerifyOptions{Roots: env.roots, Intermediates: env.inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if len(leaf1.DNSNames) == 0 || leaf1.DNSNames[0] != domain {
		t.Fatalf("star leaf DNS names = %v, want %q", leaf1.DNSNames, domain)
	}
	// The certificate is short-lived (~1h), proving the STAR lifetime governed it.
	if life := leaf1.NotAfter.Sub(leaf1.NotBefore); life > 3*time.Hour {
		t.Errorf("star leaf lifetime = %s, want the short STAR lifetime (~1h)", life)
	}

	// 4b. The same URL is also fetchable via authenticated POST-as-GET.
	presp, pbody := rc.post(starURL, nil, false)
	if presp.StatusCode != http.StatusOK {
		t.Fatalf("POST-as-GET star-certificate status = %d, want 200: %s", presp.StatusCode, pbody)
	}
	if starLeaf(t, pbody).SerialNumber.Cmp(leaf1.SerialNumber) != 0 {
		t.Error("POST-as-GET returned a different certificate than the GET")
	}

	// 5. Force the background renewer past the first certificate's renewal deadline
	//    and confirm it re-issues a FRESH certificate at the same stable URL.
	env.srv.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	n, err := env.srv.RenewDueSTAROrders(context.Background())
	if err != nil {
		t.Fatalf("RenewDueSTAROrders: %v", err)
	}
	if n != 1 {
		t.Fatalf("renewer re-issued %d certificates, want 1", n)
	}
	getResp2, err := http.Get(starURL)
	if err != nil {
		t.Fatalf("GET star-certificate after renewal: %v", err)
	}
	getBody2, _ := io.ReadAll(getResp2.Body)
	_ = getResp2.Body.Close()
	leaf2 := starLeaf(t, getBody2)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) == 0 {
		t.Fatal("star-certificate serial did not change after renewal")
	}
	// The renewed certificate is the same key and identifier (a true renewal).
	if len(leaf2.DNSNames) == 0 || leaf2.DNSNames[0] != domain {
		t.Fatalf("renewed star leaf DNS names = %v, want %q", leaf2.DNSNames, domain)
	}

	// 6. Cancel the recurrence (RFC 8739 §3.5).
	cresp, cbody := rc.post(orderURL, []byte(`{"status":"canceled"}`), false)
	if cresp.StatusCode != http.StatusOK {
		t.Fatalf("cancel status = %d, want 200: %s", cresp.StatusCode, cbody)
	}
	var canceled rawStarOrder
	if err := json.Unmarshal(cbody, &canceled); err != nil {
		t.Fatalf("decode canceled order: %v", err)
	}
	if canceled.Status != "canceled" {
		t.Fatalf("canceled order status = %q, want canceled: %s", canceled.Status, cbody)
	}

	// 6a. The renewer must not touch a canceled order.
	if n, err := env.srv.RenewDueSTAROrders(context.Background()); err != nil || n != 0 {
		t.Fatalf("renewer processed a canceled order: n=%d err=%v", n, err)
	}

	// 6b. The star-certificate URL now answers 403 autoRenewalCanceled, on both the
	//     unauthenticated GET and the authenticated POST-as-GET.
	cgetResp, err := http.Get(starURL)
	if err != nil {
		t.Fatalf("GET canceled star-certificate: %v", err)
	}
	cgetBody, _ := io.ReadAll(cgetResp.Body)
	_ = cgetResp.Body.Close()
	if cgetResp.StatusCode != http.StatusForbidden {
		t.Fatalf("canceled GET status = %d, want 403: %s", cgetResp.StatusCode, cgetBody)
	}
	var prob Problem
	if err := json.Unmarshal(cgetBody, &prob); err != nil || prob.Type != probAutoRenewalCanceled {
		t.Fatalf("canceled GET problem = %q (%v), want %q", prob.Type, err, probAutoRenewalCanceled)
	}
	cpResp, cpBody := rc.post(starURL, nil, false)
	if cpResp.StatusCode != http.StatusForbidden {
		t.Fatalf("canceled POST-as-GET status = %d, want 403: %s", cpResp.StatusCode, cpBody)
	}
	var pprob Problem
	if err := json.Unmarshal(cpBody, &pprob); err != nil || pprob.Type != probAutoRenewalCanceled {
		t.Fatalf("canceled POST-as-GET problem = %q (%v), want %q", pprob.Type, err, probAutoRenewalCanceled)
	}
}

// TestACME_STAR_Disabled confirms that with STAR disabled the directory omits
// meta.auto-renewal, an "auto-renewal" object on a newOrder is ignored (a normal,
// non-STAR order results, per RFC 8739 §3), and the star-certificate route answers
// a well-formed ACME problem rather than a bare 404.
func TestACME_STAR_Disabled(t *testing.T) {
	env := newTestEnv(t) // STAR off
	if meta := directoryAutoRenewal(t, env.dirURL); meta != nil {
		t.Fatalf("directory advertises meta.auto-renewal while STAR disabled: %+v", meta)
	}

	rc := newRawClient(t, env.dirURL)
	rc.register()

	resp, body, orderURL := rc.newStarOrder("plain.example.test", map[string]any{
		"end-date": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		"lifetime": 3600,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	var order rawStarOrder
	_ = json.Unmarshal(body, &order)
	if order.AutoRenewal != nil {
		t.Errorf("disabled server echoed an auto-renewal object: %+v", order.AutoRenewal)
	}
	// The order is a normal order, not a STAR order.
	id := orderURL[strings.LastIndex(orderURL, "/")+1:]
	stored, _ := env.db.GetACMEOrder(id)
	if stored == nil || stored.AutoRenewal != nil {
		t.Fatalf("disabled server created a STAR order: %+v", stored)
	}

	// The star-certificate route is still mounted; it answers an ACME problem.
	sresp, sbody := rc.post(env.baseURL+"/acme/star-cert/"+id, nil, false)
	if sresp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled star-cert status = %d, want 404: %s", sresp.StatusCode, sbody)
	}
	var prob Problem
	if err := json.Unmarshal(sbody, &prob); err != nil {
		t.Fatalf("disabled star-cert did not return a JSON problem: %v (%s)", err, sbody)
	}
	if !strings.HasPrefix(prob.Type, "urn:ietf:params:acme:error:") {
		t.Errorf("problem type = %q, want a urn:ietf:params:acme:error:* type", prob.Type)
	}
}

// TestACME_STAR_ValidationRejected confirms newOrder rejects an auto-renewal
// object that violates the server's bounds: a lifetime below the minimum, a
// missing end-date, and an end-date in the past all yield a malformed problem and
// no order.
func TestACME_STAR_ValidationRejected(t *testing.T) {
	env := newTestEnv(t, withStar)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	future := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name string
		ar   map[string]any
	}{
		{"lifetime-below-min", map[string]any{"end-date": future, "lifetime": 60}},             // 60s < 1h
		{"lifetime-above-max", map[string]any{"end-date": future, "lifetime": 30 * 24 * 3600}}, // 30d > 7d max
		{"missing-end-date", map[string]any{"lifetime": 3600}},
		{"missing-lifetime", map[string]any{"end-date": future}},
		{"end-date-in-past", map[string]any{"end-date": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "lifetime": 3600}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body, _ := rc.newStarOrder(tc.name+".example.test", tc.ar)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("newOrder status = %d, want 400: %s", resp.StatusCode, body)
			}
			var prob Problem
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatalf("decode problem: %v (%s)", err, body)
			}
			if prob.Type != probMalformed {
				t.Errorf("problem type = %q, want %q", prob.Type, probMalformed)
			}
		})
	}
}

// TestACME_STAR_RenewalStopsAtEndDate confirms the renewer ends the recurrence
// once the end-date passes: it issues no further certificate and clears the
// order's renewal deadline so the order drops out of the due-set.
func TestACME_STAR_RenewalStopsAtEndDate(t *testing.T) {
	env := newTestEnv(t, withStar)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "shortstar.example.test"
	// A recurrence whose horizon is only 90 minutes out: after the first 1h
	// certificate one renewal fits, then the horizon passes.
	endDate := time.Now().Add(90 * time.Minute).UTC()
	resp, body, orderURL := rc.newStarOrder(domain, map[string]any{
		"end-date": endDate.Format(time.RFC3339),
		"lifetime": 3600,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("STAR newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	var order rawStarOrder
	_ = json.Unmarshal(body, &order)
	rc.solveHTTP01(env, order.Authorizations[0])
	rc.waitStatus(orderURL, "ready")
	csr := base64CSR(t, domain)
	if r, b := rc.post(order.Finalize, []byte(`{"csr":"`+csr+`"}`), false); r.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d: %s", r.StatusCode, b)
	}
	orderID := orderURL[strings.LastIndex(orderURL, "/")+1:]

	// Jump past the end-date: the renewer must end the recurrence, issuing nothing.
	env.srv.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	n, err := env.srv.RenewDueSTAROrders(context.Background())
	if err != nil {
		t.Fatalf("RenewDueSTAROrders: %v", err)
	}
	if n != 0 {
		t.Fatalf("renewer issued %d certificates past the end-date, want 0", n)
	}
	// The recurrence is ended: the order keeps its last certificate but has no
	// renewal deadline, so it is no longer due.
	ended, err := env.db.GetACMEOrder(orderID)
	if err != nil || ended == nil {
		t.Fatalf("GetACMEOrder: %v", err)
	}
	if ended.StarNextRenewal != nil {
		t.Errorf("ended STAR order still has a renewal deadline %v, want nil", ended.StarNextRenewal)
	}
	if ended.Certificate == "" {
		t.Error("ended STAR order lost its last certificate")
	}
}
