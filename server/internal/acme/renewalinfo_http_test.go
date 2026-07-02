//go:build sqlite

package acme

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// issueOneCert drives a full http-01 order to a finalized certificate and
// returns the issued leaf, so ARI tests have a real, stored certificate to look
// up by its CertID.
func (env *testEnv) issueOneCert(t *testing.T, domain string) (*xacme.Client, *xacmeLeaf) {
	t.Helper()
	c := env.client(t)
	ctx := context.Background()
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
	leaf := parseLeaf(t, der[0])
	return c, leaf
}

// TestARIDirectoryAdvertised confirms the directory advertises the renewalInfo
// resource (draft-ietf-acme-ari §4.1).
func TestARIDirectoryAdvertised(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Get(env.dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer resp.Body.Close()
	var dir map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	ri, ok := dir["renewalInfo"].(string)
	if !ok || ri == "" {
		t.Fatalf("directory does not advertise renewalInfo: %v", dir["renewalInfo"])
	}
	if want := env.baseURL + "/acme/renewal-info"; ri != want {
		t.Errorf("renewalInfo = %q, want %q", ri, want)
	}
}

// TestARIRenewalInfoNormalWindow issues a certificate, fetches its renewal info,
// and checks that a sensible in-validity window and Retry-After are returned.
func TestARIRenewalInfoNormalWindow(t *testing.T) {
	env := newTestEnv(t)
	_, leaf := env.issueOneCert(t, "ari.example.test")

	certID, err := certIDForCertificate(leaf.AuthorityKeyId, leaf.SerialNumber)
	if err != nil {
		t.Fatalf("certID: %v", err)
	}

	resp, err := http.Get(env.baseURL + "/acme/renewal-info/" + certID)
	if err != nil {
		t.Fatalf("GET renewal-info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renewal-info status = %d, want 200", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("renewal-info response missing Retry-After header")
	} else if n, _ := strconv.Atoi(ra); n <= 0 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", ra)
	}

	var ri wireRenewalInfo
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		t.Fatalf("decode renewal-info: %v", err)
	}
	start, err := time.Parse(time.RFC3339, ri.SuggestedWindow.Start)
	if err != nil {
		t.Fatalf("parse window start %q: %v", ri.SuggestedWindow.Start, err)
	}
	end, err := time.Parse(time.RFC3339, ri.SuggestedWindow.End)
	if err != nil {
		t.Fatalf("parse window end %q: %v", ri.SuggestedWindow.End, err)
	}
	if !end.After(start) {
		t.Errorf("suggested window is empty or inverted: [%s, %s)", start, end)
	}
	if end.After(leaf.NotAfter) {
		t.Errorf("suggested window end %s is after the certificate expiry %s", end, leaf.NotAfter)
	}
}

// TestARIRenewalInfoUnknownCert returns 404 for a certificate the CA never
// issued.
func TestARIRenewalInfoUnknownCert(t *testing.T) {
	env := newTestEnv(t)
	// Well-formed CertID whose AKI matches no CA.
	fakeID := "AAAAAAAAAAAAAAAAAAAAAAAAAAA.AIdlQyE"
	resp, err := http.Get(env.baseURL + "/acme/renewal-info/" + fakeID)
	if err != nil {
		t.Fatalf("GET renewal-info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status for unknown cert = %d, want 404", resp.StatusCode)
	}
}

// TestARIRenewalInfoMalformed rejects a CertID that is not the documented shape.
func TestARIRenewalInfoMalformed(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Get(env.baseURL + "/acme/renewal-info/not-a-valid-certid")
	if err != nil {
		t.Fatalf("GET renewal-info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status for malformed CertID = %d, want 400", resp.StatusCode)
	}
}

// TestARIRevokedShortensWindow verifies a revoked certificate yields a window
// ending at/before now, telling the client to renew immediately.
func TestARIRevokedShortensWindow(t *testing.T) {
	env := newTestEnv(t)
	c, leaf := env.issueOneCert(t, "revoked.example.test")

	ctx := context.Background()
	if err := c.RevokeCert(ctx, nil, leaf.der, xacme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}

	certID, err := certIDForCertificate(leaf.AuthorityKeyId, leaf.SerialNumber)
	if err != nil {
		t.Fatalf("certID: %v", err)
	}
	resp, err := http.Get(env.baseURL + "/acme/renewal-info/" + certID)
	if err != nil {
		t.Fatalf("GET renewal-info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var ri wireRenewalInfo
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		t.Fatalf("decode: %v", err)
	}
	end, _ := time.Parse(time.RFC3339, ri.SuggestedWindow.End)
	if end.After(time.Now().Add(1 * time.Minute)) {
		t.Errorf("revoked certificate window end %s should be ~now, not in the future", end)
	}
}

// TestARIRotatingShortensWindow verifies that when the issuing CA key has been
// superseded (a rotation is in progress), leaves signed by it are told to renew
// immediately so they migrate onto the new key.
func TestARIRotatingShortensWindow(t *testing.T) {
	env := newTestEnv(t)
	_, leaf := env.issueOneCert(t, "rotating.example.test")

	// Simulate a rollover: the signing CA is now superseded by a fresh key.
	if err := env.db.SetCAStatus(env.caID, models.CAStatusSuperseded); err != nil {
		t.Fatalf("SetCAStatus: %v", err)
	}

	certID, err := certIDForCertificate(leaf.AuthorityKeyId, leaf.SerialNumber)
	if err != nil {
		t.Fatalf("certID: %v", err)
	}
	resp, err := http.Get(env.baseURL + "/acme/renewal-info/" + certID)
	if err != nil {
		t.Fatalf("GET renewal-info: %v", err)
	}
	defer resp.Body.Close()
	var ri wireRenewalInfo
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		t.Fatalf("decode: %v", err)
	}
	end, _ := time.Parse(time.RFC3339, ri.SuggestedWindow.End)
	if end.After(time.Now().Add(1 * time.Minute)) {
		t.Errorf("rotating-CA window end %s should be ~now, not in the future", end)
	}
}

// TestARIReplacesLinkage exercises the newOrder "replaces" authorization path
// through resolveReplaces: the owning account may link, a duplicate is rejected
// as alreadyReplaced, and an unknown certificate is rejected.
func TestARIReplacesLinkage(t *testing.T) {
	env := newTestEnv(t)
	_, leaf := env.issueOneCert(t, "replaces.example.test")

	// Recover the account that ordered the certificate.
	predOrder, err := env.db.GetACMEOrderByCertificate(env.caID, leaf.SerialNumber.String())
	if err != nil || predOrder == nil {
		t.Fatalf("GetACMEOrderByCertificate: order=%v err=%v", predOrder, err)
	}
	rec, err := env.db.GetACMEAccount(predOrder.AccountID)
	if err != nil || rec == nil {
		t.Fatalf("GetACMEAccount: %v", err)
	}
	acct := &acmeAccount{rec: rec}

	certID, err := certIDForCertificate(leaf.AuthorityKeyId, leaf.SerialNumber)
	if err != nil {
		t.Fatalf("certID: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, env.baseURL+"/acme/new-order", nil)

	// The owning account may link the renewal to its predecessor.
	got, prob := env.srv.resolveReplaces(r, acct, certID)
	if prob != nil {
		t.Fatalf("resolveReplaces (owner): unexpected problem %v", prob)
	}
	if got != certID {
		t.Errorf("canonical CertID = %q, want %q", got, certID)
	}

	// Persist an order that records the replacement, then a second attempt must be
	// rejected as alreadyReplaced.
	dup := &models.ACMEOrder{
		ID:          newUUID(),
		AccountID:   rec.ID,
		Status:      models.ACMEOrderStatusPending,
		Identifiers: []models.ACMEIdentifier{{Type: "dns", Value: "replaces.example.test"}},
		Expires:     time.Now().Add(time.Hour),
		Replaces:    got,
	}
	if err := env.db.CreateACMEOrder(dup); err != nil {
		t.Fatalf("CreateACMEOrder: %v", err)
	}
	if _, prob := env.srv.resolveReplaces(r, acct, certID); prob == nil || prob.Type != probAlreadyReplaced {
		t.Errorf("second replaces attempt: got %v, want alreadyReplaced", prob)
	}

	// An unknown certificate is rejected.
	unknown := "AAAAAAAAAAAAAAAAAAAAAAAAAAA.AIdlQyE"
	if _, prob := env.srv.resolveReplaces(r, acct, unknown); prob == nil {
		t.Error("replaces with an unknown certificate must be rejected")
	}
}

// ---- small leaf helper ----------------------------------------------------

// xacmeLeaf pairs a parsed leaf certificate with its DER encoding so tests can
// both inspect its fields and pass the raw bytes to RevokeCert.
type xacmeLeaf struct {
	*x509.Certificate
	der []byte
}

func parseLeaf(t *testing.T, der []byte) *xacmeLeaf {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing issued leaf: %v", err)
	}
	return &xacmeLeaf{Certificate: c, der: der}
}
