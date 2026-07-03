//go:build sqlite

package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
)

// signingFixture wires a software-backed signing service into a test API:
// a self-signed CA (stored as tenant "a"'s CA so verification finds its trust
// anchor) and one ECDSA code-signing identity scoped to tenant "a".
func signingFixture(t *testing.T, api *API, db *database.DB, provider keyprovider.Provider) *x509.Certificate {
	t.Helper()
	ctx := context.Background()

	caInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "sign-ca", KeyType: keyprovider.KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := provider.Signer(ctx, keyprovider.KeyRef{Label: "sign-ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject:   pkix.Name{CommonName: "Sign Handler Test CA"},
		PublicKey: caInfo.PublicKey,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafInfo, err := provider.GenerateKey(ctx, keyprovider.KeySpec{Label: "sign-leaf", KeyType: keyprovider.KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject:     pkix.Name{CommonName: "release-signer"},
		PublicKey:   leafInfo.PublicKey,
		Serial:      big.NewInt(2),
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	if err := db.CreateCA(&models.CA{
		ID: "sign-ca-a", TenantID: "a", Label: "sign-ca-a",
		PKCS11URI: "pkcs11:object=sign-ca", KeyType: "ecdsa-p256", PublicKey: "k",
		Certificate: caPEM,
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	svc, err := signing.NewService(provider, nil, []signing.SignerConfig{
		{
			Name:        "release",
			KeyLabel:    "sign-leaf",
			Certificate: leafCert,
			Chain:       []*x509.Certificate{leafCert, caCert},
			TenantID:    "a",
		},
		{
			// A signer whose key is gone from the provider: exercises the
			// backend-unavailable (503) path without faking a provider outage.
			Name:        "broken",
			KeyLabel:    "no-such-key",
			Certificate: leafCert,
			Chain:       []*x509.Certificate{leafCert, caCert},
			TenantID:    "a",
		},
	})
	if err != nil {
		t.Fatalf("signing.NewService: %v", err)
	}
	api.SetSigningService(svc)
	return caCert
}

// signingAPI builds the API plus its signing fixture, sharing one software
// provider between the API and the service.
func signingAPI(t *testing.T) (*API, *database.DB, *x509.Certificate) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	caCert := signingFixture(t, api, db, prov)
	return api, db, caCert
}

func TestSignArtifactFlowAndTenantScoping(t *testing.T) {
	api, db, caCert := signingAPI(t)
	artifact := []byte("release-1.0.0.tar.gz bytes")
	artifactB64 := base64.StdEncoding.EncodeToString(artifact)

	// A signer of tenant "a" may sign with tenant "a"'s identity.
	alice := tenantUser("alice", "a", "signer")
	rec := httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"release","artifact":"`+artifactB64+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("SignArtifact: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var signResp SignArtifactResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signResp); err != nil {
		t.Fatalf("decoding sign response: %v", err)
	}
	if signResp.Signer != "release" || signResp.Signature == "" || signResp.Timestamped {
		t.Errorf("unexpected sign response: %+v", signResp)
	}
	sigDER, err := base64.StdEncoding.DecodeString(signResp.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signing.Verify(signing.VerifyRequest{
		Signature: sigDER, Content: artifact, Roots: []*x509.Certificate{caCert},
	}); err != nil {
		t.Fatalf("returned signature does not verify: %v", err)
	}

	// A signer of tenant "b" is denied on tenant "a"'s identity (cross-tenant),
	// and a tenant-"a" auditor lacks artifact:sign.
	for _, u := range []*models.UserInfo{tenantUser("bob", "b", "signer"), tenantUser("carol", "a", "auditor")} {
		rec = httptest.NewRecorder()
		api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", u, "",
			`{"signer":"release","artifact":"`+artifactB64+`"}`))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("SignArtifact as %s: status = %d, want 403 (body=%s)", u.Subject, rec.Code, rec.Body.String())
		}
	}

	// Digest input signs without shipping the artifact.
	digest := sha256.Sum256(artifact)
	rec = httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"release","digest":"`+hex.EncodeToString(digest[:])+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("SignArtifact by digest: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// The audit log holds the successes and the denials.
	events, _, err := db.ListEvents(audit.ActionArtifactSign, "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var success, denied int
	for _, e := range events {
		switch e.Result {
		case audit.ResultSuccess:
			success++
			if e.Tenant != "a" {
				t.Errorf("success event tenant = %q, want a", e.Tenant)
			}
		case audit.ResultDenied:
			denied++
		}
	}
	if success != 2 || denied != 2 {
		t.Errorf("audit artifact.sign events: success=%d denied=%d, want 2/2", success, denied)
	}
}

func TestVerifyArtifactEndpoint(t *testing.T) {
	api, db, _ := signingAPI(t)
	artifact := []byte("verify me")
	artifactB64 := base64.StdEncoding.EncodeToString(artifact)

	alice := tenantUser("alice", "a", "signer")
	rec := httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"release","artifact":"`+artifactB64+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("SignArtifact: %d %s", rec.Code, rec.Body.String())
	}
	var signResp SignArtifactResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signResp); err != nil {
		t.Fatal(err)
	}

	// An auditor of tenant "a" may verify against tenant "a"'s CA.
	carol := tenantUser("carol", "a", "auditor")
	body, _ := json.Marshal(VerifyArtifactRequest{Signature: signResp.Signature, Artifact: artifactB64})
	rec = httptest.NewRecorder()
	api.VerifyArtifact(rec, reqAs(http.MethodPost, "/api/sign/verify", carol, "", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyArtifact: %d %s", rec.Code, rec.Body.String())
	}
	var vresp VerifyArtifactResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if !vresp.Valid || vresp.SignerSubject == "" {
		t.Fatalf("verify response: %+v, want valid", vresp)
	}

	// A tampered artifact yields HTTP 200 with valid=false and a reason.
	tampered := base64.StdEncoding.EncodeToString(append([]byte("x"), artifact...))
	body, _ = json.Marshal(VerifyArtifactRequest{Signature: signResp.Signature, Artifact: tampered})
	rec = httptest.NewRecorder()
	api.VerifyArtifact(rec, reqAs(http.MethodPost, "/api/sign/verify", carol, "", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyArtifact(tampered): %d %s", rec.Code, rec.Body.String())
	}
	vresp = VerifyArtifactResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if vresp.Valid || vresp.Reason == "" {
		t.Fatalf("verify(tampered) response: %+v, want invalid with reason", vresp)
	}

	// A principal whose only roles live in tenant "b" has no trust anchors in
	// scope: the request is rejected rather than silently verified against
	// another tenant's CAs.
	bob := tenantUser("bob", "b", "auditor")
	body, _ = json.Marshal(VerifyArtifactRequest{Signature: signResp.Signature, Artifact: artifactB64})
	rec = httptest.NewRecorder()
	api.VerifyArtifact(rec, reqAs(http.MethodPost, "/api/sign/verify", bob, "", string(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("VerifyArtifact cross-tenant: %d, want 400 (no anchors) — body=%s", rec.Code, rec.Body.String())
	}

	// Audit trail for verification: one success, one denied (the invalid one).
	events, _, err := db.ListEvents(audit.ActionArtifactVerify, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("artifact.verify events = %d, want 2", len(events))
	}
}

// TestSignArtifactBackendUnavailable confirms provider-side failures surface
// as 503 (retryable) without leaking provider internals in the response body.
func TestSignArtifactBackendUnavailable(t *testing.T) {
	api, db, _ := signingAPI(t)
	alice := tenantUser("alice", "a", "signer")
	rec := httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"broken","artifact":"`+base64.StdEncoding.EncodeToString([]byte("x"))+`"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("SignArtifact(broken): status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "no-such-key") {
		t.Error("response leaks the provider key label")
	}
	// The audit event carries the full detail for operators.
	events, _, err := db.ListEvents(audit.ActionArtifactSign, "", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultError || !strings.Contains(events[0].Detail, "no-such-key") {
		t.Fatalf("audit events = %+v, want one error event naming the key", events)
	}
}

func TestListSignersTenantFilter(t *testing.T) {
	api, _, _ := signingAPI(t)

	alice := tenantUser("alice", "a", "signer")
	rec := httptest.NewRecorder()
	api.ListSigners(rec, reqAs(http.MethodGet, "/api/sign/signers", alice, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListSigners: %d %s", rec.Code, rec.Body.String())
	}
	var signers []SignerInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signers); err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 || signers[0].Name != "broken" || signers[1].Name != "release" || signers[1].Tenant != "a" {
		t.Fatalf("signers for tenant-a member = %+v, want broken+release", signers)
	}

	// A tenant-b principal sees no tenant-a signers.
	bob := tenantUser("bob", "b", "auditor")
	rec = httptest.NewRecorder()
	api.ListSigners(rec, reqAs(http.MethodGet, "/api/sign/signers", bob, "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListSigners(bob): %d", rec.Code)
	}
	signers = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &signers); err != nil {
		t.Fatal(err)
	}
	if len(signers) != 0 {
		t.Fatalf("signers visible cross-tenant: %+v", signers)
	}
}
