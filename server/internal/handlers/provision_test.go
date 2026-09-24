//go:build sqlite

package handlers

// Tests for the signer-provisioning endpoints (Task 198): POST /api/tsa/key and
// POST /api/sign/signers.
//
// Neither endpoint accepts private key material, so the secrecy property they
// carry is the mirror image of the import endpoints': the key is generated inside
// the provider and must STAY there — TestProvisionNeverReturnsPrivateKey asserts
// no response or audit event ever carries a private half. The rest asserts what
// the CLI asserts about the credentials it mints: the TSA certificate is a valid
// RFC 3161 credential (id-kp-timeStamping as the sole, critical EKU, RSA key) and
// the code-signing certificate came off the ordinary, lint-gated issuance path.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// provisionRoot builds a tenant with a real software-provider root CA whose
// validity comfortably exceeds the CLI's default TSA validity (1185 days), so the
// default-validity path is reachable and the "exceeds the issuing CA" refusal can
// be provoked deliberately rather than by accident.
func provisionRoot(t *testing.T, api *API, db *database.DB, slug string, validity time.Duration) *models.CA {
	t.Helper()
	tn := &models.Tenant{ID: "pt-" + slug, Slug: slug, Name: slug, Status: models.TenantStatusActive}
	if err := db.CreateTenant(tn); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	root, err := ca.NewManager(db, api.keyProvider).InitRoot(context.Background(), ca.RootSpec{
		TenantID: tn.ID,
		Label:    "pt-root-" + slug,
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Provision Test Root " + slug}),
		Validity: validity,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return root
}

// countPEMCerts reports how many CERTIFICATE blocks a bundle holds.
func countPEMCerts(t *testing.T, bundle string) int {
	t.Helper()
	n := 0
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return n
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
}

// firstPEMCert parses the leading certificate of a bundle.
func firstPEMCert(t *testing.T, bundle string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(bundle))
	if block == nil {
		t.Fatalf("bundle is not PEM: %q", bundle)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// --- POST /api/tsa/key ---

// TestProvisionTSAKeyAuthz: the TSA credential is deployment infrastructure (the
// server reaches it through tsa.key_label), so the gate is PLATFORM ca:manage. A
// tenant admin — who may create CAs in its own tenant — must not be able to
// provision, or silently re-certify, the timestamp authority every signature and
// audit anchor in the deployment depends on.
func TestProvisionTSAKeyAuthz(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "tsa-authz", 10*365*24*time.Hour)
	body := `{"ca":"` + root.ID + `","label":"tsa-authz","validity_days":90}`

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant admin", tenantUser("alice", root.TenantID, "admin"), http.StatusForbidden},
		{"tenant auditor", tenantUser("bob", root.TenantID, "auditor"), http.StatusForbidden},
		{"platform admin", &models.UserInfo{Subject: "p", Roles: []string{"admin"}}, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ProvisionTSAKey, tc.user, "/api/tsa/key", body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	if log := eventDetails(t, db); !strings.Contains(log, actionTSAKeyProvision+"||platform ca:manage capability required") {
		t.Errorf("no tsa.key_provision denial recorded; log:\n%s", log)
	}
}

// TestProvisionTSAKeyRejects covers the input contract, including the two
// substantive refusals the CLI makes: a non-RSA key type (openssl ts -verify
// interop and the CMS signer both require RSA) and a validity that outlives the
// issuing CA.
func TestProvisionTSAKeyRejects(t *testing.T) {
	api, db := opsAPI(t)
	short := provisionRoot(t, api, db, "tsa-short", 180*24*time.Hour)
	bare := &models.CA{
		ID: "tsa-bare", TenantID: short.TenantID, Label: "tsa-bare",
		PKCS11URI: "software:tsa-bare", KeyType: "ecdsa-p256", PublicKey: "k",
	}
	if err := db.CreateCA(bare); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantSubstr string
	}{
		{"not JSON", `{`, http.StatusBadRequest, "invalid JSON"},
		{"no ca", `{}`, http.StatusBadRequest, "ca is required"},
		{"unknown ca", `{"ca":"ghost"}`, http.StatusNotFound, "not found"},
		{"ca without a certificate", `{"ca":"tsa-bare"}`, http.StatusBadRequest, "has no certificate"},
		{"unknown key type", `{"ca":"` + short.ID + `","key_type":"rsa-1234"}`, http.StatusBadRequest, ""},
		{"non-RSA key type", `{"ca":"` + short.ID + `","key_type":"ecdsa-p256"}`,
			http.StatusBadRequest, "must be RSA"},
		{"validity outlives the CA", `{"ca":"` + short.ID + `","label":"tsa-long"}`,
			http.StatusBadRequest, "exceeds issuing CA expiry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ProvisionTSAKey, rootUser(), "/api/tsa/key", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestProvisionTSAKeyOpsAbsent: without the operations dependencies the tsa-role
// backend cannot be resolved, so the endpoint reports 503 rather than quietly
// putting the TSA key wherever the CA's keys live.
func TestProvisionTSAKeyOpsAbsent(t *testing.T) {
	api, db := tenantAPI(t) // no SetOps
	root := provisionRoot(t, api, db, "tsa-noops", 10*365*24*time.Hour)
	rec := postAs(api.ProvisionTSAKey, rootUser(), "/api/tsa/key",
		`{"ca":"`+root.ID+`","validity_days":90}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "operations dependencies") {
		t.Errorf("body = %s, want it to name the missing dependencies", rec.Body.String())
	}
}

// TestProvisionTSAKeyIssuesRFC3161Credential is the substantive assertion: the
// certificate that comes back is one a TSA can actually sign tokens with — RSA
// key, id-kp-timeStamping as the SOLE extended key usage, marked critical (RFC
// 3161 §2.3) — and a second call reuses the key rather than rotating it, which is
// what makes a certificate reissue safe.
func TestProvisionTSAKeyIssuesRFC3161Credential(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "tsa-ok", 10*365*24*time.Hour)

	rec := postAs(api.ProvisionTSAKey, rootUser(), "/api/tsa/key",
		`{"ca":"`+root.Label+`","label":"tsa-prod","key_type":"rsa-2048","common_name":"Acme TSA","organization":"Acme","validity_days":365}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp TSAKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Key.Label != "tsa-prod" || resp.Key.KeyType != keyprovider.KeyTypeRSA2048 {
		t.Errorf("key = %+v, want label tsa-prod of type %s", resp.Key, keyprovider.KeyTypeRSA2048)
	}
	if resp.Key.Reused {
		t.Error("key.reused = true on the first provisioning")
	}
	if resp.Key.Role != "tsa" || resp.Key.Provider != "software" {
		t.Errorf("key role/provider = %q/%q, want tsa/software", resp.Key.Role, resp.Key.Provider)
	}
	if resp.Certificate.CAID != root.ID || resp.Certificate.CALabel != root.Label {
		t.Errorf("issuer = %s/%s, want %s/%s", resp.Certificate.CAID, resp.Certificate.CALabel, root.ID, root.Label)
	}
	if !strings.Contains(resp.ConfigHint, "tsa.key_label") {
		t.Errorf("config_hint = %q, want it to name tsa.key_label", resp.ConfigHint)
	}

	cert := firstPEMCert(t, resp.Certificate.CertificatePEM)
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("TSA certificate public key is %T, want RSA", cert.PublicKey)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("ext key usage = %v, want exactly [timeStamping]", cert.ExtKeyUsage)
	}
	if len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("unknown ext key usages present: %v", cert.UnknownExtKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("digitalSignature key usage missing")
	}
	// RFC 3161 §2.3 wants the EKU critical, which is why it is hand-built rather
	// than taken from a profile — and it must carry exactly the id-kp-timeStamping
	// OID internal/tsa checks incoming token requests against, not a lookalike.
	found := false
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtKeyUsage) {
			continue
		}
		found = true
		if !ext.Critical {
			t.Error("the extended-key-usage extension is not marked critical")
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			t.Fatalf("decoding the EKU extension: %v", err)
		}
		if len(oids) != 1 || !oids[0].Equal(tsa.OIDExtKeyUsageTimeStamping) {
			t.Errorf("EKU OIDs = %v, want exactly [%s]", oids, tsa.OIDExtKeyUsageTimeStamping)
		}
	}
	if !found {
		t.Error("the certificate carries no extended-key-usage extension")
	}
	// The same check the server applies to tsa.certificate_file at startup.
	if err := verifyTSACert(cert); err != nil {
		t.Errorf("the provisioned certificate would be refused at startup: %v", err)
	}
	if resp.Certificate.Subject == "" || !strings.Contains(resp.Certificate.Subject, "Acme TSA") {
		t.Errorf("subject = %q, want it to carry the requested CN", resp.Certificate.Subject)
	}

	// Reissue: same key, new certificate. Chain requested this time, so the
	// bundle carries the root as well.
	rec2 := postAs(api.ProvisionTSAKey, rootUser(), "/api/tsa/key",
		`{"ca":"`+root.Label+`","label":"tsa-prod","key_type":"rsa-2048","validity_days":365,"chain":true}`)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("reissue status = %d, want 201: %s", rec2.Code, rec2.Body.String())
	}
	var resp2 TSAKeyResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode reissue response: %v", err)
	}
	if !resp2.Key.Reused {
		t.Error("key.reused = false on reissue; a certificate reissue must not rotate the TSA key")
	}
	if resp2.Certificate.Serial == resp.Certificate.Serial {
		t.Error("reissue produced the same serial")
	}
	if n := countPEMCerts(t, resp2.Certificate.CertificatePEM); n < 2 {
		t.Errorf("chain bundle holds %d certificates, want the credential plus its issuer(s)", n)
	}
	reissued := firstPEMCert(t, resp2.Certificate.CertificatePEM)
	if !reissued.PublicKey.(*rsa.PublicKey).Equal(cert.PublicKey) {
		t.Error("the reissued certificate certifies a different key")
	}

	if log := eventDetails(t, db); !strings.Contains(log, "key_reused=true") {
		t.Errorf("tsa.key_provision detail does not record the reuse; log:\n%s", log)
	}
}

// --- POST /api/sign/signers ---

// TestProvisionSignerAuthz: platform ca:manage, for the same reason as the TSA
// key — the credential becomes an entry under signing.signers that every caller
// of POST /api/sign can then sign artifacts with.
func TestProvisionSignerAuthz(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "sign-authz", 10*365*24*time.Hour)
	body := `{"ca":"` + root.ID + `","label":"cs-authz"}`

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant admin", tenantUser("alice", root.TenantID, "admin"), http.StatusForbidden},
		{"artifact signer", tenantUser("sam", root.TenantID, "signer"), http.StatusForbidden},
		{"platform admin", &models.UserInfo{Subject: "p", Roles: []string{"admin"}}, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ProvisionSigner, tc.user, "/api/sign/signers", body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	if log := eventDetails(t, db); !strings.Contains(log, actionSignerProvision+"||platform ca:manage capability required") {
		t.Errorf("no signing.key_provision denial recorded; log:\n%s", log)
	}
}

// TestProvisionSignerRejects covers the input contract, including the key
// families the CMS signer supports and the requirement that the chosen profile
// actually produce a code-signing certificate.
func TestProvisionSignerRejects(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "sign-bad", 10*365*24*time.Hour)

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantSubstr string
	}{
		{"not JSON", `{`, http.StatusBadRequest, "invalid JSON"},
		{"no ca", `{}`, http.StatusBadRequest, "ca is required"},
		{"unknown ca", `{"ca":"ghost"}`, http.StatusNotFound, "not found"},
		{"unknown key type", `{"ca":"` + root.ID + `","key_type":"rsa-1234"}`, http.StatusBadRequest, ""},
		{"unsupported key family", `{"ca":"` + root.ID + `","key_type":"ed25519"}`,
			http.StatusBadRequest, "must be ECDSA or RSA"},
		{"unknown profile", `{"ca":"` + root.ID + `","label":"cs-x","profile":"no-such-profile"}`,
			http.StatusBadRequest, ""},
		// A profile that exists but carries the wrong EKU must be refused loudly
		// rather than produce a certificate nothing will accept as a signer.
		{"profile without codeSigning", `{"ca":"` + root.ID + `","label":"cs-y","profile":"server"}`,
			http.StatusBadRequest, "not usable for code signing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ProvisionSigner, rootUser(), "/api/sign/signers", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestProvisionSignerOpsAbsent: without the operations dependencies the
// signing-role backend cannot be resolved.
func TestProvisionSignerOpsAbsent(t *testing.T) {
	api, db := tenantAPI(t) // no SetOps
	root := provisionRoot(t, api, db, "sign-noops", 10*365*24*time.Hour)
	rec := postAs(api.ProvisionSigner, rootUser(), "/api/sign/signers", `{"ca":"`+root.ID+`"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}

// TestProvisionSignerIssuesCodeSigningCredential: the certificate is a usable
// code-signing credential AND — unlike the TSA certificate, which is hand-crafted
// — it came off the ordinary issuance path, so it is recorded for renewal and
// revocation like any other leaf.
func TestProvisionSignerIssuesCodeSigningCredential(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "sign-ok", 10*365*24*time.Hour)

	rec := postAs(api.ProvisionSigner, rootUser(), "/api/sign/signers",
		`{"ca":"`+root.Label+`","label":"acme-codesign","key_type":"ecdsa-p256","organization":"Acme","validity_days":365}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp SignerProvisionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Key.Label != "acme-codesign" || resp.Key.Reused {
		t.Errorf("key = %+v, want a freshly generated acme-codesign", resp.Key)
	}
	if resp.Key.Role != "signing" {
		t.Errorf("key role = %q, want signing", resp.Key.Role)
	}
	if resp.Profile != "code-signing" {
		t.Errorf("profile = %q, want code-signing", resp.Profile)
	}
	if !strings.Contains(resp.ConfigHint, "signing.signers") {
		t.Errorf("config_hint = %q, want it to name signing.signers", resp.ConfigHint)
	}
	// The CN defaults to the key label, as the CLI's -cn default does.
	if !strings.Contains(resp.Certificate.Subject, "acme-codesign") {
		t.Errorf("subject = %q, want the key label as CN", resp.Certificate.Subject)
	}

	cert := firstPEMCert(t, resp.Certificate.CertificatePEM)
	if err := signing.CheckCodeSigningCert(cert); err != nil {
		t.Errorf("the provisioned certificate is not a usable signer: %v", err)
	}

	// It went through the ordinary path, so it is in the issuance ledger and can
	// be renewed and revoked like any other leaf.
	stored, err := db.GetIssuedCertificate(root.ID, resp.Certificate.Serial)
	if err != nil || stored == nil {
		t.Fatalf("the signing certificate was not recorded: cert=%v err=%v", stored, err)
	}

	// Reissue reuses the key.
	rec2 := postAs(api.ProvisionSigner, rootUser(), "/api/sign/signers",
		`{"ca":"`+root.Label+`","label":"acme-codesign","key_type":"ecdsa-p256","validity_days":365,"chain":true}`)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("reissue status = %d, want 201: %s", rec2.Code, rec2.Body.String())
	}
	var resp2 SignerProvisionResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode reissue response: %v", err)
	}
	if !resp2.Key.Reused {
		t.Error("key.reused = false on reissue; a certificate reissue must not rotate the signing key")
	}
	if n := countPEMCerts(t, resp2.Certificate.CertificatePEM); n < 2 {
		t.Errorf("chain bundle holds %d certificates, want the credential plus its issuer(s)", n)
	}
}

// TestProvisionNeverReturnsPrivateKey: the whole point of provisioning a key in
// the provider is that the private half never exists outside it. Neither response
// nor audit event may carry one, and the provider must actually hold the key.
func TestProvisionNeverReturnsPrivateKey(t *testing.T) {
	api, db := opsAPI(t)
	root := provisionRoot(t, api, db, "secrecy", 10*365*24*time.Hour)

	for _, c := range []struct {
		name, path, body string
		h                http.HandlerFunc
		label            string
	}{
		{"tsa", "/api/tsa/key", `{"ca":"` + root.ID + `","label":"sec-tsa","validity_days":90}`,
			api.ProvisionTSAKey, "sec-tsa"},
		{"signer", "/api/sign/signers", `{"ca":"` + root.ID + `","label":"sec-cs","validity_days":90}`,
			api.ProvisionSigner, "sec-cs"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := postAs(c.h, rootUser(), c.path, c.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, marker := range []string{"PRIVATE KEY", "private_key", "RSA PRIVATE", "EC PRIVATE"} {
				if strings.Contains(body, marker) {
					t.Fatalf("response carries %q: %s", marker, body)
				}
			}
			// The key really is in the provider, and only its public half came back.
			if _, err := api.keyProvider.FindKey(context.Background(),
				keyprovider.KeyRef{Label: c.label}); err != nil {
				t.Errorf("provider does not hold %q: %v", c.label, err)
			}
		})
	}

	log := eventDetails(t, db)
	if !strings.Contains(log, actionTSAKeyProvision) || !strings.Contains(log, actionSignerProvision) {
		t.Fatalf("expected both provisioning events; log:\n%s", log)
	}
	if strings.Contains(log, "PRIVATE KEY") {
		t.Errorf("the audit log carries PEM key armour; log:\n%s", log)
	}
}
