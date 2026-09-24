//go:build sqlite

package handlers

// Tests for the key/CA adoption endpoints (Task 198): POST /api/keys/import and
// POST /api/ca/import.
//
// The property these carry that ordinary handler tests do not: the request body
// contains a private key, so every test that reaches a success or failure path
// also asserts the material did not leak into the response or into the audit
// event log. TestImportNeverLeaksKeyMaterial is the systematic version of that.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// --- harness ---

// opsAPI builds the tenant test API with the operations dependency bundle
// installed, so the import/provision endpoints resolve a role provider instead
// of reporting 503. The default config leaves every key-provider role equal, so
// providerForRole returns the already-open CA provider — the same shape a
// single-backend deployment has. ProviderFor is still wired (and counted) so the
// distinct-backend branch can be exercised where a test wants it.
func opsAPI(t *testing.T) (*API, *database.DB) {
	t.Helper()
	api, db := tenantAPI(t)
	api.SetOps(&OpsDeps{
		Config: &config.Config{},
		ProviderFor: func(string) (keyprovider.Provider, error) {
			p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
			if err != nil {
				return nil, err
			}
			return keyprovider.Instrument(p), nil
		},
		ConfigPath: "/etc/secsy/config.yaml",
	})
	return api, db
}

// postAs drives a handler with a JSON body as the given principal.
func postAs(h http.HandlerFunc, user *models.UserInfo, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, reqAs(http.MethodPost, target, user, "", body))
	return rec
}

// rsaKeyPEM returns an unencrypted PKCS#8 PEM for a fresh RSA key of the given
// size, plus the key itself.
func rsaKeyPEM(t *testing.T, bits int) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

// ecKeyPEM returns an unencrypted PKCS#8 PEM for a fresh P-256 key.
func ecKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

// selfSignedCA mints a self-signed CA certificate over key, returning its PEM.
// It is the "legacy CA an organization already runs" that ca import adopts.
func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, cn string) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// eventDetails returns every audit event detail + target name in the log, the
// surface a leaked secret would show up on.
func eventDetails(t *testing.T, db *database.DB) string {
	t.Helper()
	events, _, err := db.ListEvents("", "", "", 500, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var b strings.Builder
	for _, e := range events {
		b.WriteString(e.Action)
		b.WriteString("|")
		b.WriteString(e.TargetName)
		b.WriteString("|")
		b.WriteString(e.Detail)
		b.WriteString("\n")
	}
	return b.String()
}

// --- POST /api/keys/import ---

// TestImportKeyAuthz: the endpoint is gated on PLATFORM hsm:manage, so a tenant
// admin — who may create CAs in its own tenant — cannot write arbitrary key
// material into a backend the whole deployment shares.
func TestImportKeyAuthz(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "a")
	keyPEM, _ := ecKeyPEM(t)
	body := `{"label":"authz-import","key_pem":` + mustJSON(t, keyPEM) + `}`

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant admin", tenantUser("alice", "a", "admin"), http.StatusForbidden},
		{"tenant auditor", tenantUser("bob", "a", "auditor"), http.StatusForbidden},
		{"root", rootUser(), http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ImportKey, tc.user, "/api/keys/import", body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// A refusal is recorded as a denial, and it names no key material.
	log := eventDetails(t, db)
	if !strings.Contains(log, audit.ActionKeyImport+"||hsm:manage capability required") {
		t.Errorf("no key.import denial recorded; log:\n%s", log)
	}
}

// TestImportKeyRejects covers the validation the CLI performs, including the
// host-side gates commit c87439b added: RSA sizes are matched EXACTLY (a
// 2560-bit key is not rounded up to "rsa-3072") and imported material passes the
// key-quality gate (exponent policy, ROCA, modulus sanity). Those live in
// internal/keyprovider and are reached through keyprovider.ImportKey, not
// re-implemented here.
func TestImportKeyRejects(t *testing.T) {
	api, _ := opsAPI(t)
	okKey, _ := ecKeyPEM(t)
	odd, _ := rsaKeyPEM(t, 2560)
	small, _ := rsaKeyPEM(t, 1024)

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantSubstr string
	}{
		{"not JSON", `{`, http.StatusBadRequest, "invalid JSON"},
		{"no label", `{"key_pem":` + mustJSON(t, okKey) + `}`, http.StatusBadRequest, "label is required"},
		{"no key material", `{"label":"k"}`, http.StatusBadRequest, "key_pem or key_base64 is required"},
		{"both encodings", `{"label":"k","key_pem":` + mustJSON(t, okKey) + `,"key_base64":"AAAA"}`,
			http.StatusBadRequest, "exactly one of key_pem or key_base64"},
		{"unknown usage", `{"label":"k","usage":"wrap","key_pem":` + mustJSON(t, okKey) + `}`,
			http.StatusBadRequest, "unknown usage"},
		{"unknown role", `{"label":"k","role":"ssh","key_pem":` + mustJSON(t, okKey) + `}`,
			http.StatusBadRequest, "unknown role"},
		{"bad base64", `{"label":"k","key_base64":"not base64 !!"}`,
			http.StatusBadRequest, "not valid base64"},
		{"garbage PEM", `{"label":"k","key_pem":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}`,
			http.StatusBadRequest, ""},
		// c87439b: an exact-size match, not a round-up to the next name.
		{"odd RSA size", `{"label":"k-odd","key_pem":` + mustJSON(t, odd) + `}`,
			http.StatusBadRequest, "2560"},
		{"undersized RSA", `{"label":"k-small","key_pem":` + mustJSON(t, small) + `}`,
			http.StatusBadRequest, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ImportKey, rootUser(), "/api/keys/import", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestImportKeyOpsAbsent: a server started without the operations dependencies
// cannot resolve a role's backend, and says so rather than silently importing
// into the CA's.
func TestImportKeyOpsAbsent(t *testing.T) {
	api, _ := tenantAPI(t) // no SetOps
	keyPEM, _ := ecKeyPEM(t)
	rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
		`{"label":"k","key_pem":`+mustJSON(t, keyPEM)+`}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "operations dependencies") {
		t.Errorf("body = %s, want it to name the missing dependencies", rec.Body.String())
	}
}

// TestImportKeyHappyPath: an existing key lands in the provider, is proved to
// sign, is reported with its provenance notice, and is findable afterwards under
// the label the caller chose.
func TestImportKeyHappyPath(t *testing.T) {
	api, db := opsAPI(t)
	keyPEM, key := ecKeyPEM(t)

	rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
		`{"label":"legacy-root","usage":"sign","role":"ca","key_pem":`+mustJSON(t, keyPEM)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp ImportKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Label != "legacy-root" || resp.KeyType != keyprovider.KeyTypeECDSAP256 {
		t.Errorf("label/key_type = %q/%q, want legacy-root/%s", resp.Label, resp.KeyType, keyprovider.KeyTypeECDSAP256)
	}
	if !resp.Verified {
		t.Error("verified = false; a signing key must be proved usable before success is reported")
	}
	if resp.SourceFormat != "pkcs8" {
		t.Errorf("source_format = %q, want pkcs8", resp.SourceFormat)
	}
	if resp.Provider != "software" || resp.Role != "ca" || resp.Usage != keyprovider.KeyUsageSign {
		t.Errorf("provider/role/usage = %q/%q/%q", resp.Provider, resp.Role, resp.Usage)
	}
	if !strings.Contains(resp.Notice, "imported rather than generated") {
		t.Errorf("notice does not carry the provenance caveat: %q", resp.Notice)
	}
	if !strings.Contains(resp.Notice, "software keystore") {
		t.Errorf("notice does not name the software backend's weaker guarantee: %q", resp.Notice)
	}

	// The key really is in the provider, and it is the key that was sent.
	info, err := api.keyProvider.FindKey(context.Background(), keyprovider.KeyRef{Label: "legacy-root"})
	if err != nil {
		t.Fatalf("FindKey after import: %v", err)
	}
	got, ok := info.PublicKey.(*ecdsa.PublicKey)
	if !ok || !got.Equal(key.Public()) {
		t.Fatalf("provider holds a different key than was imported (%T)", info.PublicKey)
	}

	// The audit trail records the shape of the import and nothing else.
	log := eventDetails(t, db)
	if !strings.Contains(log, "provider=software role=ca key_type="+keyprovider.KeyTypeECDSAP256) {
		t.Errorf("key.import detail missing the import shape; log:\n%s", log)
	}
	if !strings.Contains(log, "verified=true") {
		t.Errorf("key.import detail does not record the post-import verification; log:\n%s", log)
	}
}

// TestImportKeyRoleProvider: naming a role whose configured backend differs from
// the CA's opens that role's provider, and the key lands THERE rather than in the
// CA's keystore — the mistake the CLI's role check exists to prevent.
func TestImportKeyRoleProvider(t *testing.T) {
	api, _ := tenantAPI(t)
	roleStore, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	calls := 0
	cfg := &config.Config{}
	cfg.KeyProvider.Type = "software"
	cfg.KeyProvider.Roles.TSA = "software-tsa" // a different backend for the tsa role
	api.SetOps(&OpsDeps{
		Config: cfg,
		ProviderFor: func(role string) (keyprovider.Provider, error) {
			calls++
			if role != "tsa" {
				t.Errorf("ProviderFor(%q), want tsa", role)
			}
			return keyprovider.Instrument(roleStore), nil
		},
	})

	keyPEM, _ := ecKeyPEM(t)
	rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
		`{"label":"tsa","role":"tsa","key_pem":`+mustJSON(t, keyPEM)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if calls != 1 {
		t.Errorf("ProviderFor called %d times, want 1", calls)
	}
	if _, err := roleStore.FindKey(context.Background(), keyprovider.KeyRef{Label: "tsa"}); err != nil {
		t.Errorf("the key did not land on the tsa backend: %v", err)
	}
	if _, err := api.keyProvider.FindKey(context.Background(), keyprovider.KeyRef{Label: "tsa"}); err == nil {
		t.Error("the key also landed on the CA backend; a role-scoped import must not write there")
	}
}

// --- POST /api/ca/import ---

// TestImportCAAuthz: ca:manage WITHIN the target tenant, exactly as init-root —
// so a tenant-b admin replaying a tenant-a body is refused.
func TestImportCAAuthz(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Legacy Root")
	body := `{"label":"adopted","tenant":"a","certificate":` + mustJSON(t, certPEM) +
		`,"key_pem":` + mustJSON(t, keyPEM) + `}`

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"other tenant's admin", tenantUser("carol", "b", "admin"), http.StatusForbidden},
		{"same tenant's auditor", tenantUser("bob", "a", "auditor"), http.StatusForbidden},
		{"same tenant's admin", tenantUser("alice", "a", "admin"), http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ImportCA, tc.user, "/api/ca/import", body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestImportCARejects covers the input contract: the label, the exactly-one-of
// key source rule, an unknown tenant and an unknown parent.
func TestImportCARejects(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "a")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Legacy Root")
	cert := mustJSON(t, certPEM)
	pemArg := mustJSON(t, keyPEM)

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantSubstr string
	}{
		{"not JSON", `{`, http.StatusBadRequest, "invalid JSON"},
		{"unknown tenant", `{"label":"x","tenant":"nope","certificate":` + cert + `,"key_pem":` + pemArg + `}`,
			http.StatusBadRequest, "unknown tenant"},
		{"no label", `{"tenant":"a","certificate":` + cert + `,"key_pem":` + pemArg + `}`,
			http.StatusBadRequest, "label is required"},
		{"no key source", `{"label":"x","tenant":"a","certificate":` + cert + `}`,
			http.StatusBadRequest, "exactly one of key material"},
		{"both key sources", `{"label":"x","tenant":"a","certificate":` + cert +
			`,"existing_key_label":"k","key_pem":` + pemArg + `}`,
			http.StatusBadRequest, "exactly one of key material"},
		{"unknown parent", `{"label":"x","tenant":"a","parent":"ghost","certificate":` + cert +
			`,"key_pem":` + pemArg + `}`, http.StatusBadRequest, "parent CA"},
		{"no certificate at all", `{"label":"x","tenant":"a","key_pem":` + pemArg + `}`,
			http.StatusBadRequest, "certificate is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.ImportCA, rootUser(), "/api/ca/import", tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestImportCAHappyPath: the adopted CA row is the ordinary one — right tenant,
// right label, an active X.509 CA with its certificate and a provider-held key —
// so nothing downstream can tell it from a CLI-adopted or locally created CA.
func TestImportCAHappyPath(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "acme")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Legacy Acme Root")

	rec := postAs(api.ImportCA, rootUser(), "/api/ca/import",
		`{"label":"acme-legacy","tenant":"acme","certificate":`+mustJSON(t, certPEM)+
			`,"key_pem":`+mustJSON(t, keyPEM)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp ImportCAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CA == nil {
		t.Fatal("response carries no CA record")
	}
	if !resp.SelfSigned || !resp.KeyImported {
		t.Errorf("self_signed/key_imported = %t/%t, want true/true", resp.SelfSigned, resp.KeyImported)
	}
	if resp.KeyFingerprint == "" {
		t.Error("key_fingerprint is empty; the inventory and compromise search key off it")
	}
	if resp.SourceFormat != "pkcs8" {
		t.Errorf("source_format = %q, want pkcs8", resp.SourceFormat)
	}
	if !strings.Contains(resp.Notice, "imported rather than generated") {
		t.Errorf("notice missing the provenance caveat: %q", resp.Notice)
	}

	stored, err := db.GetCAByLabel("acme-legacy")
	if err != nil || stored == nil {
		t.Fatalf("GetCAByLabel: ca=%v err=%v", stored, err)
	}
	if stored.TenantID != "acme" {
		t.Errorf("tenant = %q, want acme (the tenant field must scope the adoption)", stored.TenantID)
	}
	if stored.Certificate == "" || stored.PKCS11URI == "" {
		t.Errorf("adopted CA is missing its certificate (%d bytes) or key URI (%q)",
			len(stored.Certificate), stored.PKCS11URI)
	}
	if stored.ID != resp.CA.ID {
		t.Errorf("stored id %q != reported id %q", stored.ID, resp.CA.ID)
	}

	log := eventDetails(t, db)
	if !strings.Contains(log, audit.ActionCAImport) || !strings.Contains(log, "key_imported=true") {
		t.Errorf("ca.import not recorded with its shape; log:\n%s", log)
	}
}

// TestImportCAAdoptsExistingProviderKey: the other half of the CLI's
// exactly-one-of rule — a key already in the provider (put there by an earlier
// import-key, a vendor migration tool, or a wrapped restore) is adopted by label
// with nothing written to the backend.
func TestImportCAAdoptsExistingProviderKey(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "acme")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Staged Root")

	// Stage the key through the sibling endpoint, then adopt it by label.
	if rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
		`{"label":"staged","key_pem":`+mustJSON(t, keyPEM)+`}`); rec.Code != http.StatusCreated {
		t.Fatalf("staging import-key = %d: %s", rec.Code, rec.Body.String())
	}
	rec := postAs(api.ImportCA, rootUser(), "/api/ca/import",
		`{"label":"staged-ca","tenant":"acme","existing_key_label":"staged","certificate":`+mustJSON(t, certPEM)+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp ImportCAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.KeyImported {
		t.Error("key_imported = true; adopting an already-present key writes nothing to the backend")
	}
	if resp.Notice != "" {
		t.Errorf("notice = %q, want empty: no material was imported to warn about", resp.Notice)
	}
	if resp.SourceFormat != "" {
		t.Errorf("source_format = %q, want empty", resp.SourceFormat)
	}
}

// TestImportCAFourEyesGate: adopting a CA creates one, so it passes through the
// same maker-checker gate as init-root and issue-intermediate — 202, and no CA
// row until the second signature arrives.
func TestImportCAFourEyesGate(t *testing.T) {
	api, db := opsAPI(t)
	api.SetApprovals(approval.NewEngine(db, db, approval.Policy{
		Enabled: true, DefaultThreshold: 2, TTL: time.Hour,
	}))
	mkTenant(t, db, "acme")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Guarded Root")

	rec := postAs(api.ImportCA, rootUser(), "/api/ca/import",
		`{"label":"guarded","tenant":"acme","certificate":`+mustJSON(t, certPEM)+
			`,"key_pem":`+mustJSON(t, keyPEM)+`}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (held for approval): %s", rec.Code, rec.Body.String())
	}
	if stored, err := db.GetCAByLabel("guarded"); err != nil || stored != nil {
		t.Fatalf("a CA was created while the approval was pending: ca=%v err=%v", stored, err)
	}

	// The parked request is keyed exactly as the CLI keys it, so the console and
	// `secsy-ca ca import` address one queue — and its params carry no key bytes.
	list, err := api.approvals.List(approval.Query{Limit: 10})
	if err != nil || len(list) != 1 {
		t.Fatalf("approval list: n=%d err=%v", len(list), err)
	}
	pa := list[0]
	if pa.ResourceKey != "ca-label:guarded" {
		t.Errorf("resource key = %q, want ca-label:guarded", pa.ResourceKey)
	}
	if pa.Summary != "Adopt existing CA guarded" {
		t.Errorf("summary = %q, want the CLI's wording", pa.Summary)
	}
	// Everything an approver reads is free of key material. (The guard's params
	// are hashed into Fingerprint rather than stored, so the only persisted
	// free text is the summary, the details and the optional payload.)
	for name, field := range map[string]string{
		"summary": pa.Summary, "details": pa.Details, "payload": pa.Payload,
		"resource_key": pa.ResourceKey, "resource_name": pa.ResourceName,
	} {
		if strings.Contains(field, "BEGIN") || strings.Contains(field, "PRIVATE") {
			t.Errorf("approval %s carries key material: %q", name, field)
		}
	}
}

// TestImportNeverLeaksKeyMaterial is the systematic secrecy assertion for both
// endpoints: a private key and a passphrase go in, and neither the response body
// nor any audit event — on success OR on failure — contains any part of them.
func TestImportNeverLeaksKeyMaterial(t *testing.T) {
	api, db := opsAPI(t)
	mkTenant(t, db, "acme")
	keyPEM, key := ecKeyPEM(t)
	certPEM := selfSignedCA(t, key, "Secrecy Root")
	const passphrase = "correct-horse-battery-staple"

	// The body of the key, without the PEM armour: the bytes that must not appear.
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatal("test key is not PEM")
	}
	secrets := []string{
		strings.TrimSpace(strings.Split(keyPEM, "\n")[1]), // first base64 line of the key
		passphrase,
	}

	calls := []struct {
		name string
		h    http.HandlerFunc
		path string
		body string
	}{
		{"import-key success", api.ImportKey, "/api/keys/import",
			`{"label":"secrecy","passphrase":"` + passphrase + `","key_pem":` + mustJSON(t, keyPEM) + `}`},
		{"import-key failure", api.ImportKey, "/api/keys/import",
			`{"label":"secrecy","passphrase":"` + passphrase + `","key_pem":` + mustJSON(t, keyPEM) + `}`}, // duplicate label
		{"ca-import success", api.ImportCA, "/api/ca/import",
			`{"label":"secrecy-ca","tenant":"acme","passphrase":"` + passphrase +
				`","certificate":` + mustJSON(t, certPEM) + `,"key_pem":` + mustJSON(t, keyPEM) + `}`},
		{"ca-import failure", api.ImportCA, "/api/ca/import",
			`{"label":"secrecy-ca","tenant":"acme","passphrase":"` + passphrase +
				`","certificate":` + mustJSON(t, certPEM) + `,"key_pem":` + mustJSON(t, keyPEM) + `}`}, // duplicate label
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			rec := postAs(c.h, rootUser(), c.path, c.body)
			for _, s := range secrets {
				if strings.Contains(rec.Body.String(), s) {
					t.Fatalf("response echoes secret material (status %d): %s", rec.Code, rec.Body.String())
				}
			}
		})
	}

	// Both surfaces produced events (successes and failures alike), and not one
	// of them carries a byte of the key or the passphrase.
	log := eventDetails(t, db)
	if !strings.Contains(log, audit.ActionKeyImport) || !strings.Contains(log, audit.ActionCAImport) {
		t.Fatalf("expected both key.import and ca.import events; log:\n%s", log)
	}
	for _, s := range secrets {
		if strings.Contains(log, s) {
			t.Errorf("the audit log carries secret material; log:\n%s", log)
		}
	}
	if strings.Contains(log, "PRIVATE KEY") {
		t.Errorf("the audit log carries PEM key armour; log:\n%s", log)
	}
}

// mustJSON renders s as a JSON string literal, so multi-line PEM can be embedded
// in the table-driven request bodies above.
func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(b)
}

// TestImportKeyBackendFailureIs503 is the classification invariant for
// POST /api/keys/import: a host-side POLICY rejection is 400, a BACKEND failure is
// 503.
//
// Every keyprovider.ImportKey failure used to be 400, so a dead HSM told the
// operator their request was bad — sending them to audit the key file while the
// token was the problem. The split is by sentinel
// (keyprovider.ErrImportRejected / ErrImportUnsupported), never by matching message
// text, because those messages come from three packages and change.
func TestImportKeyBackendFailureIs503(t *testing.T) {
	keyPEM, _ := ecKeyPEM(t)

	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantSubstr string
	}{
		{"token unreachable", errors.New("keyprovider: pkcs11 token unreachable"),
			http.StatusServiceUnavailable, "could not store the key"},
		{"object creation refused", errors.New("keyprovider: importing key onto the HSM: CKR_DEVICE_ERROR"),
			http.StatusServiceUnavailable, "could not store the key"},
		{"key-quality rejection", fmt.Errorf("%w: it fails the key-quality gate and must not be imported: roca",
			keyprovider.ErrImportRejected), http.StatusBadRequest, "key-quality gate"},
		{"label already in use", fmt.Errorf("%w: a key labeled %q already exists on the token",
			keyprovider.ErrImportRejected, "dup"), http.StatusBadRequest, "already exists"},
		{"backend cannot import", fmt.Errorf("%w (backend \"kms\")", keyprovider.ErrImportUnsupported),
			http.StatusBadRequest, "cannot import"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api, db := opsAPI(t)
			api.keyProvider = importFailingProvider{Provider: api.keyProvider, err: tc.err}

			rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
				`{"label":"classify","key_pem":`+mustJSON(t, keyPEM)+`}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %s, want it to mention %q", rec.Body.String(), tc.wantSubstr)
			}
			// Either way the failure is audited with its reason and no key material.
			log := eventDetails(t, db)
			if !strings.Contains(log, audit.ActionKeyImport) {
				t.Errorf("the failed import produced no key.import event; log:\n%s", log)
			}
			if strings.Contains(log, "PRIVATE KEY") {
				t.Errorf("the audit detail carries PEM key armour; log:\n%s", log)
			}
		})
	}
}

// TestImportKeyRejectsDuplicateLabel proves the host-side duplicate-label rule is
// classified as the caller's mistake on the SOFTWARE backend too, not as a backend
// failure: writeKeyFile also refuses, but it is shared with GenerateKey and cannot
// tag the failure, so ImportKey checks first (as the PKCS#11 backend does).
func TestImportKeyRejectsDuplicateLabel(t *testing.T) {
	api, _ := opsAPI(t)
	keyPEM, _ := ecKeyPEM(t)
	body := `{"label":"taken","key_pem":` + mustJSON(t, keyPEM) + `}`

	if rec := postAs(api.ImportKey, rootUser(), "/api/keys/import", body); rec.Code != http.StatusCreated {
		t.Fatalf("first import: status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	other, _ := ecKeyPEM(t)
	rec := postAs(api.ImportKey, rootUser(), "/api/keys/import",
		`{"label":"taken","key_pem":`+mustJSON(t, other)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate label: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Errorf("body = %s, want it to say the label is taken", rec.Body.String())
	}
}
