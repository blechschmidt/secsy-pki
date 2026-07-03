//go:build sqlite

package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	sslpkcs12 "software.sslmate.com/src/go-pkcs12"
)

// pkcs12API builds an API backed by a software provider and returns the id of a
// freshly-created, issuable root CA.
func pkcs12API(t *testing.T) (*API, string) {
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

	root, err := ca.NewManager(db, prov).InitRoot(context.Background(), ca.RootSpec{
		Label:    "p12-handler-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "P12 Handler Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return api, root.ID
}

func TestExportCertificatePKCS12Handler(t *testing.T) {
	api, caID := pkcs12API(t)
	const password = "correct-horse-battery-staple"

	body := `{"profile":"server","common_name":"leaf.example.com",` +
		`"dns_names":["leaf.example.com"],"key_type":"ecdsa","encoder":"modern",` +
		`"password":"` + password + `"}`

	rec := httptest.NewRecorder()
	api.ExportCertificatePKCS12(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/pkcs12", rootUser(), caID, body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	var resp models.ExportPKCS12Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.KeyType != "ecdsa-p256" || resp.Encoder != "modern" || resp.Serial == "" {
		t.Errorf("unexpected response metadata: %+v", resp)
	}
	if resp.Escrow != nil {
		t.Errorf("escrow reported but not requested: %+v", resp.Escrow)
	}

	// The returned bundle must decode with the password and yield a private key
	// and the leaf chained to the root.
	pfx, err := base64.StdEncoding.DecodeString(resp.PKCS12)
	if err != nil {
		t.Fatalf("pkcs12 field is not base64: %v", err)
	}
	priv, leaf, caCerts, err := sslpkcs12.DecodeChain(pfx, password)
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if _, ok := priv.(*ecdsa.PrivateKey); !ok {
		t.Errorf("recovered key type = %T, want *ecdsa.PrivateKey", priv)
	}
	if leaf.Subject.CommonName != "leaf.example.com" {
		t.Errorf("leaf CN = %q, want leaf.example.com", leaf.Subject.CommonName)
	}
	if len(caCerts) != 1 {
		t.Errorf("bundled CA certs = %d, want 1 (the root)", len(caCerts))
	}
}

// TestExportCertificatePKCS12RBAC confirms the endpoint enforces the issue
// capability: a tenant auditor (no issue capability, no per-CA grant) is denied.
func TestExportCertificatePKCS12RBAC(t *testing.T) {
	api, caID := pkcs12API(t)
	body := `{"profile":"server","common_name":"leaf.example.com",` +
		`"dns_names":["leaf.example.com"],"password":"correct-horse-battery-staple"}`

	// The CA created by InitRoot belongs to the default tenant.
	auditor := tenantUser("carol", models.DefaultTenantID, "auditor")
	rec := httptest.NewRecorder()
	api.ExportCertificatePKCS12(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/pkcs12", auditor, caID, body))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("auditor status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestExportCertificatePKCS12ShortPassword rejects a too-short export password
// with a clean 400 before any issuance happens.
func TestExportCertificatePKCS12ShortPassword(t *testing.T) {
	api, caID := pkcs12API(t)
	body := `{"profile":"server","common_name":"leaf.example.com","password":"x"}`
	rec := httptest.NewRecorder()
	api.ExportCertificatePKCS12(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/pkcs12", rootUser(), caID, body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short-password status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}
