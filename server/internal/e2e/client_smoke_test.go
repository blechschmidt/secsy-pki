//go:build sqlite

// This file smoke-tests the generated Go client SDK (pkg/client) against a live,
// HSM-backed API server. It stands up the real handlers.API mux — including the
// OIDC/basic-auth middleware and access-audit logging — on an httptest server,
// then drives it exclusively through the typed client:
//
//	health (unauthenticated) -> whoami -> list profiles -> init HSM-backed root
//	-> issue an intermediate on the token -> issue a leaf from a CSR
//	-> re-read the CA inventory -> fetch the served OpenAPI document.
//
// Every CA/leaf signing operation happens on the token via the shared
// ca.Manager, so this simultaneously proves the SDK is wire-compatible with the
// server and that the whole path works against SoftHSM. It shares the SECSY_*
// gating and helpers (hsmProvider, uniqueLabel, makeCSR, intPtr) with
// fullflow_test.go, so a plain `go test ./...` with no HSM stays green.
package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/pkg/client"
)

// setupClientAPI wires an HSM-backed API server on an httptest server and
// returns its base URL. The built-in basic-auth root user (root/secret) is the
// only principal; that is enough to exercise every capability the smoke test
// touches.
func setupClientAPI(t *testing.T) string {
	t.Helper()
	provider := hsmProvider(t)

	db, err := database.New("sqlite", t.TempDir()+"/client-smoke.db")
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	api := handlers.NewAPI(db, provider, nil, hsm.Config{}, true, "")
	authMw := middleware.NewAuthMiddleware(nil, "root", "secret")

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestGeneratedClientSmoke(t *testing.T) {
	baseURL := setupClientAPI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Unauthenticated client for the public endpoints.
	pub, err := client.NewClientWithResponses(baseURL)
	if err != nil {
		t.Fatalf("NewClientWithResponses: %v", err)
	}
	// Authenticated client (built-in root via HTTP basic auth).
	c, err := client.NewClientWithResponses(baseURL, client.WithBasicAuth("root", "secret"))
	if err != nil {
		t.Fatalf("NewClientWithResponses(auth): %v", err)
	}

	// 1. Health check — public, no credentials.
	health, err := pub.GetHealthWithResponse(ctx)
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if health.StatusCode() != http.StatusOK {
		t.Fatalf("GetHealth status = %d, body = %s", health.StatusCode(), health.Body)
	}
	if health.JSON200 == nil || health.JSON200.Status == nil || *health.JSON200.Status != "ok" {
		t.Fatalf("GetHealth body = %s, want status=ok", health.Body)
	}

	// 2. An unauthenticated call to a protected endpoint must be rejected.
	if anon, err := pub.ListCAsWithResponse(ctx); err != nil {
		t.Fatalf("ListCAs (anon): %v", err)
	} else if anon.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("ListCAs (anon) status = %d, want 401", anon.StatusCode())
	}

	// 3. whoami — the root user.
	me, err := c.GetCurrentUserWithResponse(ctx)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if me.JSON200 == nil || me.JSON200.IsRoot == nil || !*me.JSON200.IsRoot {
		t.Fatalf("GetCurrentUser = %s, want is_root=true", me.Body)
	}

	// 4. List issuance profiles and remember one for the leaf issuance below.
	profs, err := c.ListProfilesWithResponse(ctx)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if profs.JSON200 == nil || len(*profs.JSON200) == 0 {
		t.Fatalf("ListProfiles returned no profiles: %s", profs.Body)
	}
	var profileName *string
	for _, p := range *profs.JSON200 {
		if p.Name != nil && (p.IsCa == nil || !*p.IsCa) {
			profileName = p.Name
			break
		}
	}

	// 5. Initialize an HSM-backed root CA (key generated on the token).
	root, err := c.InitRootCAWithResponse(ctx, client.CAInitRootRequest{
		Label:        uniqueLabel(t, "client-root"),
		KeyType:      keyprovider.KeyTypeECDSAP256,
		Subject:      client.CASubject{Cn: "Secsy Client SDK Root CA"},
		ValidityDays: intPtr(3650),
	})
	if err != nil {
		t.Fatalf("InitRootCA: %v", err)
	}
	if root.StatusCode() != http.StatusCreated || root.JSON201 == nil {
		t.Fatalf("InitRootCA status = %d, body = %s", root.StatusCode(), root.Body)
	}
	if root.JSON201.Id == nil || root.JSON201.Certificate == nil || *root.JSON201.Certificate == "" {
		t.Fatalf("InitRootCA returned no id/certificate: %s", root.Body)
	}
	rootID := *root.JSON201.Id

	// 6. Issue an intermediate CA under the root (again signed on the token).
	inter, err := c.IssueIntermediateCAWithResponse(ctx, rootID, client.CAIssueIntermediateRequest{
		Label:        uniqueLabel(t, "client-inter"),
		KeyType:      keyprovider.KeyTypeECDSAP256,
		Subject:      client.CASubject{Cn: "Secsy Client SDK Issuing CA"},
		ValidityDays: intPtr(1825),
		MaxPathLen:   intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediateCA: %v", err)
	}
	if inter.StatusCode() != http.StatusCreated || inter.JSON201 == nil || inter.JSON201.Id == nil {
		t.Fatalf("IssueIntermediateCA status = %d, body = %s", inter.StatusCode(), inter.Body)
	}
	interID := *inter.JSON201.Id

	// 7. Issue a leaf certificate from a subscriber CSR against the intermediate.
	csr := makeCSR(t, "smoke.example.com", []string{"smoke.example.com"})
	issued, err := c.IssueCertificateWithResponse(ctx, interID, client.IssueCertRequest{
		Csr:     string(csr),
		Profile: profileName,
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if issued.StatusCode() != http.StatusCreated || issued.JSON201 == nil {
		t.Fatalf("IssueCertificate status = %d, body = %s", issued.StatusCode(), issued.Body)
	}
	if issued.JSON201.Certificate == nil || *issued.JSON201.Certificate == "" ||
		issued.JSON201.Serial == nil || *issued.JSON201.Serial == "" {
		t.Fatalf("IssueCertificate returned empty certificate/serial: %s", issued.Body)
	}
	issuedSerial := *issued.JSON201.Serial

	// 8. The issued leaf must show up in the CA's certificate inventory. The list
	// endpoint is paginated (Task 83); nil params requests the first (default)
	// page, and the response is the {items, next_cursor, total} envelope.
	list, err := c.ListIssuedCertificatesWithResponse(ctx, interID, nil)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	if list.JSON200 == nil || list.JSON200.Items == nil {
		t.Fatalf("ListIssuedCertificates body = %s", list.Body)
	}
	found := false
	for _, item := range *list.JSON200.Items {
		if item.Serial != nil && *item.Serial == issuedSerial {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("issued serial %s not present in certificate inventory", issuedSerial)
	}

	// 9. Both CAs must appear in the inventory, and a point read must round-trip.
	cas, err := c.ListCAsWithResponse(ctx)
	if err != nil {
		t.Fatalf("ListCAs: %v", err)
	}
	if cas.JSON200 == nil || len(*cas.JSON200) < 2 {
		t.Fatalf("ListCAs returned %s, want >= 2 CAs", cas.Body)
	}
	got, err := c.GetCAWithResponse(ctx, rootID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if got.JSON200 == nil || got.JSON200.Id == nil || *got.JSON200.Id != rootID {
		t.Fatalf("GetCA = %s, want id %s", got.Body, rootID)
	}

	// 10. The server must serve the OpenAPI document that this SDK is built from.
	spec, err := pub.GetOpenAPIJSONWithResponse(ctx)
	if err != nil {
		t.Fatalf("GetOpenAPIJSON: %v", err)
	}
	if spec.StatusCode() != http.StatusOK || spec.JSON200 == nil {
		t.Fatalf("GetOpenAPIJSON status = %d, body = %s", spec.StatusCode(), spec.Body)
	}
	if v, ok := (*spec.JSON200)["openapi"].(string); !ok || v == "" {
		t.Fatalf("served OpenAPI document missing openapi version field: %s", spec.Body)
	}
}
