//go:build sqlite

// This file drives the Task 21 embedded operator console end-to-end against a
// real, HSM-backed CA (SoftHSM in CI). It stands up the full server handler
// stack — the exact auth + RBAC + audit middleware, route table, and embedded
// console assets a running server exposes — behind an httptest server, then
// exercises every operator workflow the console offers through the same REST
// API the browser calls:
//
//	serve embedded console assets -> list CAs & profiles -> issue a leaf via a
//	profile -> browse issued certs -> read the expiry monitor -> revoke ->
//	confirm the revocation list & CRL -> seal and recover a secret envelope.
//
// Because the console holds no privileges of its own, proving these API flows
// against the HSM proves the console's flows. It shares the SECSY_* gating and
// helpers (hsmProvider, uniqueLabel, makeCSR) with fullflow_test.go, so a plain
// `go test ./...` with no HSM stays green.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
	"golang.org/x/crypto/ssh"
)

// testExternalRoot plays the offline corporate root for the external-CA flow:
// a key + self-signed certificate that exist only in the test, signing our
// CSRs "out-of-band" the way an external parent would.
type testExternalRoot struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM []byte
}

func newTestExternalRoot(t *testing.T, cn string) *testExternalRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("external root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"External Corp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("external root cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testExternalRoot{key: key, cert: cert, certPEM: pki.EncodeCertificatePEM(der)}
}

// signCACSR signs a subordinate-CA CSR under the external root with full CA
// attributes, returning the certificate PEM.
func (r *testExternalRoot) signCACSR(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	csr, err := pki.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, csr.PublicKey, r.key)
	if err != nil {
		t.Fatalf("signing CSR under external root: %v", err)
	}
	return pki.EncodeCertificatePEM(der)
}

// consoleEnv is the wired-up server + fixtures for the console flow test.
type consoleEnv struct {
	srv     *httptest.Server
	interID string
	kek     string
}

const (
	consoleRootUser = "root"
	consoleRootPass = "console-test-password"
)

// setupConsole builds an HSM-backed root+intermediate CA and a KEK, mounts the
// full API (including the embedded console) on an httptest server, and returns
// the fixtures needed to drive the operator workflows.
func setupConsole(t *testing.T) *consoleEnv {
	t.Helper()
	provider := hsmProvider(t)
	ctx := context.Background()

	db, err := database.New("sqlite", t.TempDir()+"/console.db")
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "console-root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy Console Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "console-inter"),
		KeyType:    keyprovider.KeyTypeECDSAP256,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy Console Issuing CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	// Provision an HSM-held KEK so the secret-envelope routes are enabled.
	kek := uniqueLabel(t, "console-kek")
	if _, err := secret.ProvisionKEK(ctx, provider, kek, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}

	api := handlers.NewAPI(db, provider, nil, hsm.Config{}, false, kek)
	authMw := middleware.NewAuthMiddleware(nil, consoleRootUser, consoleRootPass)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &consoleEnv{srv: srv, interID: inter.ID, kek: kek}
}

// req issues an authenticated (root basic-auth) request and returns the status
// and raw body. A non-nil body is JSON-encoded.
func (e *consoleEnv) req(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	httpReq.SetBasicAuth(consoleRootUser, consoleRootPass)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// get fetches a path without authentication (for public assets/endpoints).
func (e *consoleEnv) getPublic(t *testing.T, path string) (int, string, []byte) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), data
}

// TestConsoleFlow exercises the operator console's backing flows end-to-end
// against the HSM, in one ordered scenario.
func TestConsoleFlow(t *testing.T) {
	env := setupConsole(t)
	var serial string
	var leafPEM string

	// --- 1. Embedded console assets are served from the binary (go:embed). ---
	t.Run("EmbeddedAssets", func(t *testing.T) {
		status, ctype, body := env.getPublic(t, "/console/")
		if status != http.StatusOK {
			t.Fatalf("GET /console/ = %d, want 200", status)
		}
		for _, want := range []string{"Operator Console", "app.js", "style.css", "DNS Records",
			// Task 143 issuance/crypto controls surfaced on the console.
			"PSD2 authorization", "Private-key usage period", "Context / AAD"} {
			if !strings.Contains(string(body), want) {
				t.Errorf("console index missing %q", want)
			}
		}
		if !strings.Contains(ctype, "html") {
			t.Errorf("console index content-type = %q, want html", ctype)
		}

		status, ctype, body = env.getPublic(t, "/console/app.js")
		if status != http.StatusOK {
			t.Fatalf("GET /console/app.js = %d, want 200", status)
		}
		if !strings.Contains(ctype, "javascript") {
			t.Errorf("app.js content-type = %q, want javascript", ctype)
		}
		for _, want := range []string{"bootAuth", "loadDNS",
			// Task 143 issuance-control logic: eIDAS PSD2 (128), PKUP (132),
			// delegated-credential eligibility (133).
			"issueQCField", "private_key_usage_period", "delegation_usage"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Errorf("app.js does not contain expected console code %q", want)
			}
		}

		if status, _, _ := env.getPublic(t, "/console/style.css"); status != http.StatusOK {
			t.Errorf("GET /console/style.css = %d, want 200", status)
		}
	})

	// --- 2. Identity: the signed-in operator's info (drives the header). ---
	t.Run("Me", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/me", nil)
		if status != http.StatusOK {
			t.Fatalf("GET /api/me = %d: %s", status, body)
		}
		var me models.UserInfo
		if err := json.Unmarshal(body, &me); err != nil {
			t.Fatalf("decode /api/me: %v", err)
		}
		if !me.IsRoot {
			t.Errorf("expected root user, got %+v", me)
		}
	})

	// --- 3. Profiles power the Issue view's profile dropdown. ---
	t.Run("Profiles", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/profiles", nil)
		if status != http.StatusOK {
			t.Fatalf("GET /api/profiles = %d: %s", status, body)
		}
		if !bytes.Contains(body, []byte(`"server"`)) {
			t.Errorf("profiles missing built-in 'server': %s", body)
		}
	})

	// --- 4. Issue a leaf via the 'server' profile (Issue view). ---
	t.Run("IssueLeaf", func(t *testing.T) {
		csr := makeCSR(t, "console.e2e.example.com", []string{"console.e2e.example.com"})
		status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]string{
			"csr":     string(csr),
			"profile": "server",
		})
		if status != http.StatusCreated {
			t.Fatalf("issue = %d: %s", status, body)
		}
		var res models.IssueCertResponse
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("decode issue response: %v", err)
		}
		if res.Serial == "" || !strings.Contains(res.Certificate, "BEGIN CERTIFICATE") {
			t.Fatalf("unexpected issue response: %+v", res)
		}
		serial = res.Serial
		leafPEM = res.Certificate
	})

	// --- 5. Browse issued certificates (Certificates view). ---
	t.Run("ListIssued", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "GET", "/api/ca/"+env.interID+"/certificates", nil)
		if status != http.StatusOK {
			t.Fatalf("list certificates = %d: %s", status, body)
		}
		// The list endpoint is paginated (Task 83): {items, next_cursor, total}.
		var page struct {
			Items []models.IssuedCertificate `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode certificates: %v", err)
		}
		found := false
		for _, c := range page.Items {
			if c.Serial == serial {
				found = true
				if c.Status != models.CertStatusValid {
					t.Errorf("issued cert status = %q, want valid", c.Status)
				}
			}
		}
		if !found {
			t.Errorf("issued serial %s not in listing", serial)
		}
	})

	// --- 5b. DNS pinning records: DANE TLSA for the CA + issued leaf. ---
	t.Run("DNSRecordsTLSA", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "GET",
			"/api/ca/"+env.interID+"/dns-records/tlsa?host=console.e2e.example.com&port=443&serial="+serial, nil)
		if status != http.StatusOK {
			t.Fatalf("dns-records tlsa = %d: %s", status, body)
		}
		var bundle struct {
			TLSA []struct {
				Usage        int    `json:"usage"`
				Selector     int    `json:"selector"`
				MatchingType int    `json:"matching_type"`
				Data         string `json:"data"`
				Zone         string `json:"zone"`
			} `json:"tlsa"`
			Zone string `json:"zone"`
		}
		if err := json.Unmarshal(body, &bundle); err != nil {
			t.Fatalf("decode tlsa bundle: %v", err)
		}
		// 4 DANE-EE (leaf) + 8 issuer (PKIX-CA + DANE-TA) records.
		if len(bundle.TLSA) != 12 {
			t.Fatalf("got %d TLSA records, want 12", len(bundle.TLSA))
		}
		// The recommended DANE-EE 3 1 1 record: SPKI/SHA-256, 64 hex chars.
		var found311 bool
		for _, r := range bundle.TLSA {
			if r.Usage == 3 && r.Selector == 1 && r.MatchingType == 1 {
				found311 = true
				if len(r.Data) != 64 {
					t.Errorf("3 1 1 data length = %d, want 64 (SHA-256 hex)", len(r.Data))
				}
				want := "_443._tcp.console.e2e.example.com. IN TLSA 3 1 1 " + r.Data
				if r.Zone != want {
					t.Errorf("3 1 1 zone = %q, want %q", r.Zone, want)
				}
			}
		}
		if !found311 {
			t.Error("missing DANE-EE 3 1 1 record")
		}
		if !strings.Contains(bundle.Zone, "IN TLSA 0 ") || !strings.Contains(bundle.Zone, "IN TLSA 2 ") {
			t.Errorf("zone missing issuer PKIX-CA/DANE-TA records: %s", bundle.Zone)
		}
	})

	// --- 6. Expiry monitor feed (Expiry Monitor view). ---
	t.Run("MonitorExpiring", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/monitor/expiring", nil)
		if status != http.StatusOK {
			t.Fatalf("monitor expiring = %d: %s", status, body)
		}
		var rep struct {
			Counts       map[string]int `json:"counts"`
			Certificates []struct {
				Serial   string `json:"serial"`
				Severity string `json:"severity"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatalf("decode monitor report: %v", err)
		}
		if rep.Certificates == nil {
			t.Error("monitor report has no certificates field")
		}
	})

	// --- 7. Revoke the leaf (Revoke action). ---
	t.Run("Revoke", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/revoke", map[string]string{
			"serial": serial,
			"reason": "superseded",
		})
		if status != http.StatusOK {
			t.Fatalf("revoke = %d: %s", status, body)
		}
		if !bytes.Contains(body, []byte(`"revoked"`)) {
			t.Errorf("unexpected revoke response: %s", body)
		}
	})

	// --- 8. Revocation now visible in the revoked list & the CRL. ---
	t.Run("RevokedListAndCRL", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "GET", "/api/ca/"+env.interID+"/revoked", nil)
		if status != http.StatusOK {
			t.Fatalf("revoked list = %d: %s", status, body)
		}
		if !bytes.Contains(body, []byte(serial)) {
			t.Errorf("revoked serial %s not in revocation list: %s", serial, body)
		}

		// The CRL is a public endpoint (relying parties fetch it unauthenticated).
		st, ctype, crl := env.getPublic(t, "/api/ca/"+env.interID+"/crl?format=pem")
		if st != http.StatusOK {
			t.Fatalf("CRL = %d", st)
		}
		if !strings.Contains(ctype, "pem") {
			t.Errorf("CRL content-type = %q", ctype)
		}
		if !bytes.Contains(crl, []byte("BEGIN X509 CRL")) {
			t.Errorf("CRL is not PEM: %s", crl)
		}
	})

	// --- 8b. Bulk revocation (Task 70): the console's incident-response panel
	// drives the dry-run → confirm-count → execute contract through the real
	// route table (proving the "revocations:bulk" pattern) against the HSM.
	t.Run("BulkRevoke", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			cn := "breach-" + string(rune('a'+i)) + ".bulk.example.com"
			csr := makeCSR(t, cn, []string{cn})
			status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]string{
				"csr": string(csr), "profile": "server",
			})
			if status != http.StatusCreated {
				t.Fatalf("seed issue %d = %d: %s", i, status, body)
			}
		}

		// Dry run: the pattern selects exactly the three seeded leaves.
		status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/revocations:bulk", map[string]any{
			"dry_run": true,
			"reason":  "keyCompromise",
			"filter":  map[string]any{"pattern": "*.bulk.example.com"},
		})
		if status != http.StatusOK {
			t.Fatalf("bulk dry run = %d: %s", status, body)
		}
		var plan struct {
			OperationID string `json:"operation_id"`
			Total       int    `json:"total"`
		}
		if err := json.Unmarshal(body, &plan); err != nil {
			t.Fatalf("decode plan: %v", err)
		}
		if plan.Total != 3 {
			t.Fatalf("plan total = %d, want 3: %s", plan.Total, body)
		}

		// A drifted confirmation is refused without side effects.
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/revocations:bulk", map[string]any{
			"reason":        "keyCompromise",
			"filter":        map[string]any{"pattern": "*.bulk.example.com"},
			"confirm_count": 2,
		})
		if status != http.StatusConflict {
			t.Fatalf("drifted confirm = %d: %s, want 409", status, body)
		}

		// The confirmed count executes: three revoked, CRL regenerated once.
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/revocations:bulk", map[string]any{
			"reason":        "keyCompromise",
			"filter":        map[string]any{"pattern": "*.bulk.example.com"},
			"confirm_count": plan.Total,
			"operation_id":  plan.OperationID,
		})
		if status != http.StatusOK {
			t.Fatalf("bulk execute = %d: %s", status, body)
		}
		var result struct {
			Revoked   int      `json:"revoked"`
			CRLScopes []string `json:"crl_scopes"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if result.Revoked != 3 || len(result.CRLScopes) == 0 {
			t.Fatalf("bulk result = %+v, want 3 revoked with regenerated scopes", result)
		}

		// The regenerated CRL (public endpoint) now carries all three serials
		// alongside the single revocation from step 7.
		st, _, crlPEM := env.getPublic(t, "/api/ca/"+env.interID+"/crl?format=pem")
		if st != http.StatusOK {
			t.Fatalf("CRL after bulk = %d", st)
		}
		block, _ := pem.Decode(crlPEM)
		if block == nil {
			t.Fatal("CRL is not PEM")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatalf("parsing CRL: %v", err)
		}
		if len(crl.RevokedCertificateEntries) < 4 {
			t.Errorf("CRL entries = %d, want >= 4 (single + 3 bulk)", len(crl.RevokedCertificateEntries))
		}
	})

	// --- 8c. Bulk / batch issuance (Task 101): the console's fleet-provisioning
	// panel drives the dry-run → confirm-count → execute contract through the real
	// route table (proving the "certificates:bulk" pattern) against the HSM, with
	// per-item results and partial success.
	t.Run("BulkIssue", func(t *testing.T) {
		items := []map[string]any{
			{"ref": "fleet-1", "csr": string(makeCSR(t, "fleet-1.example.com", []string{"fleet-1.example.com"})), "profile": "server"},
			{"ref": "fleet-2", "csr": string(makeCSR(t, "fleet-2.example.com", []string{"fleet-2.example.com"})), "profile": "server"},
			{"ref": "bad", "csr": "not a csr", "profile": "server"},
		}

		// Dry run: two well-formed items, one malformed.
		status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/certificates:bulk", map[string]any{
			"dry_run": true, "items": items,
		})
		if status != http.StatusOK {
			t.Fatalf("bulk issue dry run = %d: %s", status, body)
		}
		var plan struct {
			OperationID string `json:"operation_id"`
			Requested   int    `json:"requested"`
			Valid       int    `json:"valid"`
			Invalid     int    `json:"invalid"`
		}
		if err := json.Unmarshal(body, &plan); err != nil {
			t.Fatalf("decode plan: %v", err)
		}
		if plan.Requested != 3 || plan.Valid != 2 || plan.Invalid != 1 {
			t.Fatalf("plan = requested %d valid %d invalid %d, want 3/2/1: %s", plan.Requested, plan.Valid, plan.Invalid, body)
		}

		// A wrong confirm count is refused with 409 and no side effects.
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/certificates:bulk", map[string]any{
			"items": items, "confirm_count": 2,
		})
		if status != http.StatusConflict {
			t.Fatalf("wrong confirm = %d: %s, want 409", status, body)
		}

		// The confirmed batch issues the two valid items and reports the third
		// failed — partial success, HTTP 200.
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/certificates:bulk", map[string]any{
			"items": items, "confirm_count": 3, "operation_id": plan.OperationID,
		})
		if status != http.StatusOK {
			t.Fatalf("bulk issue execute = %d: %s", status, body)
		}
		var result struct {
			Issued int `json:"issued"`
			Failed int `json:"failed"`
			Items  []struct {
				Ref, Status, Serial, Certificate string
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if result.Issued != 2 || result.Failed != 1 {
			t.Fatalf("bulk issue result = issued %d failed %d, want 2/1: %s", result.Issued, result.Failed, body)
		}
		for _, it := range result.Items {
			if it.Status == "issued" {
				if it.Serial == "" || !strings.Contains(it.Certificate, "BEGIN CERTIFICATE") {
					t.Errorf("issued item %s missing serial/cert", it.Ref)
				}
			}
		}
	})

	// --- 9. Certificate inventory (Inventory view): JSON + CSV export. ---
	t.Run("Inventory", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "GET", "/api/report/inventory", nil)
		if status != http.StatusOK {
			t.Fatalf("inventory = %d: %s", status, body)
		}
		var inv struct {
			Total        int `json:"total"`
			Certificates []struct {
				Serial         string `json:"serial"`
				Status         string `json:"status"`
				CAID           string `json:"ca_id"`
				RevocationText string `json:"revocation_reason_text"`
				LintVerdict    string `json:"lint_verdict"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal(body, &inv); err != nil {
			t.Fatalf("decode inventory: %v", err)
		}
		var rec *struct {
			Serial         string `json:"serial"`
			Status         string `json:"status"`
			CAID           string `json:"ca_id"`
			RevocationText string `json:"revocation_reason_text"`
			LintVerdict    string `json:"lint_verdict"`
		}
		for i := range inv.Certificates {
			if inv.Certificates[i].Serial == serial {
				rec = &inv.Certificates[i]
			}
		}
		if rec == nil {
			t.Fatalf("issued serial %s not in inventory: %s", serial, body)
		}
		// The leaf was revoked (step 7) with reason "superseded", so the inventory
		// must reflect that.
		if rec.Status != "revoked" {
			t.Errorf("inventory status = %q, want revoked", rec.Status)
		}
		if rec.RevocationText != "superseded" {
			t.Errorf("inventory revocation reason = %q, want superseded", rec.RevocationText)
		}

		// CSV export carries a spreadsheet content-type, the header row, and the row.
		resp, err := http.NewRequest("GET", env.srv.URL+"/api/report/inventory?format=csv", nil)
		if err != nil {
			t.Fatalf("csv request: %v", err)
		}
		resp.SetBasicAuth(consoleRootUser, consoleRootPass)
		r, err := http.DefaultClient.Do(resp)
		if err != nil {
			t.Fatalf("csv fetch: %v", err)
		}
		defer r.Body.Close()
		csv, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("csv = %d: %s", r.StatusCode, csv)
		}
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "csv") {
			t.Errorf("csv content-type = %q, want csv", ct)
		}
		if !bytes.Contains(csv, []byte("serial,common_name")) {
			t.Errorf("csv missing header row: %s", csv)
		}
		if !bytes.Contains(csv, []byte(serial)) {
			t.Errorf("csv missing issued serial %s", serial)
		}
	})

	// --- 10. Compliance / lint summary dashboard (Compliance view). ---
	t.Run("Compliance", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/report/compliance", nil)
		if status != http.StatusOK {
			t.Fatalf("compliance = %d: %s", status, body)
		}
		var rep struct {
			Conformant bool `json:"conformant"`
			CAs        []struct {
				Label     string `json:"label"`
				HSMBacked bool   `json:"hsm_backed"`
			} `json:"cas"`
			Lint struct {
				IssuedTotal int `json:"issued_total"`
				Pass        int `json:"pass"`
			} `json:"lint"`
			AuditChain struct {
				Valid bool `json:"valid"`
			} `json:"audit_chain"`
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			t.Fatalf("decode compliance: %v", err)
		}
		if !rep.AuditChain.Valid {
			t.Errorf("audit chain reported invalid: %s", body)
		}
		if !rep.Conformant {
			t.Errorf("expected conformant report: %s", body)
		}
		if rep.Lint.IssuedTotal < 1 {
			t.Errorf("compliance issued_total = %d, want >= 1", rep.Lint.IssuedTotal)
		}
		if len(rep.CAs) == 0 {
			t.Error("compliance report has no CAs")
		}
	})

	// --- 11. CRL/delta-CRL status view (Certificates view strip). ---
	t.Run("CRLStatus", func(t *testing.T) {
		if serial == "" {
			t.Skip("no leaf issued")
		}
		status, body := env.req(t, "GET", "/api/ca/"+env.interID+"/crl/status", nil)
		if status != http.StatusOK {
			t.Fatalf("crl status = %d: %s", status, body)
		}
		var st struct {
			Base struct {
				Available    bool   `json:"available"`
				Number       string `json:"number"`
				RevokedCount int    `json:"revoked_count"`
			} `json:"base"`
		}
		if err := json.Unmarshal(body, &st); err != nil {
			t.Fatalf("decode crl status: %v", err)
		}
		if !st.Base.Available {
			t.Fatalf("base CRL not available: %s", body)
		}
		if st.Base.Number == "" {
			t.Errorf("base CRL has no number: %s", body)
		}
		// The revoked leaf must be counted on the base CRL.
		if st.Base.RevokedCount < 1 {
			t.Errorf("base CRL revoked_count = %d, want >= 1", st.Base.RevokedCount)
		}
	})

	// --- 12. Trust-bundle / chain download (Trust Bundle view). ---
	t.Run("ChainDownload", func(t *testing.T) {
		// The chain is a public endpoint (relying parties fetch it unauthenticated).
		st, ctype, chain := env.getPublic(t, "/api/ca/"+env.interID+"/chain")
		if st != http.StatusOK {
			t.Fatalf("chain = %d", st)
		}
		_ = ctype
		if !bytes.Contains(chain, []byte("BEGIN CERTIFICATE")) {
			t.Errorf("chain is not a PEM bundle: %s", chain)
		}
	})

	// --- 13. Secret envelope seal + recover (Secrets view). ---
	t.Run("SecretRoundTrip", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/secret/info", nil)
		if status != http.StatusOK {
			t.Fatalf("secret info = %d: %s", status, body)
		}
		if !bytes.Contains(body, []byte(env.kek)) {
			t.Errorf("secret info missing KEK label %s: %s", env.kek, body)
		}

		plaintext := []byte("correct horse battery staple")
		status, body = env.req(t, "POST", "/api/secret/encrypt", map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		})
		if status != http.StatusOK {
			t.Fatalf("encrypt = %d: %s", status, body)
		}
		var enc struct {
			Envelope json.RawMessage `json:"envelope"`
		}
		if err := json.Unmarshal(body, &enc); err != nil {
			t.Fatalf("decode encrypt response: %v", err)
		}
		if bytes.Contains(enc.Envelope, plaintext) {
			t.Fatal("plaintext leaked into envelope")
		}

		status, body = env.req(t, "POST", "/api/secret/decrypt", map[string]any{
			"envelope": enc.Envelope,
		})
		if status != http.StatusOK {
			t.Fatalf("decrypt = %d: %s", status, body)
		}
		var dec struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.Unmarshal(body, &dec); err != nil {
			t.Fatalf("decode decrypt response: %v", err)
		}
		got, err := base64.StdEncoding.DecodeString(dec.Plaintext)
		if err != nil {
			t.Fatalf("decode plaintext b64: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("secret round-trip mismatch: got %q want %q", got, plaintext)
		}

		// The Secrets view renders the escrow policy shape; none is configured
		// here, so the info endpoint must say so (rather than omit the fields).
		var info struct {
			EscrowAvailable *bool `json:"escrow_available"`
		}
		_, body = env.req(t, "GET", "/api/secret/info", nil)
		if err := json.Unmarshal(body, &info); err != nil {
			t.Fatalf("decode secret info: %v", err)
		}
		if info.EscrowAvailable == nil || *info.EscrowAvailable {
			t.Errorf("escrow_available should be present and false: %s", body)
		}
	})

	// --- 14. CA lifecycle via the Authorities view: create a root and an
	// intermediate over REST, rotate the intermediate's signing key, watch the
	// rotation status, and retire the superseded key. ---
	var root2ID string
	t.Run("AuthoritiesLifecycle", func(t *testing.T) {
		status, body := env.req(t, "POST", "/api/ca/init-root", map[string]any{
			"label":         uniqueLabel(t, "console-root2"),
			"key_type":      "ecdsa-p256",
			"subject":       map[string]string{"cn": "Console Root 2", "o": "Secsy"},
			"validity_days": 3650,
		})
		if status != http.StatusCreated {
			t.Fatalf("init-root = %d: %s", status, body)
		}
		var root2 models.CA
		if err := json.Unmarshal(body, &root2); err != nil {
			t.Fatalf("decode root: %v", err)
		}
		root2ID = root2.ID

		status, body = env.req(t, "POST", "/api/ca/"+root2.ID+"/issue-intermediate", map[string]any{
			"label":         uniqueLabel(t, "console-inter2"),
			"key_type":      "ecdsa-p256",
			"subject":       map[string]string{"cn": "Console Issuing 2"},
			"validity_days": 1825,
			"max_path_len":  0,
		})
		if status != http.StatusCreated {
			t.Fatalf("issue-intermediate = %d: %s", status, body)
		}
		var inter2 models.CA
		if err := json.Unmarshal(body, &inter2); err != nil {
			t.Fatalf("decode intermediate: %v", err)
		}

		// Rotate the intermediate's key: same subject, fresh HSM key.
		status, body = env.req(t, "POST", "/api/ca/"+inter2.ID+"/rotate", map[string]any{})
		if status != http.StatusCreated {
			t.Fatalf("rotate = %d: %s", status, body)
		}
		var rot struct {
			OldCA            models.CA `json:"old_ca"`
			NewCA            models.CA `json:"new_ca"`
			CombinedChainPEM string    `json:"combined_chain_pem"`
		}
		if err := json.Unmarshal(body, &rot); err != nil {
			t.Fatalf("decode rotate response: %v", err)
		}
		if rot.OldCA.ID != inter2.ID || rot.OldCA.Status != models.CAStatusSuperseded {
			t.Errorf("old CA not superseded: %+v", rot.OldCA)
		}
		if rot.NewCA.ID == inter2.ID || rot.NewCA.Status != models.CAStatusActive {
			t.Errorf("new CA not active: %+v", rot.NewCA)
		}
		if strings.Count(rot.CombinedChainPEM, "BEGIN CERTIFICATE") < 3 {
			t.Errorf("combined chain should bundle old+new+parent: %s", rot.CombinedChainPEM)
		}

		// Rotation status: superseded, linked to its successor, retirable (no leaves).
		status, body = env.req(t, "GET", "/api/ca/"+inter2.ID+"/rotation", nil)
		if status != http.StatusOK {
			t.Fatalf("rotation status = %d: %s", status, body)
		}
		var rs struct {
			CA           models.CA  `json:"ca"`
			Successor    *models.CA `json:"successor"`
			SafeToRetire bool       `json:"safe_to_retire"`
		}
		if err := json.Unmarshal(body, &rs); err != nil {
			t.Fatalf("decode rotation status: %v", err)
		}
		if rs.Successor == nil || rs.Successor.ID != rot.NewCA.ID || !rs.SafeToRetire {
			t.Errorf("unexpected rotation status: %s", body)
		}

		// The lineage shows up in the Authorities view's rotation list.
		status, body = env.req(t, "GET", "/api/rotations", nil)
		if status != http.StatusOK {
			t.Fatalf("list rotations = %d: %s", status, body)
		}
		if !bytes.Contains(body, []byte(inter2.ID)) || !bytes.Contains(body, []byte(rot.NewCA.ID)) {
			t.Errorf("rotation list missing lineage members: %s", body)
		}

		// Retire the drained superseded key; the parent CRL now lists it.
		status, body = env.req(t, "POST", "/api/ca/"+inter2.ID+"/retire", map[string]any{
			"reason": "cessationOfOperation",
		})
		if status != http.StatusOK {
			t.Fatalf("retire = %d: %s", status, body)
		}
		var ret struct {
			RetiredCA     models.CA `json:"retired_ca"`
			RevokedSerial string    `json:"revoked_serial"`
			CRLPEM        string    `json:"crl_pem"`
		}
		if err := json.Unmarshal(body, &ret); err != nil {
			t.Fatalf("decode retire response: %v", err)
		}
		if ret.RetiredCA.Status != models.CAStatusRetired || ret.RevokedSerial == "" {
			t.Errorf("unexpected retire result: %s", body)
		}
		if !strings.Contains(ret.CRLPEM, "BEGIN X509 CRL") {
			t.Errorf("retire did not return the refreshed parent CRL: %q", ret.CRLPEM)
		}
	})

	// --- 15. Renewal (Certificates view's Renew action). ---
	t.Run("RenewLeaf", func(t *testing.T) {
		csr := makeCSR(t, "renew.e2e.example.com", []string{"renew.e2e.example.com"})
		status, body := env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]string{
			"csr": string(csr), "profile": "server",
		})
		if status != http.StatusCreated {
			t.Fatalf("issue = %d: %s", status, body)
		}
		var issued models.IssueCertResponse
		if err := json.Unmarshal(body, &issued); err != nil {
			t.Fatalf("decode issue: %v", err)
		}

		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/renew", map[string]string{
			"serial": issued.Serial,
		})
		if status != http.StatusCreated {
			t.Fatalf("renew = %d: %s", status, body)
		}
		var renewed models.IssueCertResponse
		if err := json.Unmarshal(body, &renewed); err != nil {
			t.Fatalf("decode renew: %v", err)
		}
		if renewed.Serial == "" || renewed.Serial == issued.Serial {
			t.Errorf("renewal must mint a fresh serial: old=%s new=%s", issued.Serial, renewed.Serial)
		}
	})

	// --- 16. Cross-signing (Authorities view): the second root certifies the
	// original intermediate's key, yielding an alternate chain. ---
	t.Run("CrossSignFlow", func(t *testing.T) {
		if root2ID == "" {
			t.Skip("AuthoritiesLifecycle did not run")
		}
		status, body := env.req(t, "POST", "/api/ca/"+root2ID+"/cross-signs", map[string]any{
			"subject_ca_id": env.interID,
		})
		if status != http.StatusCreated {
			t.Fatalf("cross-sign = %d: %s", status, body)
		}
		var cs struct {
			CrossSign struct {
				ID string `json:"id"`
			} `json:"cross_sign"`
			ChainPEM string `json:"chain_pem"`
		}
		if err := json.Unmarshal(body, &cs); err != nil {
			t.Fatalf("decode cross-sign: %v", err)
		}
		if cs.CrossSign.ID == "" || !strings.Contains(cs.ChainPEM, "BEGIN CERTIFICATE") {
			t.Fatalf("unexpected cross-sign result: %s", body)
		}

		status, body = env.req(t, "GET", "/api/ca/"+env.interID+"/cross-signs", nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte(cs.CrossSign.ID)) {
			t.Errorf("cross-sign list = %d, missing %s: %s", status, cs.CrossSign.ID, body)
		}

		// Both the per-cross-sign chain and the alternate-chain listing are public.
		st, _, chain := env.getPublic(t, "/api/ca/"+env.interID+"/cross-signs/"+cs.CrossSign.ID+"/chain")
		if st != http.StatusOK || !bytes.Contains(chain, []byte("BEGIN CERTIFICATE")) {
			t.Errorf("cross-sign chain download = %d: %s", st, chain)
		}
		st, _, chains := env.getPublic(t, "/api/ca/"+env.interID+"/chains")
		if st != http.StatusOK || !bytes.Contains(chains, []byte(cs.CrossSign.ID)) {
			t.Errorf("alternate chains = %d: %s", st, chains)
		}
	})

	// --- 16b. Externally-signed subordinate CA (Authorities view, Task 69):
	// generate an HSM-backed key + CSR via REST, play the offline corporate root
	// in-test, import the signed certificate + external chain, and confirm the
	// public chain endpoint reaches the external anchor and issuance works. ---
	t.Run("ExternalCAFlow", func(t *testing.T) {
		status, body := env.req(t, "POST", "/api/ca/csr", map[string]any{
			"label":    uniqueLabel(t, "console-extsub"),
			"key_type": "ecdsa-p256",
			"subject":  map[string]string{"cn": "Console External Sub CA", "o": "Secsy"},
		})
		if status != http.StatusCreated {
			t.Fatalf("ca csr = %d: %s", status, body)
		}
		var csrRes models.CAExternalCSRResponse
		if err := json.Unmarshal(body, &csrRes); err != nil {
			t.Fatalf("decode csr response: %v", err)
		}
		if csrRes.CA.Status != models.CAStatusPending || !strings.Contains(csrRes.CSRPEM, "BEGIN CERTIFICATE REQUEST") {
			t.Fatalf("unexpected csr result: status=%q csr=%.60q", csrRes.CA.Status, csrRes.CSRPEM)
		}
		extID := csrRes.CA.ID

		// A pending CA must not appear among the SSH signing keys.
		status, body = env.req(t, "GET", "/api/ssh/cas", nil)
		if status != http.StatusOK {
			t.Fatalf("list ssh cas = %d: %s", status, body)
		}
		if bytes.Contains(body, []byte(extID)) {
			t.Errorf("pending external CA leaked into the SSH CA list: %s", body)
		}

		// The CSR is re-downloadable while the signing ceremony is in flight.
		status, body = env.req(t, "GET", "/api/ca/"+extID+"/csr", nil)
		if status != http.StatusOK || string(body) != csrRes.CSRPEM {
			t.Fatalf("csr re-download = %d (matches original: %t)", status, string(body) == csrRes.CSRPEM)
		}

		// Play the external root out-of-band and sign the CSR.
		root := newTestExternalRoot(t, "Console External Corp Root")
		signedPEM := root.signCACSR(t, []byte(csrRes.CSRPEM))

		// Fail-closed check via REST: a certificate for a different key is refused.
		otherRes, otherBody := env.req(t, "POST", "/api/ca/csr", map[string]any{
			"label":    uniqueLabel(t, "console-extsub-other"),
			"key_type": "ecdsa-p256",
			"subject":  map[string]string{"cn": "Console External Other"},
		})
		if otherRes != http.StatusCreated {
			t.Fatalf("second ca csr = %d: %s", otherRes, otherBody)
		}
		var other models.CAExternalCSRResponse
		if err := json.Unmarshal(otherBody, &other); err != nil {
			t.Fatal(err)
		}
		status, body = env.req(t, "POST", "/api/ca/"+other.CA.ID+"/import-cert", map[string]any{
			"certificate_pem": string(signedPEM), // signed for extID's key, not other's
		})
		if status != http.StatusBadRequest || !bytes.Contains(body, []byte("does not match")) {
			t.Fatalf("mismatched import = %d, want 400 key mismatch: %s", status, body)
		}

		// Import the certificate with the external root as chain.
		status, body = env.req(t, "POST", "/api/ca/"+extID+"/import-cert", map[string]any{
			"certificate_pem": string(signedPEM),
			"chain_pem":       string(root.certPEM),
		})
		if status != http.StatusOK {
			t.Fatalf("import-cert = %d: %s", status, body)
		}
		var imp models.CAImportCertResponse
		if err := json.Unmarshal(body, &imp); err != nil {
			t.Fatalf("decode import response: %v", err)
		}
		if imp.CA.Status != models.CAStatusActive || imp.CA.ExternalChain == "" {
			t.Fatalf("import did not activate with chain: %s", body)
		}

		// The public chain endpoint serves our certificate plus the external root.
		st, _, chain := env.getPublic(t, "/api/ca/"+extID+"/chain")
		if st != http.StatusOK {
			t.Fatalf("chain download = %d", st)
		}
		if !bytes.Contains(chain, bytes.TrimSpace(root.certPEM)) {
			t.Errorf("served chain does not include the external root:\n%s", chain)
		}
		if strings.Count(string(chain), "BEGIN CERTIFICATE") < 2 {
			t.Errorf("served chain should carry the CA cert + external root: %s", chain)
		}

		// Issuance from the imported CA works through the same REST path.
		csr := makeCSR(t, "ext.e2e.example.com", []string{"ext.e2e.example.com"})
		status, body = env.req(t, "POST", "/api/ca/"+extID+"/issue", map[string]string{
			"csr": string(csr), "profile": "server",
		})
		if status != http.StatusCreated {
			t.Fatalf("issue under imported CA = %d: %s", status, body)
		}
	})

	// --- 17. SSH CA (SSH CA view): create, list, sign a user key, browse the
	// inventory, revoke, and fetch the public trust anchor + KRL. ---
	t.Run("SSHCAFlow", func(t *testing.T) {
		status, body := env.req(t, "POST", "/api/ssh/cas", map[string]string{
			"label": uniqueLabel(t, "console-sshca"), "key_type": "ed25519",
		})
		if status != http.StatusCreated {
			t.Fatalf("create SSH CA = %d: %s", status, body)
		}
		var sshCA models.CA
		if err := json.Unmarshal(body, &sshCA); err != nil {
			t.Fatalf("decode SSH CA: %v", err)
		}

		// The SSH CA list carries it — and no X.509 CA leaks in.
		status, body = env.req(t, "GET", "/api/ssh/cas", nil)
		if status != http.StatusOK {
			t.Fatalf("list SSH CAs = %d: %s", status, body)
		}
		var sshCAs []models.CA
		if err := json.Unmarshal(body, &sshCAs); err != nil {
			t.Fatalf("decode SSH CA list: %v", err)
		}
		found := false
		for _, c := range sshCAs {
			if c.ID == sshCA.ID {
				found = true
			}
			if c.ID == env.interID {
				t.Errorf("X.509 CA leaked into the SSH CA list")
			}
		}
		if !found {
			t.Fatalf("created SSH CA missing from list: %s", body)
		}

		if st, body := env.req(t, "GET", "/api/ssh/profiles", nil); st != http.StatusOK ||
			!bytes.Contains(body, []byte("user-default")) {
			t.Errorf("ssh profiles = %d: %s", st, body)
		}

		// Sign a fresh ed25519 user key.
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate user key: %v", err)
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("ssh public key: %v", err)
		}
		status, body = env.req(t, "POST", "/api/ssh/cas/"+sshCA.ID+"/sign", map[string]any{
			"public_key": string(ssh.MarshalAuthorizedKey(sshPub)),
			"cert_type":  "user",
			"key_id":     "console-e2e",
			"principals": []string{"alice"},
		})
		if status != http.StatusCreated {
			t.Fatalf("ssh sign = %d: %s", status, body)
		}
		var signed struct {
			Certificate string `json:"certificate"`
			Serial      string `json:"serial"`
		}
		if err := json.Unmarshal(body, &signed); err != nil {
			t.Fatalf("decode ssh sign: %v", err)
		}
		if !strings.Contains(signed.Certificate, "cert-v01@openssh.com") || signed.Serial == "" {
			t.Fatalf("unexpected ssh certificate: %s", body)
		}

		if st, body := env.req(t, "GET", "/api/ssh/cas/"+sshCA.ID+"/certificates", nil); st != http.StatusOK ||
			!bytes.Contains(body, []byte(`"console-e2e"`)) {
			t.Errorf("ssh certificates = %d: %s", st, body)
		}

		status, body = env.req(t, "POST", "/api/ssh/cas/"+sshCA.ID+"/revoke", map[string]string{
			"serial": signed.Serial, "reason": "key compromise drill",
		})
		if status != http.StatusOK {
			t.Fatalf("ssh revoke = %d: %s", status, body)
		}
		if st, body := env.req(t, "GET", "/api/ssh/cas/"+sshCA.ID+"/revocations", nil); st != http.StatusOK ||
			!bytes.Contains(body, []byte(signed.Serial)) {
			t.Errorf("ssh revocations = %d: %s", st, body)
		}

		// Public trust-anchor + KRL downloads (what the view's links point at).
		st, _, pubLine := env.getPublic(t, "/api/ssh/cas/"+sshCA.ID+"/public")
		if st != http.StatusOK || !bytes.Contains(pubLine, []byte("ssh-ed25519")) {
			t.Errorf("ssh public key = %d: %s", st, pubLine)
		}
		st, _, krl := env.getPublic(t, "/api/ssh/cas/"+sshCA.ID+"/krl")
		if st != http.StatusOK || !bytes.HasPrefix(krl, []byte("SSHKRL")) {
			t.Errorf("krl = %d (magic %q)", st, string(krl[:min(6, len(krl))]))
		}
	})

	// --- 18. Artifact signing (Signing view): the service is not configured in
	// this environment, so the view sees an empty signer list and a clean 503. ---
	t.Run("SigningEndpoints", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/sign/signers", nil)
		if status != http.StatusOK || strings.TrimSpace(string(body)) != "[]" {
			t.Errorf("signers = %d: %s (want empty list)", status, body)
		}
		status, _ = env.req(t, "POST", "/api/sign", map[string]string{"signer": "release", "digest": "00"})
		if status != http.StatusServiceUnavailable {
			t.Errorf("sign without service = %d, want 503", status)
		}
	})

	// --- 19. Ad-hoc lint (Compliance view): the issued leaf passes the profile
	// gate it was issued under; garbage is rejected. ---
	t.Run("LintEndpoint", func(t *testing.T) {
		status, body := env.req(t, "POST", "/api/lint", map[string]string{
			"certificate": leafPEM, "profile": "server",
		})
		if status != http.StatusOK {
			t.Fatalf("lint = %d: %s", status, body)
		}
		var res struct {
			Subject string `json:"subject"`
			Pass    bool   `json:"pass"`
			Errors  int    `json:"errors"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			t.Fatalf("decode lint: %v", err)
		}
		if res.Subject == "" {
			t.Errorf("lint response missing subject: %s", body)
		}
		if res.Errors > 0 {
			t.Errorf("the gate-passed leaf must not lint with errors: %s", body)
		}

		if st, _ := env.req(t, "POST", "/api/lint", map[string]string{"certificate": "not pem"}); st != http.StatusBadRequest {
			t.Errorf("lint of garbage = %d, want 400", st)
		}
	})

	// --- 20. HSM key inventory (Authorities view): the issuing CA's key is on
	// the token, non-extractable, and bound to its CA record. ---
	t.Run("KeyInventory", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/inventory/keys", nil)
		if status != http.StatusOK {
			t.Fatalf("inventory = %d: %s", status, body)
		}
		var inv struct {
			Provider string `json:"provider"`
			Keys     []struct {
				Label       string `json:"label"`
				Extractable bool   `json:"extractable"`
				CALabel     string `json:"ca_label"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(body, &inv); err != nil {
			t.Fatalf("decode inventory: %v", err)
		}
		st, caBody := env.req(t, "GET", "/api/keys/"+env.interID, nil)
		if st != http.StatusOK {
			t.Fatalf("get CA = %d", st)
		}
		var inter models.CA
		if err := json.Unmarshal(caBody, &inter); err != nil {
			t.Fatalf("decode CA: %v", err)
		}
		found := false
		for _, k := range inv.Keys {
			if k.Label == inter.Label {
				found = true
				if k.Extractable {
					t.Errorf("issuing CA key %q reports extractable", k.Label)
				}
				if k.CALabel == "" {
					t.Errorf("issuing CA key %q not bound to its CA record", k.Label)
				}
			}
		}
		if !found {
			t.Errorf("issuing CA key %q missing from provider inventory", inter.Label)
		}
	})

	// --- 21. Audit trail (Audit view): list, verify the hash chain, export. ---
	t.Run("AuditTrail", func(t *testing.T) {
		status, body := env.req(t, "GET", "/api/events?limit=50", nil)
		if status != http.StatusOK {
			t.Fatalf("events = %d: %s", status, body)
		}
		var page struct {
			Entries []json.RawMessage `json:"entries"`
			Total   int               `json:"total"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode events: %v", err)
		}
		if page.Total == 0 || len(page.Entries) == 0 {
			t.Fatalf("the flow above must have produced audit events: %s", body)
		}

		status, body = env.req(t, "GET", "/api/events/verify", nil)
		if status != http.StatusOK {
			t.Fatalf("verify = %d: %s", status, body)
		}
		var vr struct {
			Valid bool `json:"valid"`
			Count int  `json:"count"`
		}
		if err := json.Unmarshal(body, &vr); err != nil {
			t.Fatalf("decode verify: %v", err)
		}
		if !vr.Valid || vr.Count == 0 {
			t.Errorf("event chain must verify: %s", body)
		}

		// Exports: NDJSON parses per line; CEF carries its header; junk is a 400.
		status, body = env.req(t, "GET", "/api/events/export?format=json", nil)
		if status != http.StatusOK {
			t.Fatalf("export json = %d: %s", status, body)
		}
		lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
		if len(lines) != vr.Count {
			t.Errorf("export line count = %d, chain count = %d", len(lines), vr.Count)
		}
		var ev struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(lines[0], &ev); err != nil || ev.Action == "" {
			t.Errorf("export line is not an event: %s (%v)", lines[0], err)
		}

		status, body = env.req(t, "GET", "/api/events/export?format=cef", nil)
		if status != http.StatusOK || !bytes.Contains(body, []byte("CEF:0|")) {
			t.Errorf("export cef = %d: %.120s", status, body)
		}
		if st, _ := env.req(t, "GET", "/api/events/export?format=bogus", nil); st != http.StatusBadRequest {
			t.Errorf("bogus export format = %d, want 400", st)
		}
	})

	// --- Console issuance controls (Task 143): eIDAS QCStatements / PSD2 (Task
	// 128), the RFC 5280 private-key usage period (Task 132), and RFC 9345
	// delegated-credential eligibility (Task 133). The console holds no privileges
	// of its own: it gates these controls on the metadata /api/profiles advertises
	// and submits them through the same issue endpoint the browser calls. Proving
	// both ends — the advertised flags and the stamped extensions — proves the
	// console surface maps to a real, authorized issuance path. ---
	t.Run("IssuanceControls", func(t *testing.T) {
		// The profile metadata that drives the console's show/hide + policy hint.
		status, body := env.req(t, "GET", "/api/profiles", nil)
		if status != http.StatusOK {
			t.Fatalf("profiles = %d: %s", status, body)
		}
		var profs []struct {
			Name            string `json:"name"`
			DelegationUsage bool   `json:"delegation_usage"`
			QCStatements    *struct {
				Type              string `json:"type"`
				AllowPSD2Override bool   `json:"allow_psd2_override"`
			} `json:"qcstatements"`
			PrivateKeyUsagePeriod *struct {
				AllowOverride bool `json:"allow_override"`
			} `json:"private_key_usage_period"`
		}
		if err := json.Unmarshal(body, &profs); err != nil {
			t.Fatalf("decode profiles: %v", err)
		}
		byName := map[string]int{}
		for i, p := range profs {
			byName[p.Name] = i
		}
		if i, ok := byName["qualified-web"]; !ok || profs[i].QCStatements == nil || !profs[i].QCStatements.AllowPSD2Override {
			t.Errorf("qualified-web must advertise qcstatements.allow_psd2_override (drives the PSD2 control)")
		}
		if i, ok := byName["qualified-esign"]; !ok || profs[i].PrivateKeyUsagePeriod == nil || !profs[i].PrivateKeyUsagePeriod.AllowOverride {
			t.Errorf("qualified-esign must advertise private_key_usage_period.allow_override (drives the PKUP control)")
		}
		if i, ok := byName["server-delegation"]; !ok || !profs[i].DelegationUsage {
			t.Errorf("server-delegation must advertise delegation_usage:true (drives the eligibility indicator)")
		}

		leafOf := func(t *testing.T, pemStr string) *x509.Certificate {
			t.Helper()
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				t.Fatalf("issued certificate is not PEM")
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse issued certificate: %v", err)
			}
			return c
		}
		hasExt := func(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
			for _, e := range c.Extensions {
				if e.Id.Equal(oid) {
					return true
				}
			}
			return false
		}

		// (1) eIDAS QWAC with a per-request PSD2 QcStatement — the exact body the
		// console's issueFormBody() builds when PSD2 roles are checked (Task 128).
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]any{
			"csr":     string(makeCSR(t, "psd2.e2e.example.com", []string{"psd2.e2e.example.com"})),
			"profile": "qualified-web",
			"psd2": map[string]any{
				"roles":    []string{"PSP_AI"},
				"nca_name": "Financial Conduct Authority",
				"nca_id":   "GB-FCA",
			},
		})
		if status != http.StatusCreated {
			t.Fatalf("issue qualified-web + PSD2 = %d: %s", status, body)
		}
		var qwac models.IssueCertResponse
		if err := json.Unmarshal(body, &qwac); err != nil {
			t.Fatalf("decode qualified-web response: %v", err)
		}
		if !hasExt(leafOf(t, qwac.Certificate), pki.OIDQCStatements) {
			t.Errorf("qualified-web leaf is missing the id-pe-qcStatements extension")
		}

		// (2) A private-key usage period override — the console's PKUP control
		// (Task 132), a duration from notBefore honored under an override profile.
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]any{
			"csr":                      string(makeCSR(t, "pkup.e2e.example.com", []string{"pkup.e2e.example.com"})),
			"profile":                  "qualified-esign",
			"validity_days":            90,
			"private_key_usage_period": map[string]any{"duration": "30d"},
		})
		if status != http.StatusCreated {
			t.Fatalf("issue qualified-esign + PKUP = %d: %s", status, body)
		}
		var pkupRes models.IssueCertResponse
		if err := json.Unmarshal(body, &pkupRes); err != nil {
			t.Fatalf("decode qualified-esign response: %v", err)
		}
		if !hasExt(leafOf(t, pkupRes.Certificate), pki.OIDPrivateKeyUsagePeriod) {
			t.Errorf("qualified-esign leaf is missing the id-ce-privateKeyUsagePeriod extension")
		}

		// (3) A delegated-credential-eligible leaf — the eligibility the console
		// surfaces from the server-delegation profile (Task 133).
		status, body = env.req(t, "POST", "/api/ca/"+env.interID+"/issue", map[string]any{
			"csr":     string(makeCSR(t, "dc.e2e.example.com", []string{"dc.e2e.example.com"})),
			"profile": "server-delegation",
		})
		if status != http.StatusCreated {
			t.Fatalf("issue server-delegation = %d: %s", status, body)
		}
		var dcRes models.IssueCertResponse
		if err := json.Unmarshal(body, &dcRes); err != nil {
			t.Fatalf("decode server-delegation response: %v", err)
		}
		if !pki.HasDelegationUsage(leafOf(t, dcRes.Certificate)) {
			t.Errorf("server-delegation leaf is not delegated-credential eligible (missing DelegationUsage)")
		}
	})
}
