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
	"encoding/base64"
	"encoding/json"
	"io"
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
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

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

	// --- 1. Embedded console assets are served from the binary (go:embed). ---
	t.Run("EmbeddedAssets", func(t *testing.T) {
		status, ctype, body := env.getPublic(t, "/console/")
		if status != http.StatusOK {
			t.Fatalf("GET /console/ = %d, want 200", status)
		}
		for _, want := range []string{"Operator Console", "app.js", "style.css"} {
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
		if !bytes.Contains(body, []byte("bootAuth")) {
			t.Error("app.js does not contain expected console code")
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
		var certs []models.IssuedCertificate
		if err := json.Unmarshal(body, &certs); err != nil {
			t.Fatalf("decode certificates: %v", err)
		}
		found := false
		for _, c := range certs {
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
	})
}
