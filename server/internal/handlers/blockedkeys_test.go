//go:build sqlite

package handlers

// Tests for the compromised-key blocklist REST surface (Task 198). The headline
// invariant is fingerprint agreement: a PEM public key, its canonical
// "SHA256:<base64>" fingerprint, and its hex digest must all resolve to ONE row —
// otherwise the console could "block" a key the CLI and the pre-issuance gate
// never see.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// freshPublicKey returns a new ECDSA P-256 public key as PEM alongside the
// SubjectPublicKeyInfo fingerprint the pre-issuance gate would compute for it.
func freshPublicKey(t *testing.T) (pemText, fingerprint string) {
	t.Helper()
	key := freshECDSAKey(t)
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	fp, err := keycheck.Fingerprint(key.Public())
	if err != nil {
		t.Fatalf("keycheck.Fingerprint: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), fp
}

func freshECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// blockKey drives POST /api/blocked-keys.
func blockKey(api *API, user *models.UserInfo, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.BlockKey(rec, reqAs(http.MethodPost, "/api/blocked-keys", user, "", body))
	return rec
}

// unblockKey drives DELETE /api/blocked-keys/{fingerprint} with the path value
// the router would set.
func unblockKey(api *API, user *models.UserInfo, fingerprint string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := reqAs(http.MethodDelete, "/api/blocked-keys/"+url.PathEscape(fingerprint), user, "", "")
	r.SetPathValue("fingerprint", fingerprint)
	api.UnblockKey(rec, r)
	return rec
}

// listBlockedKeys drives GET /api/blocked-keys and decodes the payload.
func listBlockedKeys(t *testing.T, api *API, user *models.UserInfo) (*httptest.ResponseRecorder, BlockedKeyListResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	api.ListBlockedKeys(rec, reqAs(http.MethodGet, "/api/blocked-keys", user, "", ""))
	var resp BlockedKeyListResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode list: %v; body=%s", err, rec.Body.String())
		}
	}
	return rec, resp
}

// TestBlockedKeysAuthz pins the gate on each verb: reading is open to any
// assigned role, mutating requires the platform-wide ca:configure capability, and
// an unauthenticated or roleless caller reaches nothing. Each case works on its
// own fingerprint so the rows cannot leak between subtests.
func TestBlockedKeysAuthz(t *testing.T) {
	api, _ := tenantAPI(t)

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		// expected status per verb: list, add, remove.
		list, add, remove int
	}{
		{"unauthenticated", nil, 403, 403, 403},
		{"roleless", &models.UserInfo{Subject: "nobody"}, 403, 403, 403},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, 200, 403, 403},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, 200, 403, 403},
		// A tenant admin holds no PLATFORM capability, and the blocklist is
		// deployment-global: it may read it but not change it.
		{"tenant admin", tenantUser("tadmin", "a", "admin"), 200, 403, 403},
		{"root", rootUser(), 200, 201, 200},
		{"platform admin", platformAdmin(), 200, 201, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fp := freshPublicKey(t)
			if rec, _ := listBlockedKeys(t, api, tc.user); rec.Code != tc.list {
				t.Errorf("list: status = %d, want %d; body=%s", rec.Code, tc.list, rec.Body.String())
			}
			if rec := blockKey(api, tc.user, `{"fingerprint":"`+fp+`","reason":"authz"}`); rec.Code != tc.add {
				t.Errorf("add: status = %d, want %d; body=%s", rec.Code, tc.add, rec.Body.String())
			}
			if rec := unblockKey(api, tc.user, fp); rec.Code != tc.remove {
				t.Errorf("remove: status = %d, want %d; body=%s", rec.Code, tc.remove, rec.Body.String())
			}
		})
	}
}

// TestBlockKeyBadInput rejects every malformed request with 400 and stores
// nothing.
func TestBlockedKeyAddBadInput(t *testing.T) {
	api, db := tenantAPI(t)
	keyPEM, fp := freshPublicKey(t)

	for _, tc := range []struct {
		name, body string
	}{
		{"not json", `{`},
		{"no input", `{"reason":"x"}`},
		{"empty inputs", `{"fingerprint":"","public_key":"  "}`},
		{"two inputs", `{"fingerprint":"` + fp + `","public_key":` + quoteJSON(keyPEM) + `}`},
		{"fingerprint not a digest", `{"fingerprint":"SHA256:zzz"}`},
		{"fingerprint wrong length", `{"fingerprint":"` + hex.EncodeToString([]byte("short")) + `"}`},
		{"public key garbage", `{"public_key":"-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n"}`},
		{"certificate garbage", `{"certificate":"not a certificate"}`},
		{"csr garbage", `{"csr":"-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----\n"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := blockKey(api, rootUser(), tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if n, err := db.CountBlockedKeys(); err != nil || n != 0 {
		t.Fatalf("CountBlockedKeys after rejected requests = %d (err=%v), want 0", n, err)
	}
}

// TestBlockKeyFingerprintAgreement is the point of the endpoint: a PEM public key
// and every textual spelling of its fingerprint resolve to the single row the CLI
// would have written.
func TestBlockedKeyFingerprintAgreement(t *testing.T) {
	api, db := tenantAPI(t)
	keyPEM, want := freshPublicKey(t)
	hexDigest := hexOfFingerprint(t, want)

	// 1. The PEM public key creates the entry.
	rec := blockKey(api, rootUser(), `{"public_key":`+quoteJSON(keyPEM)+`,"reason":"key compromise, INC-1234"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add by public_key: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created BlockKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Fingerprint != want {
		t.Fatalf("stored fingerprint = %q, want %q (keycheck.Fingerprint of the key)", created.Fingerprint, want)
	}
	if !created.NewlyAdded {
		t.Errorf("newly_added = false on the first add")
	}
	if created.Reason != "key compromise, INC-1234" || created.Source != blockedKeySourceAPI {
		t.Errorf("entry = %+v, want the reason echoed and source %q", created.BlockedKey, blockedKeySourceAPI)
	}
	if created.AddedBy != "root" {
		t.Errorf("added_by = %q, want the authenticated subject", created.AddedBy)
	}

	// 2. Every other spelling of the same key is recognized as already blocked.
	for _, tc := range []struct {
		name, body string
	}{
		{"canonical fingerprint", `{"fingerprint":"` + want + `"}`},
		{"hex digest", `{"fingerprint":"` + hexDigest + `"}`},
		{"colon-grouped hex", `{"fingerprint":"` + strings.ToUpper(colonizeHex(hexDigest)) + `"}`},
		{"padded base64", `{"fingerprint":"` + want + `="}`},
		{"the same PEM again", `{"public_key":` + quoteJSON(keyPEM) + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := blockKey(api, rootUser(), tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (already blocked); body=%s", rec.Code, rec.Body.String())
			}
			var again BlockKeyResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &again); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if again.Fingerprint != want {
				t.Errorf("fingerprint = %q, want %q", again.Fingerprint, want)
			}
			if again.NewlyAdded {
				t.Errorf("newly_added = true, want false for an already-blocked key")
			}
			// The original justification survives a re-submit.
			if again.Reason != "key compromise, INC-1234" {
				t.Errorf("reason = %q, want the ORIGINAL justification", again.Reason)
			}
		})
	}

	// Exactly one row, and the pre-issuance gate's hot-path lookup sees it.
	if n, err := db.CountBlockedKeys(); err != nil || n != 1 {
		t.Fatalf("CountBlockedKeys = %d (err=%v), want 1", n, err)
	}
	if blocked, err := db.IsKeyBlocked(want); err != nil || !blocked {
		t.Fatalf("IsKeyBlocked(%q) = %v (err=%v), want true", want, blocked, err)
	}
}

// TestBlockKeyFromCertificateAndCSR blocks a key through the certificate and CSR
// inputs, proving both land on the same fingerprint as the bare public key.
func TestBlockedKeyFromCertificateAndCSR(t *testing.T) {
	api, db := tenantAPI(t)
	key := freshECDSAKey(t)
	want, err := keycheck.Fingerprint(key.Public())
	if err != nil {
		t.Fatalf("keycheck.Fingerprint: %v", err)
	}

	for _, tc := range []struct {
		name, body string
		wantStatus int
		wantNew    bool
	}{
		{"certificate", `{"certificate":` + quoteJSON(selfSignedPEM(t, key)) + `,"reason":"leaked leaf"}`, http.StatusCreated, true},
		{"csr", `{"csr":` + quoteJSON(csrPEM(t, key)) + `}`, http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := blockKey(api, rootUser(), tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var resp BlockKeyResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Fingerprint != want {
				t.Fatalf("fingerprint = %q, want the key's SPKI fingerprint %q", resp.Fingerprint, want)
			}
			if resp.NewlyAdded != tc.wantNew {
				t.Errorf("newly_added = %v, want %v", resp.NewlyAdded, tc.wantNew)
			}
		})
	}
	if n, err := db.CountBlockedKeys(); err != nil || n != 1 {
		t.Fatalf("CountBlockedKeys = %d (err=%v), want 1 — the certificate and the CSR are the same key", n, err)
	}
}

// TestBlockedKeysListRemoveAndAudit covers the list payload, removal (including
// the tolerant repeat), and the audit trail both verbs leave under the same
// action strings the CLI records.
func TestBlockedKeysListRemoveAndAudit(t *testing.T) {
	api, db := tenantAPI(t)

	// An empty blocklist is an empty list, never null.
	rec, resp := listBlockedKeys(t, api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200", rec.Code)
	}
	if resp.BlockedKeys == nil || len(resp.BlockedKeys) != 0 || resp.Total != 0 {
		t.Fatalf("empty list = %+v, want [] and total 0", resp)
	}

	var fps []string
	for i := 0; i < 3; i++ {
		_, fp := freshPublicKey(t)
		fps = append(fps, fp)
		body := fmt.Sprintf(`{"fingerprint":%q,"reason":"incident %d","source":"incident-response"}`, fp, i)
		if rec := blockKey(api, rootUser(), body); rec.Code != http.StatusCreated {
			t.Fatalf("add %d: status = %d; body=%s", i, rec.Code, rec.Body.String())
		}
	}

	rec, resp = listBlockedKeys(t, api, &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("list as auditor: status = %d, want 200", rec.Code)
	}
	if resp.Total != 3 || len(resp.BlockedKeys) != 3 {
		t.Fatalf("list = %d entries (total %d), want 3", len(resp.BlockedKeys), resp.Total)
	}
	for _, k := range resp.BlockedKeys {
		if k.AddedAt.IsZero() || k.AddedBy != "root" || k.Source != "incident-response" || !strings.HasPrefix(k.Reason, "incident ") {
			t.Errorf("entry %+v is missing a field `blocked-keys list` prints", k)
		}
	}

	// A fingerprint that is not a digest at all never reaches the store.
	if rec := unblockKey(api, rootUser(), fps[0]+"?"); rec.Code != http.StatusBadRequest {
		t.Errorf("remove with a malformed fingerprint: status = %d, want 400", rec.Code)
	}
	// Removal is audited and tolerant of a repeat.
	rec = unblockKey(api, rootUser(), fps[0])
	if rec.Code != http.StatusOK {
		t.Fatalf("remove: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var removed UnblockKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &removed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if removed.Status != "unblocked" || !removed.Removed || removed.Fingerprint != fps[0] {
		t.Fatalf("remove response = %+v, want unblocked/true/%s", removed, fps[0])
	}
	rec = unblockKey(api, rootUser(), fps[0])
	if err := json.Unmarshal(rec.Body.Bytes(), &removed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Code != http.StatusOK || removed.Status != "not_blocked" || removed.Removed {
		t.Fatalf("repeat remove = %d %+v, want 200 not_blocked/false", rec.Code, removed)
	}
	if blocked, err := db.IsKeyBlocked(fps[0]); err != nil || blocked {
		t.Fatalf("IsKeyBlocked after removal = %v (err=%v), want false", blocked, err)
	}

	// The audit trail uses the CLI's action strings, with via=api provenance.
	assertBlockedKeyEvent(t, db, audit.ActionKeyBlock, fps[1], "source=incident-response")
	assertBlockedKeyEvent(t, db, audit.ActionKeyUnblock, fps[0], "via=api")
}

// TestUnblockKeyThroughRouter proves the registered route pattern survives a
// canonical fingerprint: standard-alphabet base64 can contain '/', so the escaped
// path value must arrive at the handler unescaped and intact.
func TestBlockedKeyRemoveThroughRouter(t *testing.T) {
	api, db := tenantAPI(t)
	fp := fingerprintWithSlash(t)
	if rec := blockKey(api, rootUser(), `{"fingerprint":"`+fp+`"}`); rec.Code != http.StatusCreated {
		t.Fatalf("add: status = %d; body=%s", rec.Code, rec.Body.String())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/blocked-keys/{fingerprint}", func(w http.ResponseWriter, r *http.Request) {
		// Re-wrap with an authenticated context (the real router does this in the
		// auth middleware), carrying the router's path value through.
		inner := reqAs(http.MethodDelete, r.URL.String(), rootUser(), "", "")
		inner.SetPathValue("fingerprint", r.PathValue("fingerprint"))
		api.UnblockKey(w, inner)
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/blocked-keys/"+url.PathEscape(fp), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("routed remove of %q: status = %d, want 200; body=%s", fp, rec.Code, rec.Body.String())
	}
	if blocked, err := db.IsKeyBlocked(fp); err != nil || blocked {
		t.Fatalf("IsKeyBlocked after routed removal = %v (err=%v), want false", blocked, err)
	}
}

// --- helpers ---

// quoteJSON renders s as a JSON string literal (PEM carries newlines).
func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// selfSignedPEM wraps key's public half in a throwaway self-signed certificate.
func selfSignedPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "blocked-key.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// csrPEM builds a PKCS#10 request for key.
func csrPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "blocked-key.example.com"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// hexOfFingerprint converts "SHA256:<base64>" back to its hex digest.
func hexOfFingerprint(t *testing.T, fp string) string {
	t.Helper()
	sum, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fp, "SHA256:"))
	if err != nil {
		t.Fatalf("decoding %q: %v", fp, err)
	}
	return hex.EncodeToString(sum)
}

// colonizeHex groups a hex digest the way openssl prints it.
func colonizeHex(hexDigest string) string {
	var parts []string
	for i := 0; i+2 <= len(hexDigest); i += 2 {
		parts = append(parts, hexDigest[i:i+2])
	}
	return strings.Join(parts, ":")
}

// fingerprintWithSlash returns a valid canonical fingerprint whose base64 body
// contains a '/' — the character that makes a fingerprint hostile to path
// routing.
func fingerprintWithSlash(t *testing.T) string {
	t.Helper()
	for i := 0; i < 10000; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("slash-probe-%d", i)))
		if b64 := base64.RawStdEncoding.EncodeToString(sum[:]); strings.Contains(b64, "/") {
			return "SHA256:" + b64
		}
	}
	t.Fatal("no digest with a '/' in its base64 found")
	return ""
}

// assertBlockedKeyEvent finds the audit event for one fingerprint and checks its
// provenance detail and actor attribution.
func assertBlockedKeyEvent(t *testing.T, db *database.DB, action, fingerprint, wantDetail string) {
	t.Helper()
	events, _, err := db.ListEvents(action, "", "", 100, 0)
	if err != nil {
		t.Fatalf("ListEvents(%s): %v", action, err)
	}
	for _, e := range events {
		if e.Target != fingerprint {
			continue
		}
		if e.Result != audit.ResultSuccess {
			t.Errorf("%s event result = %q, want success", action, e.Result)
		}
		if !strings.Contains(e.Detail, wantDetail) {
			t.Errorf("%s detail = %q, want it to contain %q", action, e.Detail, wantDetail)
		}
		if e.Actor != "root" {
			t.Errorf("%s actor = %q, want the requesting operator", action, e.Actor)
		}
		return
	}
	t.Fatalf("no %s audit event for %s (events=%d)", action, fingerprint, len(events))
}
