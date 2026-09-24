//go:build sqlite

package handlers

// Tests for the Evidence-Record endpoints (Task 198): GET /api/ers,
// POST /api/ers/generate, POST /api/ers/renew, GET /api/ers/export.
//
// The property these carry beyond ordinary handler tests is that the artifact they
// produce must remain verifiable: TestErsGenerateRenewExportRoundTrip mints a
// record through the API, hands it to the pre-existing POST /api/ers/verify, and
// re-verifies after each renewal — so a change to either endpoint that silently
// produces an unverifiable record fails here rather than in an audit years later.

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/ers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// --- harness ---

// tsaOpsAPI builds an API whose operations bundle carries a WORKING internal
// RFC 3161 authority: an RSA key in a software keystore plus a self-signed
// timeStamping certificate on disk, and a ProviderFor that reopens that same
// keystore for the "tsa" role (the software backend is file-backed and its Close
// is a no-op, so reopening is exactly what a second session looks like).
//
// It is shared with the audit-anchor tests: both endpoints obtain tokens from this
// authority, and both must keep working when only the TSA role — never the CA one
// — can be opened.
func tsaOpsAPI(t *testing.T) (*API, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	dir := t.TempDir()
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: dir})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	certFile := writeTSACredential(t, prov, "ops-tsa")
	api.SetOps(&OpsDeps{
		Config: &config.Config{TSA: config.TSAConfig{KeyLabel: "ops-tsa", CertificateFile: certFile}},
		ProviderFor: func(string) (keyprovider.Provider, error) {
			p, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: dir})
			if err != nil {
				return nil, err
			}
			return keyprovider.Instrument(p), nil
		},
	})
	return api, db
}

// writeTSACredential generates an RSA timestamping key in the provider and writes
// a self-signed certificate for it (id-kp-timeStamping as its sole EKU, which is
// what tsa.New enforces), returning the PEM path for tsa.certificate_file.
func writeTSACredential(t *testing.T, prov keyprovider.Provider, label string) string {
	t.Helper()
	ctx := context.Background()
	info, err := prov.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyprovider.KeyTypeRSA2048})
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", label, err)
	}
	signer, err := prov.Signer(ctx, keyprovider.KeyRef{Label: label})
	if err != nil {
		t.Fatalf("Signer(%s): %v", label, err)
	}
	defer signer.Close()

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Ops Test TSA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, info.PublicKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "tsa.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing TSA certificate: %v", err)
	}
	return path
}

// appendErsTestEvents appends n events to the tamper-evident log and returns the
// inclusive sequence range they occupy, which is what an audit-scope Evidence
// Record preserves.
func appendErsTestEvents(t *testing.T, db *database.DB, n int) (first, last int64) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: uuid.New().String(), Actor: "tester", ActorRoles: "system",
			Action: "test.event", Result: audit.ResultSuccess, Detail: fmt.Sprintf("event %d", i),
		}); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}
	head, err := db.MaxEventSeq()
	if err != nil {
		t.Fatalf("MaxEventSeq: %v", err)
	}
	return head - int64(n) + 1, head
}

// getAsUser drives a GET handler as the given principal.
func getAsUser(h http.HandlerFunc, user *models.UserInfo, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, reqAs(http.MethodGet, target, user, "", ""))
	return rec
}

// platAdminUser is a platform-wide admin: the principal that holds ca:manage.
func platAdminUser() *models.UserInfo {
	return &models.UserInfo{Subject: "plat-admin", Roles: []string{"admin"}}
}

// --- GET /api/ers ---

// TestErsListAuthz: the listing is read-gated exactly like POST /api/ers/verify —
// any assigned role may see which records exist; a roleless principal may not.
func TestErsListAuthz(t *testing.T) {
	api, _ := tsaOpsAPI(t)
	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant auditor", tenantUser("bob", models.DefaultTenantID, "auditor"), http.StatusOK},
		{"platform admin", platAdminUser(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := getAsUser(api.ListEvidenceRecords, tc.user, "/api/ers")
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestErsListEmptyAndBadParams: an empty store lists as an empty array (never
// null, which a console would have to special-case), and a malformed page
// parameter is refused rather than silently serving a different page.
func TestErsListEmptyAndBadParams(t *testing.T) {
	api, _ := tsaOpsAPI(t)

	rec := getAsUser(api.ListEvidenceRecords, rootUser(), "/api/ers")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp EvidenceRecordListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Items == nil || len(resp.Items) != 0 || resp.Total != 0 {
		t.Fatalf("empty store: items=%v total=%d, want [] / 0", resp.Items, resp.Total)
	}
	if resp.Limit != ersDefaultPageSize {
		t.Errorf("limit = %d, want the default page size %d", resp.Limit, ersDefaultPageSize)
	}

	// limit=0 means "as many as the hard cap allows", and an over-large ask is
	// clamped to it rather than refused.
	for _, q := range []string{"?limit=0", "?limit=99999"} {
		rec := getAsUser(api.ListEvidenceRecords, rootUser(), "/api/ers"+q)
		var capped EvidenceRecordListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &capped); err != nil {
			t.Fatalf("%s: decode: %v", q, err)
		}
		if capped.Limit != ersMaxPageSize {
			t.Errorf("%s: limit = %d, want the hard cap %d", q, capped.Limit, ersMaxPageSize)
		}
	}

	for _, q := range []string{"?limit=abc", "?limit=-1", "?offset=-2"} {
		if rec := getAsUser(api.ListEvidenceRecords, rootUser(), "/api/ers"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400: %s", q, rec.Code, rec.Body.String())
		}
	}
}

// --- POST /api/ers/generate ---

// TestErsGenerateAuthz: minting an Evidence Record signs with the deployment's
// timestamp authority over the shared audit chain, so the gate is PLATFORM
// ca:manage. A tenant admin — who may create CAs in its own tenant — must not be
// able to mint preservation evidence for the whole deployment.
func TestErsGenerateAuthz(t *testing.T) {
	api, db := tsaOpsAPI(t)
	first, last := appendErsTestEvents(t, db, 2)
	body := fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, last)

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"platform auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, http.StatusForbidden},
		{"platform issuer", &models.UserInfo{Subject: "iss", Roles: []string{"issuer"}}, http.StatusForbidden},
		{"tenant admin", tenantUser("alice", models.DefaultTenantID, "admin"), http.StatusForbidden},
		{"platform admin", platAdminUser(), http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.GenerateEvidenceRecord, tc.user, "/api/ers/generate", body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestErsGenerateBadInput: every request-shape error is answered 400 BEFORE a key
// provider is opened, so a malformed call never costs an HSM session.
func TestErsGenerateBadInput(t *testing.T) {
	api, db := tsaOpsAPI(t)
	_, last := appendErsTestEvents(t, db, 2)

	for _, tc := range []struct{ name, body string }{
		{"malformed JSON", `{`},
		{"no scope", `{}`},
		{"both scopes", fmt.Sprintf(`{"audit_from":1,"audit_to":%d,"objects":["aGk="]}`, last)},
		{"half a range", `{"audit_from":1}`},
		{"inverted range", `{"audit_from":2,"audit_to":1}`},
		{"range past the head", fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, last+10, last+20)},
		{"unsupported hash", `{"objects":["aGk="],"hash":"md5"}`},
		{"object not base64", `{"objects":["not base64!"]}`},
		{"object_ids length mismatch", `{"objects":["aGk="],"object_ids":["a","b"]}`},
		{"empty object id", `{"objects":["aGk="],"object_ids":[""]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestErsGenerateBoundsAuditRange is the range-bound invariant: audit_to is
// clamped DOWN to the chain head and the resulting span is capped.
//
// ers.GenerateAuditRange turns (to-from+1) straight into a SQL LIMIT and then
// hashes every returned event into a Merkle tree in memory, and the only check
// this endpoint made was audit_from <= head — so
// {"audit_from":1,"audit_to":9223372036854775807} loaded the whole event log from
// one request field. The span cap answers that as a 400; an audit_to merely past
// the head is still honored, clamped to what exists, because "everything up to
// now" is a legitimate thing to ask for.
func TestErsGenerateBoundsAuditRange(t *testing.T) {
	api, db := tsaOpsAPI(t)
	first, last := appendErsTestEvents(t, db, 3)

	// The unbounded span is refused, and the refusal says what the limit is.
	rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		`{"audit_from":1,"audit_to":9223372036854775807}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("int64-max range: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), fmt.Sprint(maxERSAuditSpan)) {
		t.Errorf("the 400 does not name the span limit: %s", rec.Body.String())
	}
	// Anything wider than the cap is refused whatever its start point.
	rec = postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, first+maxERSAuditSpan))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-wide range: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	// A modest audit_to past the head is clamped rather than refused, and the record
	// it produces covers only the events that exist.
	rec = postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, last+50))
	if rec.Code != http.StatusCreated {
		t.Fatalf("clamped range: status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp EvidenceRecordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FirstSeq != first || resp.LastSeq != last {
		t.Errorf("record covers %d-%d, want it clamped to the existing %d-%d",
			resp.FirstSeq, resp.LastSeq, first, last)
	}
}

// TestErsOpsAbsent503: a server started without the operations bundle cannot know
// which timestamp source to use, so the mutating endpoints report 503 with a
// reason instead of half-working. The reads are unaffected — they never needed it.
func TestErsOpsAbsent503(t *testing.T) {
	api, db := tenantAPI(t) // no SetOps
	first, last := appendErsTestEvents(t, db, 2)

	rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, last))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("generate: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	rec = postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew", `{"id":"whatever"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("renew: status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(api.ListEvidenceRecords, rootUser(), "/api/ers"); rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200 without ops deps: %s", rec.Code, rec.Body.String())
	}
}

// TestErsNoTimestampSource503: ops deps present but neither ers.tsa_url nor the
// internal tsa: block configured — the one case where the CLI refuses too, and the
// error must name both ways out.
func TestErsNoTimestampSource503(t *testing.T) {
	api, db := tenantAPI(t)
	api.SetOps(&OpsDeps{Config: &config.Config{}})
	first, last := appendErsTestEvents(t, db, 2)

	rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, last))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "timestamp source") {
		t.Errorf("error should name the missing timestamp source, got %s", body)
	}
}

// --- the round trip ---

// TestErsGenerateRenewExportRoundTrip is the headline proof: a record minted
// through the API verifies through the pre-existing verify endpoint, appears in
// the listing, exports byte-identically in both formats, and survives both a
// time-stamp and a hash-tree renewal still verifying.
func TestErsGenerateRenewExportRoundTrip(t *testing.T) {
	api, db := tsaOpsAPI(t)
	first, last := appendErsTestEvents(t, db, 3)

	rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		fmt.Sprintf(`{"audit_from":%d,"audit_to":%d}`, first, last))
	if rec.Code != http.StatusCreated {
		t.Fatalf("generate: status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var gen EvidenceRecordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode generate: %v", err)
	}
	if gen.Kind != "generated" || gen.ID == "" {
		t.Fatalf("generate response = %+v, want kind=generated with an id", gen)
	}
	if gen.Scope != ers.ScopeAudit || gen.FirstSeq != first || gen.LastSeq != last {
		t.Errorf("scope/range = %s %d-%d, want audit %d-%d", gen.Scope, gen.FirstSeq, gen.LastSeq, first, last)
	}
	if gen.Chains != 1 || gen.DigestAlg != "sha256" {
		t.Errorf("chains/hash = %d/%s, want 1/sha256 (the configured default)", gen.Chains, gen.DigestAlg)
	}

	// It verifies through the endpoint that already existed.
	ersAssertVerifies(t, api, gen.ID)

	// It is listed, with the total count.
	list := getAsUser(api.ListEvidenceRecords, rootUser(), "/api/ers")
	if list.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200: %s", list.Code, list.Body.String())
	}
	var listed EvidenceRecordListResponse
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].ID != gen.ID {
		t.Fatalf("list = %+v, want exactly the generated record", listed)
	}

	// Export: the JSON body's base64 DER and the raw ?format=der stream are the
	// same bytes, and they parse as the record that was minted.
	exp := getAsUser(api.ExportEvidenceRecord, rootUser(), "/api/ers/export?id="+gen.ID)
	if exp.Code != http.StatusOK {
		t.Fatalf("export: status = %d, want 200: %s", exp.Code, exp.Body.String())
	}
	var exported ExportEvidenceRecordResponse
	if err := json.Unmarshal(exp.Body.Bytes(), &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(exported.Record)
	if err != nil {
		t.Fatalf("exported record is not base64: %v", err)
	}
	if len(der) == 0 || len(der) != exported.Size {
		t.Fatalf("exported DER is %d bytes, size field says %d", len(der), exported.Size)
	}
	if exported.Info.Chains != 1 || len(exported.Info.Timestamps) != 1 {
		t.Errorf("info = %+v, want one chain with one timestamp", exported.Info)
	}
	if _, err := ers.Parse(der); err != nil {
		t.Fatalf("exported DER does not parse as an Evidence Record: %v", err)
	}
	raw := getAsUser(api.ExportEvidenceRecord, rootUser(), "/api/ers/export?id="+gen.ID+"&format=der")
	if raw.Code != http.StatusOK {
		t.Fatalf("export der: status = %d, want 200: %s", raw.Code, raw.Body.String())
	}
	if got := raw.Body.Bytes(); string(got) != string(der) {
		t.Errorf("?format=der returned %d bytes, JSON carried %d — they must be identical", len(got), len(der))
	}
	if ct := raw.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}

	// Time-stamp renewal: a fresh token on the same chain.
	rn := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew", `{"id":"`+gen.ID+`"}`)
	if rn.Code != http.StatusOK {
		t.Fatalf("renew: status = %d, want 200: %s", rn.Code, rn.Body.String())
	}
	var renewed EvidenceRecordResponse
	if err := json.Unmarshal(rn.Body.Bytes(), &renewed); err != nil {
		t.Fatalf("decode renew: %v", err)
	}
	if renewed.Kind != "timestamp" || renewed.Chains != 1 || renewed.RenewedAt == nil {
		t.Fatalf("renew response = %+v, want kind=timestamp, 1 chain, renewed_at set", renewed)
	}
	ersAssertVerifies(t, api, gen.ID)

	// Hash-tree renewal: a new chain under a stronger algorithm, objects
	// re-derived from the event log because the record is audit-scope.
	ht := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew",
		`{"id":"`+gen.ID+`","hashtree":true,"hash":"sha512"}`)
	if ht.Code != http.StatusOK {
		t.Fatalf("hashtree renew: status = %d, want 200: %s", ht.Code, ht.Body.String())
	}
	var migrated EvidenceRecordResponse
	if err := json.Unmarshal(ht.Body.Bytes(), &migrated); err != nil {
		t.Fatalf("decode hashtree renew: %v", err)
	}
	if migrated.Kind != "hashtree" || migrated.Chains != 2 || migrated.DigestAlg != "sha512" {
		t.Fatalf("hashtree renew = kind %s chains %d hash %s, want hashtree/2/sha512",
			migrated.Kind, migrated.Chains, migrated.DigestAlg)
	}
	ersAssertVerifies(t, api, gen.ID)

	// Both operations are attributed to the operator in the audit trail, alongside
	// the ers service's own events.
	// An audit-scope record is labelled by the service ("audit events N-M"), so the
	// request's description applies to artifact records only — as in the CLI.
	log := eventDetails(t, db)
	wantLabel := fmt.Sprintf("%s|audit events %d-%d|", audit.ActionERSGenerate, first, last)
	if !strings.Contains(log, wantLabel) || !strings.Contains(log, "kind=hashtree") {
		t.Errorf("audit log lacks operator-attributed ers events:\n%s", log)
	}
	if !strings.Contains(log, "via=api") {
		t.Errorf("operator-attributed events must be distinguishable from the job's:\n%s", log)
	}
}

// TestErsGenerateArtifactObjects: the artifact scope preserves caller-supplied
// bytes under the labels the caller chose, and verifies when those exact bytes are
// handed back (the server never stored them).
func TestErsGenerateArtifactObjects(t *testing.T) {
	api, _ := tsaOpsAPI(t)
	payload := []byte("release-1.2.3.tar.gz contents")
	b64 := base64.StdEncoding.EncodeToString(payload)

	rec := postAs(api.GenerateEvidenceRecord, platAdminUser(), "/api/ers/generate",
		`{"objects":["`+b64+`"],"object_ids":["release-1.2.3.tar.gz"],"hash":"sha384"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var gen EvidenceRecordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gen.Scope != ers.ScopeArtifact || gen.DigestAlg != "sha384" {
		t.Fatalf("scope/hash = %s/%s, want artifact/sha384", gen.Scope, gen.DigestAlg)
	}
	if len(gen.ObjectIDs) != 1 || gen.ObjectIDs[0] != "release-1.2.3.tar.gz" {
		t.Errorf("object_ids = %v, want the caller's label", gen.ObjectIDs)
	}

	// The record verifies only with the original bytes re-supplied.
	vr := postAs(api.VerifyEvidenceRecord, rootUser(), "/api/ers/verify",
		`{"id":"`+gen.ID+`","objects":["`+b64+`"]}`)
	if vr.Code != http.StatusOK {
		t.Fatalf("verify with objects: status = %d, want 200: %s", vr.Code, vr.Body.String())
	}

	// A hash-tree renewal of an artifact record without the objects is refused,
	// because the server cannot reconstruct what it never stored.
	bad := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew",
		`{"id":"`+gen.ID+`","hashtree":true}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("hashtree renew without objects: status = %d, want 400: %s", bad.Code, bad.Body.String())
	}
	ok := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew",
		`{"id":"`+gen.ID+`","hashtree":true,"hash":"sha512","objects":["`+b64+`"]}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("hashtree renew with objects: status = %d, want 200: %s", ok.Code, ok.Body.String())
	}
}

// --- POST /api/ers/renew and GET /api/ers/export, error paths ---

// TestErsRenewAndExportNotFound: an unknown id is 404 (not a 500), and the
// mandatory parameters are enforced.
func TestErsRenewAndExportNotFound(t *testing.T) {
	api, _ := tsaOpsAPI(t)

	if rec := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew", `{"id":"nope"}`); rec.Code != http.StatusNotFound {
		t.Errorf("renew unknown id: status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if rec := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("renew without id: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := postAs(api.RenewEvidenceRecord, platAdminUser(), "/api/ers/renew", `{`); rec.Code != http.StatusBadRequest {
		t.Errorf("renew malformed JSON: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(api.ExportEvidenceRecord, rootUser(), "/api/ers/export?id=nope"); rec.Code != http.StatusNotFound {
		t.Errorf("export unknown id: status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(api.ExportEvidenceRecord, rootUser(), "/api/ers/export"); rec.Code != http.StatusBadRequest {
		t.Errorf("export without id: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(api.ExportEvidenceRecord, rootUser(), "/api/ers/export?id=x&format=pem"); rec.Code != http.StatusBadRequest {
		t.Errorf("export bad format: status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if rec := getAsUser(api.ExportEvidenceRecord, &models.UserInfo{Subject: "nobody"}, "/api/ers/export?id=x"); rec.Code != http.StatusForbidden {
		t.Errorf("export roleless: status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// ersAssertVerifies drives the pre-existing POST /api/ers/verify over a stored
// audit-scope record (whose objects it re-derives from the event log) and requires
// a valid verdict.
func ersAssertVerifies(t *testing.T, api *API, id string) {
	t.Helper()
	rec := postAs(api.VerifyEvidenceRecord, rootUser(), "/api/ers/verify", `{"id":"`+id+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify %s: status = %d, want 200: %s", id, rec.Code, rec.Body.String())
	}
	var res ers.VerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if !res.Valid {
		t.Fatalf("record %s does not verify: %s", id, res.Reason)
	}
}
