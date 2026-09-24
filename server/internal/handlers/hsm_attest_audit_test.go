//go:build sqlite

package handlers

// Tests for GET /api/hsm/attestation-audit (Task 198), the REST form of
// `secsy-ca hsm-attest audit`.
//
// The property under test that no other attestation endpoint has: this one walks
// the whole inventory, so ONE key's failure must be a datum in the response
// rather than a failed request. The test environment has no YubiHSM, which makes
// it the ideal harness for exactly that — every key is unattestable, and the
// endpoint still owes the operator a 200 with a row per key, a rollup that counts
// the failures, and an audit event saying the pass found something. Verifying a
// real attestation is covered by internal/hsmattest; producing one needs hardware
// (see scripts/yubihsm-test.sh).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// attestAuditAPI builds an API whose provider holds two keys — one referenced by
// a CA record, one not — and whose HSM connector points at a closed port, so the
// per-key device round-trip fails fast the way it does on a host with no device.
func attestAuditAPI(t *testing.T) (*API, *database.DB) {
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
	for _, label := range []string{"ca-root", "orphan-key"} {
		if _, err := prov.GenerateKey(context.Background(), keyprovider.KeySpec{
			Label: label, KeyType: keyprovider.KeyTypeECDSAP256,
		}); err != nil {
			t.Fatalf("GenerateKey(%s): %v", label, err)
		}
	}
	if err := db.CreateCA(&models.CA{
		ID: "ca-1", TenantID: models.DefaultTenantID, Label: "ca-root",
		PKCS11URI: "pkcs11:object=ca-root", KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{ConnectorURL: "http://127.0.0.1:1"}, true, ""), db
}

func getAttestationAudit(t *testing.T, api *API, user *models.UserInfo) (*httptest.ResponseRecorder, HSMAttestationAudit) {
	t.Helper()
	rec := httptest.NewRecorder()
	api.GetHSMAttestationAudit(rec, reqAs(http.MethodGet, "/api/hsm/attestation-audit", user, "", ""))
	var out HSMAttestationAudit
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode audit response: %v (body=%s)", err, rec.Body.String())
		}
	}
	return rec, out
}

// TestAttestationAuditReportsPerKeyFailures: with no device reachable, every key
// is an error ROW and the request still succeeds. That is the CLI's audit-pass
// contract — it prints "ERROR: …" on the line and keeps walking — and it is what
// makes the endpoint usable as a posture check rather than an all-or-nothing call.
func TestAttestationAuditReportsPerKeyFailures(t *testing.T) {
	api, db := attestAuditAPI(t)

	rec, got := getAttestationAudit(t, api, rootUser())
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.Total != 2 || len(got.Keys) != 2 {
		t.Fatalf("total = %d with %d rows, want 2 keys enumerated: %+v", got.Total, len(got.Keys), got.Keys)
	}
	if got.Errors != 2 || got.Verified != 0 || got.Failed != 0 {
		t.Errorf("rollup = {verified:%d failed:%d errors:%d}, want every key errored", got.Verified, got.Failed, got.Errors)
	}
	if got.Provider == "" || got.Summary == "" {
		t.Errorf("missing provider/summary in the rollup: %+v", got)
	}
	// Label-sorted, annotated with the CA that owns the key, and each row carries
	// its own error rather than a shared one.
	if got.Keys[0].Label != "ca-root" || got.Keys[1].Label != "orphan-key" {
		t.Errorf("rows are not label-sorted: %q, %q", got.Keys[0].Label, got.Keys[1].Label)
	}
	if got.Keys[0].CALabel != "ca-root" {
		t.Errorf("the CA-bound key is not annotated: %+v", got.Keys[0])
	}
	if got.Keys[1].CALabel != "" {
		t.Errorf("an unreferenced key claims CA %q", got.Keys[1].CALabel)
	}
	for _, k := range got.Keys {
		if k.Error == "" {
			t.Errorf("key %q has no error despite no device: %+v", k.Label, k)
		}
		if k.Verification != nil || k.Attestation != nil {
			t.Errorf("key %q carries an attestation that cannot exist: %+v", k.Label, k)
		}
		if k.KeyType == "" {
			t.Errorf("key %q has no key type, so the error row does not say what failed", k.Label)
		}
	}

	// The pass is one audit event, recorded as an error because it found something.
	events, _, err := db.ListEvents("", "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var found int
	for _, e := range events {
		if e.Action == audit.ActionHSMKeyAttestation && e.TargetName == "attestation-audit" {
			found++
			if e.Result != audit.ResultError {
				t.Errorf("event result = %q, want %q for a pass with findings", e.Result, audit.ResultError)
			}
			if e.Detail != got.Summary {
				t.Errorf("event detail = %q, want the rollup summary %q", e.Detail, got.Summary)
			}
		}
	}
	if found != 1 {
		t.Errorf("%d rollup events recorded, want exactly 1 for one pass", found)
	}
}

// TestAttestationAuditRequiresHSMManage: the pass names every key label on the
// token and reaches the device once per key, so it is gated like the other
// attestation producers — not like a tenant-scoped read.
func TestAttestationAuditRequiresHSMManage(t *testing.T) {
	api, _ := attestAuditAPI(t)

	for _, user := range []*models.UserInfo{
		tenantUser("dev", models.DefaultTenantID, "admin"), // tenant admin holds no PLATFORM hsm:manage
		{Subject: "nobody"},
	} {
		rec, _ := getAttestationAudit(t, api, user)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: audit = %d, want 403; body=%s", user.Subject, rec.Code, rec.Body.String())
		}
	}
}

// noListProvider wraps a Provider so the KeyLister capability is NOT promoted:
// embedding the interface exposes only the interface's own methods, which is
// precisely the shape of a backend that cannot enumerate its keys.
type noListProvider struct{ keyprovider.Provider }

// TestAttestationAuditNeedsEnumerableProvider: a backend that cannot list its
// keys cannot be audited as a whole, and says so with 501 rather than reporting a
// clean device from an empty list — the failure mode that would matter most.
func TestAttestationAuditNeedsEnumerableProvider(t *testing.T) {
	api, _ := attestAuditAPI(t)
	api.keyProvider = noListProvider{api.keyProvider}

	rec, _ := getAttestationAudit(t, api, rootUser())
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("audit on a non-enumerable provider = %d, want 501; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAttestationAuditSummary pins the rollup wording for each shape of outcome,
// since the summary is what the console's headline and the audit event both carry.
func TestAttestationAuditSummary(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   HSMAttestationAudit
		want string
	}{
		{"empty device", HSMAttestationAudit{}, "No keys on the device."},
		{"all pass", HSMAttestationAudit{Total: 3, Verified: 3}, "3 keys attested; all satisfy the attestation policy."},
		{"one key passes", HSMAttestationAudit{Total: 1, Verified: 1}, "1 key attested; all satisfy the attestation policy."},
		{"policy failures", HSMAttestationAudit{Total: 4, Verified: 2, Failed: 2},
			"2 of 4 keys did not satisfy the attestation policy."},
		{"unattestable only", HSMAttestationAudit{Total: 2, Verified: 1, Errors: 1}, "1 key of 2 could not be attested."},
		{"both", HSMAttestationAudit{Total: 5, Verified: 2, Failed: 2, Errors: 1},
			"2 of 5 keys did not satisfy the attestation policy; 1 could not be attested."},
	} {
		if got := auditSummary(tc.in); got != tc.want {
			t.Errorf("%s: summary = %q, want %q", tc.name, got, tc.want)
		}
	}
}
