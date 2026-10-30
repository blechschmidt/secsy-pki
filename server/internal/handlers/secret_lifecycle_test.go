//go:build sqlite

package handlers

// Tests for the stored-secret value lifecycle endpoints (Task 72). Authorization
// and tenant isolation for these routes are covered exhaustively by
// authz_matrix_test.go; what is pinned here is what that matrix cannot see —
// that reading a historical version emits its own audit event, that operator
// labels survive a round trip through the API, and that the configured
// retention depth is actually applied by the handler rather than only by the
// store it calls.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// storedSecretAPI builds an API with a software-backed KEK family so secrets
// can really be sealed and opened, plus the default tenant.
func storedSecretAPI(t *testing.T, historyDepth int) (*API, *database.DB) {
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
	const family = "test-kek"
	if _, err := secret.ProvisionKEK(context.Background(), prov, family, keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, family)
	api.SetSecretHistoryDepth(historyDepth)
	return api, db
}

// storeSecret creates a named secret through the API and returns its id.
func storeSecret(t *testing.T, api *API, body string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	api.StoreSecret(rec, reqAs(http.MethodPost, "/api/secret/store", rootUser(), "", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("StoreSecret = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding store response: %v", err)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("store response carries no id: %s", rec.Body.String())
	}
	return id
}

// putVersion writes a new value version through the API.
func putVersion(t *testing.T, api *API, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.PutStoredSecret(rec, reqAs(http.MethodPut, "/api/secret/store/"+id, rootUser(), id, body))
	return rec
}

// b64 renders a plaintext the way the API expects it.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// eventsFor returns the recorded events for one action.
func eventsFor(t *testing.T, db *database.DB, action string) []audit.Event {
	t.Helper()
	evs, _, err := db.ListEvents(action, "", "", 100, 0)
	if err != nil {
		t.Fatalf("ListEvents(%s): %v", action, err)
	}
	return evs
}

// TestVersionReadIsAudited is the point of a separate version-read event:
// handing out a historical envelope is the only way to obtain a value the
// secret no longer holds, so a successful read, a miss, and a denial must each
// leave a trace. Without this the one privileged read on the lifecycle is the
// only one that happens invisibly.
func TestVersionReadIsAudited(t *testing.T) {
	api, db := storedSecretAPI(t, 0)
	id := storeSecret(t, api, fmt.Sprintf(`{"name":"db-password","plaintext":%q}`, b64("v1")))
	if rec := putVersion(t, api, id, fmt.Sprintf(`{"plaintext":%q}`, b64("v2"))); rec.Code != http.StatusOK {
		t.Fatalf("put = %d; body=%s", rec.Code, rec.Body.String())
	}

	readVersion := func(user *models.UserInfo, version string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := reqAs(http.MethodGet, "/api/secret/store/"+id+"/versions/"+version, user, id, "")
		r.SetPathValue("version", version)
		api.GetStoredSecretVersion(rec, r)
		return rec
	}

	// A successful historical read returns the envelope and is audited.
	rec := readVersion(rootUser(), "1")
	if rec.Code != http.StatusOK {
		t.Fatalf("reading version 1 = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["envelope"] == nil {
		t.Error("the point read must carry the version's envelope")
	}
	if cur, _ := got["current"].(bool); cur {
		t.Error("version 1 is not current after a put")
	}

	// A version that does not exist is audited too — probing for a pruned
	// value is worth seeing in the log.
	if rec := readVersion(rootUser(), "99"); rec.Code != http.StatusNotFound {
		t.Errorf("reading an absent version = %d, want 404", rec.Code)
	}

	// A principal without secret:decrypt is refused, and the denial recorded.
	if rec := readVersion(tenantUser("outsider", models.DefaultTenantID, "auditor"), "1"); rec.Code != http.StatusForbidden {
		t.Errorf("unauthorized version read = %d, want 403", rec.Code)
	}

	evs := eventsFor(t, db, audit.ActionSecretVersionRead)
	if len(evs) != 3 {
		t.Fatalf("recorded %d version-read events, want one per attempt: %+v", len(evs), evs)
	}
	results := map[string]bool{}
	for _, e := range evs {
		results[e.Result] = true
		if e.Action != audit.ActionSecretVersionRead {
			t.Errorf("unexpected action %q", e.Action)
		}
	}
	for _, want := range []string{audit.ResultSuccess, audit.ResultError, audit.ResultDenied} {
		if !results[want] {
			t.Errorf("no version-read event with result %q: %+v", want, evs)
		}
	}
	// The success detail names the version read, not just the secret.
	var success audit.Event
	for _, e := range evs {
		if e.Result == audit.ResultSuccess {
			success = e
		}
	}
	// Target is the KEK family; the secret's own name is the target NAME.
	if success.TargetName != "db-password" {
		t.Errorf("event target name = %q, want the secret name", success.TargetName)
	}
	if success.Target != "test-kek" {
		t.Errorf("event target = %q, want the KEK family", success.Target)
	}
	for _, want := range []string{"version=1", "current_version=2"} {
		if !strings.Contains(success.Detail, want) {
			t.Errorf("success detail %q does not mention %s", success.Detail, want)
		}
	}
}

// TestStoredSecretLabelsRoundTripThroughAPI covers operator metadata on the
// REST surface, including the tri-state put: omitting labels keeps them,
// sending them replaces the set, and sending an empty object clears it.
func TestStoredSecretLabelsRoundTripThroughAPI(t *testing.T) {
	api, _ := storedSecretAPI(t, 0)
	id := storeSecret(t, api, fmt.Sprintf(
		`{"name":"db-password","plaintext":%q,"labels":{"owner":"payments","env":"prod"}}`, b64("v1")))

	labelsOf := func(rec *httptest.ResponseRecorder) map[string]string {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("response = %d; body=%s", rec.Code, rec.Body.String())
		}
		var out struct {
			Labels map[string]string `json:"labels"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Labels
	}

	// A put that does not mention labels keeps them.
	got := labelsOf(putVersion(t, api, id, fmt.Sprintf(`{"plaintext":%q}`, b64("v2"))))
	if got["owner"] != "payments" || got["env"] != "prod" {
		t.Errorf("labels after a silent put = %+v, want both preserved", got)
	}

	// Sending labels replaces the whole set rather than merging.
	got = labelsOf(putVersion(t, api, id, fmt.Sprintf(
		`{"plaintext":%q,"labels":{"owner":"platform"}}`, b64("v3"))))
	if len(got) != 1 || got["owner"] != "platform" {
		t.Errorf("labels after a replace = %+v, want only owner=platform", got)
	}

	// An empty object clears them.
	got = labelsOf(putVersion(t, api, id, fmt.Sprintf(`{"plaintext":%q,"labels":{}}`, b64("v4"))))
	if len(got) != 0 {
		t.Errorf("labels after a clear = %+v, want none", got)
	}

	// Labels also appear in the lifecycle report, which is what routes an alert.
	rec := httptest.NewRecorder()
	api.SecretLifecycleReport(rec, reqAs(http.MethodGet, "/api/secret/lifecycle", rootUser(), "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("lifecycle report = %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestPutAppliesConfiguredHistoryDepth proves the handler passes the configured
// retention bound down to the store and says so in the audit record. Pruning
// destroys ciphertext irreversibly, so an operator must be able to see from the
// log that it happened and at what depth.
func TestPutAppliesConfiguredHistoryDepth(t *testing.T) {
	api, db := storedSecretAPI(t, 2)
	id := storeSecret(t, api, fmt.Sprintf(`{"name":"rotating","plaintext":%q}`, b64("v1")))
	for v := 2; v <= 4; v++ {
		if rec := putVersion(t, api, id, fmt.Sprintf(`{"plaintext":%q}`, b64(fmt.Sprintf("v%d", v)))); rec.Code != http.StatusOK {
			t.Fatalf("put v%d = %d; body=%s", v, rec.Code, rec.Body.String())
		}
	}

	// Depth 2: only the newest two versions survive, and the current value is
	// among them.
	versions, err := db.ListStoredSecretVersions(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Version != 4 || versions[1].Version != 3 {
		t.Fatalf("retained history = %+v, want versions 4 and 3", versions)
	}
	s, err := db.GetStoredSecret(id)
	if err != nil || s.CurrentVersion != 4 {
		t.Fatalf("current secret = %+v, %v", s, err)
	}
	if v, _ := db.GetStoredSecretVersion(id, s.CurrentVersion); v == nil {
		t.Fatal("the current version must never be pruned")
	}

	// The pruning is on the record, with the depth that caused it.
	var sawPrune bool
	for _, e := range eventsFor(t, db, audit.ActionSecretPut) {
		if strings.Contains(e.Detail, "pruned_versions=") && strings.Contains(e.Detail, "history_depth=2") {
			sawPrune = true
		}
	}
	if !sawPrune {
		t.Error("no secret.put event reported the pruning it performed")
	}
}
