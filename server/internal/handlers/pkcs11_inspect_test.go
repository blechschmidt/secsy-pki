//go:build sqlite

package handlers

// Tests for the raw PKCS#11 inspection endpoints (Task 218).
//
// The harness's provider is the software backend, which has no PKCS#11 view, so
// what is asserted here is the contract around the view rather than the view
// itself (internal/pki covers that against SoftHSM and the YubiHSM):
//
//   - the gate: hsm:manage, with every lesser principal refused, and the refusal
//     recorded in the audit log;
//   - the capability answer: 501 with the backend named, not a synthesised empty
//     view that would read as "the token is empty";
//   - the query knobs, which shape how much of a token is read;
//   - the audit detail, which is what an access review actually reads.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Both endpoints administer the device, so both demand platform hsm:manage —
// an auditor or a tenant admin must not be able to enumerate the token.
func TestPKCS11InspectRequiresHSMManage(t *testing.T) {
	api, _ := tenantAPI(t)
	endpoints := map[string]http.HandlerFunc{
		"module":  api.InspectPKCS11Module,
		"objects": api.InspectPKCS11Objects,
	}
	principals := []struct {
		name string
		user *models.UserInfo
		want int
	}{
		// The software provider has no PKCS#11 view, so an authorized caller
		// gets 501: past the gate, which is what this test is about.
		{"platform admin", &models.UserInfo{Subject: "root", Roles: []string{"admin"}}, http.StatusNotImplemented},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"auditor", &models.UserInfo{Subject: "aud", Roles: []string{"auditor"}}, http.StatusForbidden},
		{"operator", &models.UserInfo{Subject: "op", Roles: []string{"operator"}}, http.StatusForbidden},
		{"tenant admin", &models.UserInfo{Subject: "ta", TenantRoles: map[string][]string{"t1": {"admin"}}}, http.StatusForbidden},
	}
	for name, h := range endpoints {
		for _, p := range principals {
			t.Run(name+"/"+p.name, func(t *testing.T) {
				rec := getAsUser(h, p.user, "/api/pkcs11/"+name)
				if rec.Code != p.want {
					t.Errorf("status = %d, want %d; body=%s", rec.Code, p.want, rec.Body.String())
				}
			})
		}
	}
}

// A denied inspection is recorded: an attempt to enumerate the token is exactly
// the thing an access review wants to see, successful or not.
func TestPKCS11InspectRecordsDenial(t *testing.T) {
	api, db := tenantAPI(t)
	rec := getAsUser(api.InspectPKCS11Objects, &models.UserInfo{Subject: "nobody"}, "/api/pkcs11/objects")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	events, _, err := db.ListEvents(audit.ActionHSMInspect, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Action == audit.ActionHSMInspect {
			found = true
			if e.Result != audit.ResultDenied {
				t.Errorf("event result = %q, want %q", e.Result, audit.ResultDenied)
			}
			if !strings.Contains(e.Detail, "hsm:manage") {
				t.Errorf("event detail %q does not name the missing capability", e.Detail)
			}
		}
	}
	if !found {
		t.Errorf("no %s event was recorded for the denied inspection", audit.ActionHSMInspect)
	}
}

// A backend with no slots and no CKA_* must say so, naming itself. Answering
// 200 with an empty view would read as "the token holds nothing", which is a
// different and alarming claim.
func TestPKCS11InspectUnsupportedBackendIsNamed(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := getAsUser(api.InspectPKCS11Module, &models.UserInfo{Subject: "root", Roles: []string{"admin"}}, "/api/pkcs11/module")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the error body: %v", err)
	}
	if !strings.Contains(body["error"], string(keyprovider.ProviderSoftware)) {
		t.Errorf("error %q does not name the configured backend", body["error"])
	}
	if !strings.Contains(body["error"], "PKCS#11") {
		t.Errorf("error %q does not say what is unavailable", body["error"])
	}
}

func TestInspectOptionsFromQuery(t *testing.T) {
	cases := []struct {
		query string
		want  pki.InspectOptions
	}{
		{"", pki.InspectOptions{}},
		{"?all=1", pki.InspectOptions{AllAttributes: true}},
		{"?all=true", pki.InspectOptions{AllAttributes: true}},
		{"?all=0", pki.InspectOptions{}},
		{"?max_objects=25", pki.InspectOptions{MaxObjects: 25}},
		{"?max_value_bytes=64", pki.InspectOptions{MaxValueBytes: 64}},
		{"?max_objects=-5", pki.InspectOptions{}},   // nonsense is ignored, not an error
		{"?max_objects=lots", pki.InspectOptions{}}, //
		{"?all=1&max_objects=3", pki.InspectOptions{AllAttributes: true, MaxObjects: 3}},
	}
	for _, c := range cases {
		got := inspectOptions(httptest.NewRequest(http.MethodGet, "/api/pkcs11/objects"+c.query, nil))
		if got != c.want {
			t.Errorf("%q -> %+v, want %+v", c.query, got, c.want)
		}
	}
}

// The audit detail is the per-token object count, because "someone enumerated
// the device" is less useful than "and it held 14 objects at the time".
func TestInspectionDetail(t *testing.T) {
	yes := true
	cases := []struct {
		name  string
		views []keyprovider.TokenView
		want  []string
	}{
		{
			name:  "single token",
			views: []keyprovider.TokenView{{Objects: &pki.ObjectSet{TokenLabel: "secsy-root", Objects: make([]pki.Object, 3)}}},
			want:  []string{"secsy-root: 3 object(s)"},
		},
		{
			name: "truncated",
			views: []keyprovider.TokenView{{Objects: &pki.ObjectSet{
				TokenLabel: "big", Objects: make([]pki.Object, 500), Truncated: true}}},
			want: []string{"big: 500 object(s) (truncated)"},
		},
		{
			name: "HA set with one member down",
			views: []keyprovider.TokenView{
				{Token: "primary", Healthy: &yes, Objects: &pki.ObjectSet{Objects: make([]pki.Object, 2)}},
				{Token: "standby", Error: "token unreachable"},
			},
			want: []string{"primary: 2 object(s)", "standby: error: token unreachable"},
		},
		{
			name:  "no objects enumerated",
			views: []keyprovider.TokenView{{Token: "primary"}},
			want:  []string{"primary: no objects enumerated"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := inspectionDetail(c.views)
			for _, want := range c.want {
				if !strings.Contains(got, want) {
					t.Errorf("detail %q does not contain %q", got, want)
				}
			}
		})
	}
}
