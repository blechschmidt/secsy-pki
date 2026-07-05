//go:build sqlite

package handlers

// Functional tests for the format-preserving-encryption / tokenization endpoints
// (Task 144), exercised end-to-end against a software KEK. Authorization and
// tenant isolation are covered by the authz matrix; these prove the transform
// actually round-trips, preserves format, converges for equal input, and honors
// the per-template role allowlist.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

func newTransformAPI(t *testing.T) *API {
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
	if _, err := secret.ProvisionKEK(context.Background(), prov, "xform-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "xform-kek")
	must := func(s secret.TransformSpec) *secret.TransformTemplate {
		tmpl, err := secret.ResolveTransformTemplate(s)
		if err != nil {
			t.Fatalf("ResolveTransformTemplate(%s): %v", s.Name, err)
		}
		return tmpl
	}
	api.SetTransformTemplates(map[string]*secret.TransformTemplate{
		"pan":  must(secret.TransformSpec{Name: "pan", Alphabet: "digits", Deterministic: true, MinLength: 12, MaxLength: 19, PreserveOther: true}),
		"acct": must(secret.TransformSpec{Name: "acct", Alphabet: "alphanumeric", Deterministic: false, TweakSource: secret.TweakSourceRequest, MinLength: 8}),
	})
	return api
}

func encodeDecode(t *testing.T, api *API, h http.HandlerFunc, body string) transformResponse {
	t.Helper()
	rec := doJSON(t, h, "/api/secret/transform", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("transform = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp transformResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// TestTransformEncodeDecodeRoundTrip: a deterministic PAN template preserves
// length and dashes, converges for equal input, and decodes back exactly.
func TestTransformEncodeDecodeRoundTrip(t *testing.T) {
	api := newTransformAPI(t)
	const pan = "4111-1111-1111-1111"

	enc := encodeDecode(t, api, api.EncodeTransform, `{"template":"pan","value":"`+pan+`"}`)
	if enc.Result == pan || len(enc.Result) != len(pan) {
		t.Fatalf("bad token %q for %q", enc.Result, pan)
	}
	if !enc.Deterministic {
		t.Fatal("pan template should report deterministic")
	}
	if enc.Result[4] != '-' || enc.Result[9] != '-' {
		t.Fatalf("dashes not preserved: %q", enc.Result)
	}
	// Convergent: encoding again yields the identical token (equality search).
	enc2 := encodeDecode(t, api, api.EncodeTransform, `{"template":"pan","value":"`+pan+`"}`)
	if enc2.Result != enc.Result {
		t.Fatalf("deterministic template diverged: %q vs %q", enc.Result, enc2.Result)
	}
	dec := encodeDecode(t, api, api.DecodeTransform, `{"template":"pan","value":"`+enc.Result+`"}`)
	if dec.Result != pan {
		t.Fatalf("decode mismatch: %q != %q", dec.Result, pan)
	}
}

// TestTransformRequestTweak: the alphanumeric account template requires a tweak,
// diverges across tweaks, and decodes only with the matching tweak.
func TestTransformRequestTweak(t *testing.T) {
	api := newTransformAPI(t)
	// Missing tweak -> 400.
	rec := doJSON(t, api.EncodeTransform, "/api/secret/transform", `{"template":"acct","value":"ACCT12345"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing tweak = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// base64("ctx1")=Y3R4MQ==, base64("ctx2")=Y3R4Mg==
	a := encodeDecode(t, api, api.EncodeTransform, `{"template":"acct","value":"ACCT12345","tweak":"Y3R4MQ=="}`)
	b := encodeDecode(t, api, api.EncodeTransform, `{"template":"acct","value":"ACCT12345","tweak":"Y3R4Mg=="}`)
	if a.Result == b.Result {
		t.Fatal("different tweaks produced identical tokens")
	}
	back := encodeDecode(t, api, api.DecodeTransform, `{"template":"acct","value":"`+a.Result+`","tweak":"Y3R4MQ=="}`)
	if back.Result != "ACCT12345" {
		t.Fatalf("decode with matching tweak = %q", back.Result)
	}
}

// TestTransformUnknownTemplate: an unknown template is a 400 for an authorized
// caller (not a 500 or a silent success).
func TestTransformUnknownTemplate(t *testing.T) {
	api := newTransformAPI(t)
	rec := doJSON(t, api.EncodeTransform, "/api/secret/transform", `{"template":"nope","value":"123456"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown template = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestTemplateRoleAllowlist unit-tests the per-template RBAC helper: an empty
// allowlist admits any caller, a populated one admits only matching roles (and
// root), and denies everyone else.
func TestTemplateRoleAllowlist(t *testing.T) {
	open := &secret.TransformTemplate{Name: "open"}
	restricted := &secret.TransformTemplate{Name: "restricted", Roles: []string{"issuer"}}

	root := &models.UserInfo{Subject: "root", IsRoot: true}
	issuer := &models.UserInfo{Subject: "i", Roles: []string{"issuer"}}
	auditor := &models.UserInfo{Subject: "a", Roles: []string{"auditor"}}

	if !templateRoleAllowed(issuer, "default", open) || !templateRoleAllowed(auditor, "default", open) {
		t.Fatal("open template should admit any caller")
	}
	if !templateRoleAllowed(issuer, "default", restricted) {
		t.Fatal("restricted template should admit the issuer role")
	}
	if !templateRoleAllowed(root, "default", restricted) {
		t.Fatal("restricted template should admit root")
	}
	if templateRoleAllowed(auditor, "default", restricted) {
		t.Fatal("restricted template should deny a non-matching role")
	}
	if templateRoleAllowed(nil, "default", restricted) {
		t.Fatal("restricted template should deny an anonymous caller")
	}
}
