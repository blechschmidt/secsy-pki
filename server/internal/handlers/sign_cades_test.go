//go:build sqlite

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSignArtifactCAdESLevel covers the CAdES level wiring on the HTTP layer:
// the requested level flows into the service and back into the response, an
// invalid level is a 400, and a level that needs a TSA the fixture lacks (t/lt)
// is rejected rather than silently downgraded.
func TestSignArtifactCAdESLevel(t *testing.T) {
	api, _, caCert := signingAPI(t)
	artifact := []byte("cades level artifact")
	artifactB64 := base64.StdEncoding.EncodeToString(artifact)
	alice := tenantUser("alice", "a", "signer")

	// level=b: signed attributes only, no timestamp, response reports "b".
	rec := httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"release","artifact":"`+artifactB64+`","level":"b"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("SignArtifact level=b: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var signResp SignArtifactResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &signResp); err != nil {
		t.Fatal(err)
	}
	if signResp.Level != "b" || signResp.Timestamped {
		t.Fatalf("level=b response: level=%q timestamped=%v", signResp.Level, signResp.Timestamped)
	}

	// An invalid level is a client error.
	rec = httptest.NewRecorder()
	api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
		`{"signer":"release","artifact":"`+artifactB64+`","level":"lta"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("SignArtifact level=lta: status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}

	// t/lt need a TSA; the fixture has none, so the request is rejected (400),
	// never silently downgraded to an unstamped signature.
	for _, level := range []string{"t", "lt"} {
		rec = httptest.NewRecorder()
		api.SignArtifact(rec, reqAs(http.MethodPost, "/api/sign", alice, "",
			`{"signer":"release","artifact":"`+artifactB64+`","level":"`+level+`"}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("SignArtifact level=%s without a TSA: status=%d, want 400 (body=%s)", level, rec.Code, rec.Body.String())
		}
	}

	// Verify reports the achieved level, and require_level enforces a floor: a B
	// signature fails a require_level of t.
	carol := tenantUser("carol", "a", "auditor")
	body, _ := json.Marshal(VerifyArtifactRequest{Signature: signResp.Signature, Artifact: artifactB64})
	rec = httptest.NewRecorder()
	api.VerifyArtifact(rec, reqAs(http.MethodPost, "/api/sign/verify", carol, "", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyArtifact: %d %s", rec.Code, rec.Body.String())
	}
	var vresp VerifyArtifactResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if !vresp.Valid || vresp.Level != "b" {
		t.Fatalf("verify response: valid=%v level=%q, want valid b", vresp.Valid, vresp.Level)
	}

	body, _ = json.Marshal(VerifyArtifactRequest{Signature: signResp.Signature, Artifact: artifactB64, RequireLevel: "t"})
	rec = httptest.NewRecorder()
	api.VerifyArtifact(rec, reqAs(http.MethodPost, "/api/sign/verify", carol, "", string(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyArtifact require_level=t: %d %s", rec.Code, rec.Body.String())
	}
	vresp = VerifyArtifactResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &vresp); err != nil {
		t.Fatal(err)
	}
	if vresp.Valid {
		t.Fatal("require_level=t accepted a CAdES-B signature")
	}
	_ = caCert
}
