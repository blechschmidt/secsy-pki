package celpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Tests for the request-fact capture. The invariant that matters more than any
// of the facts: capture must be transparent. A middleware that reads a request
// body to show it to a policy rule and then hands the handler a short, empty or
// re-ordered body has broken the API to decorate the policy engine.

// captureAndServe runs a request through Capture and returns the facts the
// middleware collected plus whatever the handler read from the body.
func captureAndServe(t *testing.T, r *http.Request) (*Facts, []byte) {
	t.Helper()
	var (
		facts *Facts
		read  []byte
	)
	h := Capture(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		facts = FromContext(req.Context())
		b, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("handler could not read the body: %v", err)
		}
		read = b
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if facts == nil {
		t.Fatal("Capture installed no fact holder")
	}
	return facts, read
}

func TestCaptureRecordsTheURLAsAnObject(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost,
		"https://pki.example.com:8443/api/keys/ca-1/issue?dry_run=1&tag=a&tag=b", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "10.9.9.9:54321"
	facts, _ := captureAndServe(t, r)

	in := facts.Input(CertRequest{})
	got := in.URL
	if !got.Present {
		t.Error("url.present is false for a request that arrived over HTTP")
	}
	if got.Method != http.MethodPost {
		t.Errorf("method = %q", got.Method)
	}
	if got.Path != "/api/keys/ca-1/issue" {
		t.Errorf("path = %q", got.Path)
	}
	if in.URL.Path != got.Path {
		t.Error("the path variable and url.path disagree")
	}
	if got.Host != "pki.example.com" || got.Port != "8443" {
		t.Errorf("host/port = %q/%q", got.Host, got.Port)
	}
	wantSegments := []string{"api", "keys", "ca-1", "issue"}
	if len(got.Segments) != len(wantSegments) {
		t.Fatalf("segments = %v", got.Segments)
	}
	for i := range wantSegments {
		if got.Segments[i] != wantSegments[i] {
			t.Fatalf("segments = %v, want %v", got.Segments, wantSegments)
		}
	}
	if got.RawQuery != "dry_run=1&tag=a&tag=b" {
		t.Errorf("raw_query = %q", got.RawQuery)
	}
	if len(got.Query["tag"]) != 2 {
		t.Errorf("a repeated query parameter lost a value: %v", got.Query)
	}
	if got.ClientIP != "10.9.9.9" {
		t.Errorf("client_ip = %q, want the peer address without its port", got.ClientIP)
	}
	if !strings.HasPrefix(got.Full, "http") || !strings.Contains(got.Full, "/api/keys/ca-1/issue") {
		t.Errorf("full = %q", got.Full)
	}
}

// TestClientIPIgnoresForwardedFor: a header the client sets must not be what a
// restriction rule trusts.
func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(`{}`))
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	facts, _ := captureAndServe(t, r)
	if ip := facts.Input(CertRequest{}).URL.ClientIP; ip != "10.0.0.1" {
		t.Errorf("client_ip = %q; a spoofable header must not win", ip)
	}
}

func TestCaptureDecodesJSONBody(t *testing.T) {
	body := `{"profile":"server","validity_days":90,"reason":"CHG-1","sans":["a","b"],"nested":{"k":"v"}}`
	r := httptest.NewRequest(http.MethodPost, "/api/keys/ca-1/issue", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	facts, read := captureAndServe(t, r)

	if string(read) != body {
		t.Fatalf("the handler read %q, want the bytes the client sent", read)
	}
	in := facts.Input(CertRequest{})
	if in.Body["profile"] != "server" {
		t.Errorf("body.profile = %v", in.Body["profile"])
	}
	if in.Body["validity_days"] != float64(90) {
		t.Errorf("body.validity_days = %v (%T)", in.Body["validity_days"], in.Body["validity_days"])
	}
	// And a rule can actually read the nested and list-valued parameters.
	for _, expr := range []string{
		`has(body.profile) && body.profile == "server"`,
		`has(body.sans) && body.sans.size() == 2`,
		`has(body.nested) && body.nested.k == "v"`,
		`!has(body.absent)`,
	} {
		if d := Shared().Evaluate([]Rule{rule("body", expr)}, in); !d.Allowed {
			t.Errorf("%q did not hold over the captured body: %+v", expr, d.Violations)
		}
	}
}

func TestCaptureDecodesFormBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader("profile=server&san=a&san=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	facts, read := captureAndServe(t, r)
	if string(read) != "profile=server&san=a&san=b" {
		t.Fatalf("the handler read %q", read)
	}
	in := facts.Input(CertRequest{})
	if in.Body["profile"] != "server" {
		t.Errorf("a single-valued form parameter is not a string: %v", in.Body["profile"])
	}
	if list, ok := in.Body["san"].([]interface{}); !ok || len(list) != 2 {
		t.Errorf("a repeated form parameter is not a list: %v", in.Body["san"])
	}
}

// TestCaptureLeavesBinaryBodiesAlone: an EST/SCEP/CMP payload is not something a
// certificate rule inspects, and buffering it would be pure cost.
func TestCaptureLeavesBinaryBodiesAlone(t *testing.T) {
	payload := strings.Repeat("\x30\x82", 64)
	for _, ct := range []string{"application/pkcs10", "application/pkcs7-mime", "application/pkixcmp", "application/octet-stream"} {
		r := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", strings.NewReader(payload))
		r.Header.Set("Content-Type", ct)
		facts, read := captureAndServe(t, r)
		if string(read) != payload {
			t.Errorf("%s: the handler read %d bytes, want %d", ct, len(read), len(payload))
		}
		if body := facts.Input(CertRequest{}).Body; len(body) != 0 {
			t.Errorf("%s: a binary body was exposed as parameters: %v", ct, body)
		}
	}
}

// TestCaptureSkipsBodylessMethods keeps a GET off the buffering path entirely.
func TestCaptureSkipsBodylessMethods(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions} {
		r := httptest.NewRequest(m, "/api/issuance-policies", nil)
		facts, _ := captureAndServe(t, r)
		if body := facts.Input(CertRequest{}).Body; len(body) != 0 {
			t.Errorf("%s: body exposed: %v", m, body)
		}
		if !facts.Input(CertRequest{}).URL.Present {
			t.Errorf("%s: the URL was not captured", m)
		}
	}
}

// TestCaptureIsTransparentForOversizeBodies is the headline transparency test:
// a body past the capture bound is not exposed, and the handler still reads
// every byte in order.
func TestCaptureIsTransparentForOversizeBodies(t *testing.T) {
	// A JSON object just over the bound.
	filler := strings.Repeat("x", maxCapturedBodyBytes)
	body := fmt.Sprintf(`{"profile":"server","pad":%q}`, filler)
	if len(body) <= maxCapturedBodyBytes {
		t.Fatalf("test body is %d bytes, not over the %d bound", len(body), maxCapturedBodyBytes)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/keys/ca-1/issue", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	facts, read := captureAndServe(t, r)
	if string(read) != body {
		t.Fatalf("the handler read %d bytes of a %d-byte body", len(read), len(body))
	}
	if b := facts.Input(CertRequest{}).Body; len(b) != 0 {
		t.Errorf("an over-long body was exposed; a rule must see no body rather than a truncated one: %d keys", len(b))
	}

	// And a body exactly at the bound IS exposed, so the boundary is inclusive.
	pad := maxCapturedBodyBytes - len(`{"profile":"server","pad":""}`)
	atBound := fmt.Sprintf(`{"profile":"server","pad":%q}`, strings.Repeat("y", pad))
	if len(atBound) != maxCapturedBodyBytes {
		t.Fatalf("at-bound body is %d bytes, want %d", len(atBound), maxCapturedBodyBytes)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/keys/ca-1/issue", strings.NewReader(atBound))
	r.Header.Set("Content-Type", "application/json")
	facts, read = captureAndServe(t, r)
	if string(read) != atBound {
		t.Error("the handler did not read the at-bound body intact")
	}
	if facts.Input(CertRequest{}).Body["profile"] != "server" {
		t.Error("a body exactly at the bound was not exposed")
	}
}

// TestCaptureHandlesUndecodableBodies: a malformed or non-object JSON body must
// not be invented into parameters, and must still reach the handler so the
// handler reports the error.
func TestCaptureHandlesUndecodableBodies(t *testing.T) {
	for _, body := range []string{`{not json`, `[1,2,3]`, `"a string"`, `null`, ``} {
		r := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		facts, read := captureAndServe(t, r)
		if string(read) != body {
			t.Errorf("%q: handler read %q", body, read)
		}
		if b := facts.Input(CertRequest{}).Body; len(b) != 0 {
			t.Errorf("%q produced parameters: %v", body, b)
		}
	}
}

// TestCaptureTreatsMissingContentTypeAsJSON: this PKI's own clients and the
// console do not always set the header.
func TestCaptureTreatsMissingContentTypeAsJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader(`{"reason":"CHG-1"}`))
	r.Header.Del("Content-Type")
	facts, _ := captureAndServe(t, r)
	if facts.Input(CertRequest{}).Body["reason"] != "CHG-1" {
		t.Error("a body with no Content-Type was not decoded")
	}
}

func TestCaptureAcceptsJSONSuffixTypes(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/acme/new-order", strings.NewReader(`{"reason":"x"}`))
	r.Header.Set("Content-Type", "application/jose+json; charset=utf-8")
	facts, _ := captureAndServe(t, r)
	if facts.Input(CertRequest{}).Body["reason"] != "x" {
		t.Error("a +json media type was not decoded")
	}
}

// TestFactsNilSafety: a code path that never passed through capture must still
// evaluate, with the HTTP facts empty and the principal unauthenticated.
func TestFactsNilSafety(t *testing.T) {
	var f *Facts
	f.SetURL(RequestURL{Present: true}) // must not panic
	f.SetBody(map[string]interface{}{"a": "b"})
	f.SetJWT(map[string]interface{}{"sub": "x"})
	f.SetPrincipal(Principal{Subject: "x"})
	f.SetSource(SourceREST)
	if f.Source() != "" {
		t.Error("a nil holder reported a source")
	}

	in := f.Input(CertRequest{Profile: "server"})
	if in.URL.Present || len(in.Body) != 0 || len(in.JWT) != 0 || in.Principal.Authenticated {
		t.Fatalf("a nil holder produced facts: %+v", in)
	}
	if in.Request.Source != SourceUnknown {
		t.Errorf("source = %q, want %q", in.Request.Source, SourceUnknown)
	}
	// A nil Context is not something a caller should pass, but FromContext is
	// reached from deep inside the issuance path and a nil one there must read as
	// "no facts" rather than panic the signer — so the guard is tested even though
	// staticcheck rightly objects to the call.
	var noCtx context.Context //nolint:staticcheck // SA1012: the nil guard is the thing under test
	if FromContext(noCtx) != nil || FromContext(context.Background()) != nil {
		t.Error("FromContext invented a holder")
	}
	// WithFacts(nil) must not install anything.
	if FromContext(WithFacts(context.Background(), nil)) != nil {
		t.Error("WithFacts installed a nil holder")
	}
}

// TestInputDefaultsSourceFromTheHolder covers the precedence: an explicit source
// from the handler wins, then the holder's, then the mere presence of a URL.
func TestInputDefaultsSourceFromTheHolder(t *testing.T) {
	f := NewFacts()
	f.SetURL(RequestURL{Present: true, Path: "/api/x"})
	if got := f.Input(CertRequest{}).Request.Source; got != SourceREST {
		t.Errorf("source = %q, want %q for an HTTP request with no explicit source", got, SourceREST)
	}
	f.SetSource(SourceEST)
	if got := f.Input(CertRequest{}).Request.Source; got != SourceEST {
		t.Errorf("source = %q, want the holder's %q", got, SourceEST)
	}
	if got := f.Input(CertRequest{Source: SourceBulk}).Request.Source; got != SourceBulk {
		t.Errorf("source = %q, want the caller's explicit %q", got, SourceBulk)
	}
}

// TestInputFillsRequestedByFromThePrincipal: a rule and an audit record should
// agree about who asked.
func TestInputFillsRequestedByFromThePrincipal(t *testing.T) {
	f := NewFacts()
	f.SetPrincipal(Principal{Subject: "ops@example.com", Authenticated: true})
	if got := f.Input(CertRequest{}).Request.RequestedBy; got != "ops@example.com" {
		t.Errorf("requested_by = %q", got)
	}
	// An explicit value is not overwritten.
	if got := f.Input(CertRequest{RequestedBy: "acme-account-7"}).Request.RequestedBy; got != "acme-account-7" {
		t.Errorf("requested_by = %q, want the explicit value", got)
	}
}

// TestInputSnapshotsTheMaps: an evaluation must not observe a later write, and
// must not be able to mutate the holder.
func TestInputSnapshotsTheMaps(t *testing.T) {
	f := NewFacts()
	f.SetJWT(map[string]interface{}{"sub": "a"})
	in := f.Input(CertRequest{})
	f.SetJWT(map[string]interface{}{"sub": "b"})
	if in.JWT["sub"] != "a" {
		t.Error("an evaluation's claim set changed under it")
	}
	in.JWT["sub"] = "c"
	if f.Input(CertRequest{}).JWT["sub"] != "b" {
		t.Error("mutating a snapshot reached back into the holder")
	}
}

// TestFactsConcurrentAccess: a bulk run fans out over one request's holder. Run
// with -race, this is the test that catches an unguarded field.
func TestFactsConcurrentAccess(t *testing.T) {
	f := NewFacts()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%4 == 0 {
				f.SetJWT(map[string]interface{}{"sub": fmt.Sprint(n)})
			}
			if n%4 == 1 {
				f.SetPrincipal(Principal{Subject: fmt.Sprint(n), Authenticated: true})
			}
			if n%4 == 2 {
				f.SetBody(map[string]interface{}{"n": n})
			}
			_ = f.Input(CertRequest{Profile: "server"})
		}(i)
	}
	wg.Wait()
}

// TestClaimSetNormalizesTheVerifiedClaims: the four claims the verifier resolved
// are present in the shape a rule expects, whatever the raw decode held.
func TestClaimSetNormalizesTheVerifiedClaims(t *testing.T) {
	raw := map[string]interface{}{"groups": []interface{}{"g1"}, "aud": "single-string"}
	claims := ClaimSet("sub-1", "a@b.io", "https://idp", []string{"pki", "api"}, raw)
	if claims["sub"] != "sub-1" || claims["email"] != "a@b.io" || claims["iss"] != "https://idp" {
		t.Fatalf("verified claims were not filled in: %v", claims)
	}
	aud, ok := claims["aud"].([]interface{})
	if !ok || len(aud) != 2 {
		t.Fatalf("aud = %#v; a bare-string audience must be normalized to a list", claims["aud"])
	}
	if _, ok := claims["groups"]; !ok {
		t.Error("the raw claims were dropped")
	}
	// The raw map must not be mutated: it belongs to the token verifier.
	if raw["sub"] != nil || raw["aud"] != "single-string" {
		t.Error("ClaimSet mutated the raw claim set")
	}
	// And a rule can read all of it.
	in := Input{JWT: claims}
	for _, expr := range []string{
		`jwt.sub == "sub-1"`,
		`"pki" in jwt.aud`,
		`jwt.iss == "https://idp"`,
		`has(jwt.groups) && "g1" in jwt.groups`,
	} {
		if d := Shared().Evaluate([]Rule{rule("jwt", expr)}, in); !d.Allowed {
			t.Errorf("%q did not hold: %+v", expr, d.Violations)
		}
	}
}

// TestCaptureRoundTripsThroughAHandlerThatDecodes is the end-to-end transparency
// check against a real JSON decode, the thing every issuance handler does.
func TestCaptureRoundTripsThroughAHandlerThatDecodes(t *testing.T) {
	type issueBody struct {
		CSR          string `json:"csr"`
		Profile      string `json:"profile"`
		ValidityDays int    `json:"validity_days"`
	}
	want := issueBody{CSR: "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----", Profile: "server", ValidityDays: 42}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got issueBody
	var facts *Facts
	h := Capture(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		facts = FromContext(r.Context())
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("handler decode: %v", err)
		}
	}))
	r := httptest.NewRequest(http.MethodPost, "/api/keys/ca-1/issue", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got != want {
		t.Fatalf("the handler decoded %+v, want %+v", got, want)
	}
	if facts.Input(CertRequest{}).Body["validity_days"] != float64(42) {
		t.Error("the same body was not exposed to the engine")
	}
}
