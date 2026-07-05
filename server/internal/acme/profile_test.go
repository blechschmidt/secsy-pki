//go:build sqlite

package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// These tests cover the ACME Profiles extension (RFC 9773) end-to-end: the
// directory advertises the configured profiles, newOrder honors and persists a
// selected profile (defaulting when omitted), an unknown profile is rejected with
// invalidProfile, and a selected profile threads all the way through finalize to
// the issued certificate. The golang.org/x/crypto/acme client used by the other
// ACME tests does not expose the "profile" field, so this file drives a minimal
// raw JWS client instead — the same shape a real ACME-Profiles-aware client uses.

// withProfiles configures the ACME Profiles allowlist on the test server.
func withProfiles(cfg *Config) {
	cfg.Profiles = map[string]ACMEProfile{
		"tls-server":   {Description: "Long-lived TLS server certificate", Profile: "server"},
		"dual-usage":   {Description: "TLS server + client (mTLS)", Profile: "server-client"},
		"take-default": {Description: "Falls back to the default profile"}, // empty internal id
	}
}

// rawClient is a minimal ACME client that signs its own JWS requests, so it can
// set the newOrder "profile" field the higher-level client library omits.
type rawClient struct {
	t   *testing.T
	key *ecdsa.PrivateKey
	dir rawDirectory
	kid string // account URL, set by register
}

type rawDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	Meta       struct {
		Profiles map[string]string `json:"profiles"`
	} `json:"meta"`
}

type rawOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
}

type rawAuthz struct {
	Status     string `json:"status"`
	Challenges []struct {
		Type  string `json:"type"`
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"challenges"`
}

func newRawClient(t *testing.T, dirURL string) *rawClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rc := &rawClient{t: t, key: key}
	resp, err := http.Get(dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(&rc.dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	return rc
}

// Nonce implements jose.NonceSource: it fetches a fresh anti-replay nonce.
func (rc *rawClient) Nonce() (string, error) {
	resp, err := http.Get(rc.dir.NewNonce)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", fmt.Errorf("new-nonce returned no Replay-Nonce header")
	}
	return n, nil
}

// post signs and sends a JWS request. When embedJWK is true the account key is
// embedded (newAccount); otherwise the request is authenticated with the account
// URL as "kid". An empty payload produces a POST-as-GET.
func (rc *rawClient) post(url string, payload []byte, embedJWK bool) (*http.Response, []byte) {
	rc.t.Helper()
	opts := &jose.SignerOptions{NonceSource: rc}
	opts.EmbedJWK = embedJWK
	opts.WithHeader("url", url)
	if !embedJWK {
		opts.WithHeader("kid", rc.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: rc.key}, opts)
	if err != nil {
		rc.t.Fatalf("new signer: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		rc.t.Fatalf("sign: %v", err)
	}
	// go-jose's FullSerialize omits an empty payload, but ACME POST-as-GET
	// (RFC 8555 §6.3) requires a present "payload":"" field, so ensure it is there.
	serialized := jws.FullSerialize()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(serialized), &m); err != nil {
		rc.t.Fatalf("re-decode signed JWS: %v", err)
	}
	if _, ok := m["payload"]; !ok {
		m["payload"] = json.RawMessage(`""`)
		fixed, _ := json.Marshal(m)
		serialized = string(fixed)
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(serialized))
	if err != nil {
		rc.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		rc.t.Fatalf("POST %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// register creates (or retrieves) the account and records its URL as the kid.
func (rc *rawClient) register() {
	rc.t.Helper()
	resp, body := rc.post(rc.dir.NewAccount, []byte(`{"termsOfServiceAgreed":true}`), true)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		rc.t.Fatalf("newAccount: status %d: %s", resp.StatusCode, body)
	}
	rc.kid = resp.Header.Get("Location")
	if rc.kid == "" {
		rc.t.Fatalf("newAccount: missing Location (account URL)")
	}
}

// newOrder posts a newOrder for a single DNS identifier, selecting profile when
// non-empty. It returns the response, the parsed order, and the order URL.
func (rc *rawClient) newOrder(profile, domain string) (*http.Response, []byte, rawOrder, string) {
	rc.t.Helper()
	req := map[string]any{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	}
	if profile != "" {
		req["profile"] = profile
	}
	payload, _ := json.Marshal(req)
	resp, body := rc.post(rc.dir.NewOrder, payload, false)
	var ord rawOrder
	_ = json.Unmarshal(body, &ord)
	return resp, body, ord, resp.Header.Get("Location")
}

// thumbprint returns the account key's base64url JWK thumbprint.
func (rc *rawClient) thumbprint() string {
	rc.t.Helper()
	tp, err := jwkThumbprint(&jose.JSONWebKey{Key: rc.key.Public()})
	if err != nil {
		rc.t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// TestACME_Profiles_DirectoryAdvertises confirms the directory's meta.profiles
// map advertises exactly the configured client-selectable profiles, and that a
// server with no profiles configured omits the field entirely (backward compat).
func TestACME_Profiles_DirectoryAdvertises(t *testing.T) {
	env := newTestEnv(t, withProfiles)
	rc := newRawClient(t, env.dirURL)
	want := map[string]string{
		"tls-server":   "Long-lived TLS server certificate",
		"dual-usage":   "TLS server + client (mTLS)",
		"take-default": "Falls back to the default profile",
	}
	if len(rc.dir.Meta.Profiles) != len(want) {
		t.Fatalf("meta.profiles = %v, want %v", rc.dir.Meta.Profiles, want)
	}
	for name, desc := range want {
		if rc.dir.Meta.Profiles[name] != desc {
			t.Errorf("meta.profiles[%q] = %q, want %q", name, rc.dir.Meta.Profiles[name], desc)
		}
	}

	// A server without profiles configured must not carry meta.profiles at all.
	plain := newTestEnv(t)
	prc := newRawClient(t, plain.dirURL)
	if prc.dir.Meta.Profiles != nil {
		t.Errorf("meta.profiles present without configured profiles: %v", prc.dir.Meta.Profiles)
	}
}

// TestACME_Profiles_SelectionPersisted confirms newOrder resolves and persists
// the selected profile: a named profile maps to its internal id, an omitted
// profile falls back to the default, and an entry with an empty internal id
// resolves to the default too.
func TestACME_Profiles_SelectionPersisted(t *testing.T) {
	env := newTestEnv(t, withProfiles)

	cases := []struct {
		name        string
		profile     string
		domain      string
		wantProfile string
	}{
		{"named", "dual-usage", "named.example.test", "server-client"},
		{"default-omitted", "", "omitted.example.test", "server"},
		{"empty-internal-id", "take-default", "fallback.example.test", "server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRawClient(t, env.dirURL)
			rc.register()
			resp, body, _, orderURL := rc.newOrder(tc.profile, tc.domain)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
			}
			id := orderURL[strings.LastIndex(orderURL, "/")+1:]
			order, err := env.db.GetACMEOrder(id)
			if err != nil || order == nil {
				t.Fatalf("GetACMEOrder(%q): %v", id, err)
			}
			if order.Profile != tc.wantProfile {
				t.Errorf("persisted order.Profile = %q, want %q", order.Profile, tc.wantProfile)
			}
		})
	}
}

// TestACME_Profiles_UnknownRejected confirms a newOrder naming a profile the
// server does not offer is rejected with the invalidProfile problem (RFC 9773).
func TestACME_Profiles_UnknownRejected(t *testing.T) {
	env := newTestEnv(t, withProfiles)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	resp, body, _, _ := rc.newOrder("no-such-profile", "reject.example.test")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("newOrder status = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatalf("decode problem: %v (%s)", err, body)
	}
	if prob.Type != probInvalidProfile {
		t.Errorf("problem type = %q, want %q", prob.Type, probInvalidProfile)
	}
	// The detail should name the available profiles to guide the client.
	if !strings.Contains(prob.Detail, "tls-server") {
		t.Errorf("problem detail %q does not list available profiles", prob.Detail)
	}

	// An explicit profile against a server that advertises none is likewise unknown.
	plain := newTestEnv(t)
	prc := newRawClient(t, plain.dirURL)
	prc.register()
	presp, pbody, _, _ := prc.newOrder("tls-server", "reject2.example.test")
	if presp.StatusCode != http.StatusBadRequest {
		t.Fatalf("newOrder(no profiles configured) status = %d, want 400: %s", presp.StatusCode, pbody)
	}
	var pprob Problem
	_ = json.Unmarshal(pbody, &pprob)
	if pprob.Type != probInvalidProfile {
		t.Errorf("problem type = %q, want %q", pprob.Type, probInvalidProfile)
	}
}

// TestACME_Profiles_EndToEnd drives a full order under a selected profile and
// confirms the issued certificate reflects that profile — not the default. The
// selected "dual-usage" profile maps to "server-client" (serverAuth + clientAuth),
// so the leaf must carry clientAuth, which the default "server" profile lacks.
func TestACME_Profiles_EndToEnd(t *testing.T) {
	env := newTestEnv(t, withProfiles)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "e2e.example.test"
	resp, body, ord, orderURL := rc.newOrder("dual-usage", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}

	// Solve the http-01 challenge for the single authorization.
	tp := rc.thumbprint()
	for _, au := range ord.Authorizations {
		_, ab := rc.post(au, nil, false) // POST-as-GET
		var az rawAuthz
		if err := json.Unmarshal(ab, &az); err != nil {
			t.Fatalf("decode authz: %v (%s)", err, ab)
		}
		var chURL, token string
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				chURL, token = ch.URL, ch.Token
			}
		}
		if chURL == "" {
			t.Fatalf("no http-01 challenge offered: %s", ab)
		}
		env.httpMu.Lock()
		env.httpResp[token] = keyAuthorization(token, tp)
		env.httpMu.Unlock()
		if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
			t.Fatalf("accept challenge: status %d: %s", r.StatusCode, b)
		}
		rc.waitStatus(au, "valid")
	}

	// The order should now be ready; finalize with a CSR for the domain.
	rc.waitStatus(orderURL, "ready")
	csr := base64.RawURLEncoding.EncodeToString(csrFor(t, domain))
	fresp, fbody := rc.post(ord.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d, want 200: %s", fresp.StatusCode, fbody)
	}
	var finalized rawOrder
	if err := json.Unmarshal(fbody, &finalized); err != nil {
		t.Fatalf("decode finalized order: %v", err)
	}
	if finalized.Status != "valid" || finalized.Certificate == "" {
		t.Fatalf("finalized order = %+v, want valid with a certificate URL", finalized)
	}

	// Download and verify the leaf carries clientAuth (proving the selected
	// server-client profile governed issuance, not the default server profile).
	_, chain := rc.post(finalized.Certificate, nil, false)
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatalf("certificate response is not PEM: %s", chain)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !hasEKU(leaf, x509.ExtKeyUsageClientAuth) {
		t.Errorf("leaf EKUs = %v, want clientAuth (selected profile not applied)", leaf.ExtKeyUsage)
	}
	if !hasEKU(leaf, x509.ExtKeyUsageServerAuth) {
		t.Errorf("leaf EKUs = %v, want serverAuth", leaf.ExtKeyUsage)
	}
}

// waitStatus polls a resource (order or authorization) until it reaches the
// wanted status. Validation and issuance are synchronous in this server, so a
// couple of iterations suffice; the bound guards against a hang on regression.
func (rc *rawClient) waitStatus(url, want string) {
	rc.t.Helper()
	for i := 0; i < 40; i++ {
		_, body := rc.post(url, nil, false)
		var obj struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &obj)
		if obj.Status == want {
			return
		}
		if obj.Status == "invalid" {
			rc.t.Fatalf("%s became invalid while waiting for %q: %s", url, want, body)
		}
		time.Sleep(25 * time.Millisecond)
	}
	rc.t.Fatalf("%s did not reach status %q in time", url, want)
}

// hasEKU reports whether cert carries the given extended key usage.
func hasEKU(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}
