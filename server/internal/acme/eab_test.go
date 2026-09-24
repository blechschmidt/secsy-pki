//go:build sqlite

package acme

// Coverage for the External Account Binding gate (RFC 8555 §7.3.4) and the
// constant-time thumbprint comparison it relies on. The EAB is the authorization
// grant that decides whether an ACME client may create an account at all, so
// every rejection path is asserted, and every EAB JWS in this file is built from
// crypto/hmac + encoding/json + base64url so the test is an independent oracle
// rather than a call back into the implementation.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"strings"
	"testing"
)

// ---- hmacEqual ------------------------------------------------------------

// TestHMACEqual covers the thumbprint comparison exhaustively: it must behave
// exactly like equality, including for the empty string and for inputs that
// differ only in their first or last byte.
func TestHMACEqual(t *testing.T) {
	const ref = "wZ7l5o1X8m2kqPjA_3rTnBcVdEfGhIjKlMnOpQrStUv"
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", ref, ref, true},
		{"both-empty", "", "", true},
		{"a-empty", "", ref, false},
		{"b-empty", ref, "", false},
		{"differs-first-byte", ref, "X" + ref[1:], false},
		{"differs-last-byte", ref, ref[:len(ref)-1] + "X", false},
		{"differs-middle-byte", ref, ref[:20] + "X" + ref[21:], false},
		{"prefix-of-b", ref[:len(ref)-1], ref, false},
		{"b-prefix-of-a", ref, ref[:len(ref)-1], false},
		{"longer-b", ref, ref + "A", false},
		{"case-differs", "abc", "abC", false},
		{"embedded-nul-equal", "a\x00b", "a\x00b", true},
		{"embedded-nul-differs-after-nul", "a\x00b", "a\x00c", false},
		{"single-byte-equal", "a", "a", true},
		{"single-byte-differs", "a", "b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hmacEqual(tc.a, tc.b); got != tc.want {
				t.Errorf("hmacEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// The comparison must be symmetric.
			if got := hmacEqual(tc.b, tc.a); got != tc.want {
				t.Errorf("hmacEqual(%q, %q) = %v, want %v (asymmetric)", tc.b, tc.a, got, tc.want)
			}
		})
	}
}

// TestHMACEqualIsConstantTime asserts structurally that hmacEqual delegates to a
// constant-time primitive (hmac.Equal / subtle.ConstantTimeCompare) rather than
// "==" or bytes.Equal on a string. Timing cannot be asserted reliably in a unit
// test, but the choice of primitive can: this guards against a future
// "simplification" to a short-circuiting comparison, which would leak the
// account-key thumbprint byte by byte through the EAB rejection latency.
func TestHMACEqualIsConstantTime(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	const want1, want2 = "hmac.Equal", "subtle.ConstantTimeCompare"
	fset := token.NewFileSet()
	var found bool
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "hmacEqual" || fn.Recv != nil || fn.Body == nil {
				continue
			}
			found = true
			var calls []string
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkgIdent, ok := sel.X.(*ast.Ident); ok {
						calls = append(calls, pkgIdent.Name+"."+sel.Sel.Name)
					}
				}
				return true
			})
			var constantTime bool
			for _, c := range calls {
				if c == want1 || c == want2 {
					constantTime = true
				}
			}
			if !constantTime {
				t.Errorf("%s: hmacEqual body calls %v; it must use %s or %s so the comparison is constant time",
					name, calls, want1, want2)
			}
		}
	}
	if !found {
		t.Fatal("could not locate func hmacEqual in the package source")
	}
}

// ---- EAB test fixtures ----------------------------------------------------

// The operator-provisioned HMAC keys the test server accepts. eabGoodKID is the
// happy-path credential; eabPaddedKID exercises the standard-base64-with-padding
// tolerance in the config decoder; eabBrokenKID is unusable in either encoding
// and must surface as a server misconfiguration, never as a pass.
const (
	eabGoodKID   = "kid-good"
	eabPaddedKID = "kid-padded"
	eabBrokenKID = "kid-broken"
)

var (
	eabGoodKey   = []byte("0123456789abcdef0123456789abcdef")
	eabPaddedKey = []byte("fedcba9876543210fedcba9876543210ab")
	eabOtherKey  = []byte("an-entirely-different-hmac-secret!!")
)

// withEAB turns on the EAB requirement with the fixture credentials above.
func withEAB(cfg *Config) {
	cfg.RequireEAB = true
	cfg.EABHMACKeys = map[string]string{
		eabGoodKID: base64.RawURLEncoding.EncodeToString(eabGoodKey),
		// Deliberately standard base64 *with* padding, which the server tolerates.
		eabPaddedKID: base64.StdEncoding.EncodeToString(eabPaddedKey),
		// Valid in neither encoding.
		eabBrokenKID: "%%%not-base64%%%",
	}
}

// eabParts is a flattened-JSON JWS built field by field, so a test can corrupt
// any single field (or omit it) without touching the others.
type eabParts struct {
	protected *string // nil omits the field entirely
	payload   string
	signature string
}

func (p eabParts) raw() json.RawMessage {
	m := map[string]string{"payload": p.payload, "signature": p.signature}
	if p.protected != nil {
		m["protected"] = *p.protected
	}
	b, _ := json.Marshal(m)
	return b
}

// b64 is raw-base64url, the only encoding RFC 7515 permits in a JWS.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// buildEAB assembles an EAB JWS the way RFC 8555 §7.3.4 specifies: a flattened
// JWS whose protected header carries {alg, kid, url} and whose payload is the
// account key's JWK, MAC'd with the operator key. alg selects both the advertised
// algorithm and the digest, so a test can present one the server must refuse.
func buildEAB(t *testing.T, alg, kid, url string, macKey []byte, payloadJSON []byte) eabParts {
	t.Helper()
	hdr := map[string]any{"alg": alg, "kid": kid, "url": url}
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal protected header: %v", err)
	}
	prot := b64(hb)
	pl := b64(payloadJSON)
	return eabParts{protected: &prot, payload: pl, signature: eabMAC(t, alg, macKey, prot+"."+pl)}
}

// eabMAC computes the JWS MAC over signingInput for the named HS* algorithm.
func eabMAC(t *testing.T, alg string, key []byte, signingInput string) string {
	t.Helper()
	var mac []byte
	switch alg {
	case "HS256":
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(signingInput))
		mac = h.Sum(nil)
	case "HS384":
		h := hmac.New(sha512.New384, key)
		_, _ = h.Write([]byte(signingInput))
		mac = h.Sum(nil)
	case "HS512":
		h := hmac.New(sha512.New, key)
		_, _ = h.Write([]byte(signingInput))
		mac = h.Sum(nil)
	case "none":
		mac = nil
	default:
		// An asymmetric alg smuggled into the MAC field: keep an HS256 MAC so the
		// only thing wrong is the advertised algorithm.
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(signingInput))
		mac = h.Sum(nil)
	}
	return b64(mac)
}

// registerEAB posts a newAccount carrying the given externalAccountBinding.
// A nil eab omits the field, modelling a client that ignores the requirement.
func (rc *rawClient) registerEAB(eab json.RawMessage) (*http.Response, []byte) {
	rc.t.Helper()
	req := map[string]any{"termsOfServiceAgreed": true}
	if eab != nil {
		req["externalAccountBinding"] = eab
	}
	payload, err := json.Marshal(req)
	if err != nil {
		rc.t.Fatalf("marshal newAccount payload: %v", err)
	}
	resp, body := rc.post(rc.dir.NewAccount, payload, true)
	if loc := resp.Header.Get("Location"); loc != "" {
		rc.kid = loc
	}
	return resp, body
}

// accountJWK renders the client's account public key as a JWK, hand-built from
// the raw EC coordinates so the EAB payload does not depend on the server's own
// serialization.
func (rc *rawClient) accountJWK() []byte {
	rc.t.Helper()
	pub := rc.key.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y)}
	b, err := json.Marshal(jwk)
	if err != nil {
		rc.t.Fatalf("marshal account JWK: %v", err)
	}
	return b
}

// ---- verifyEAB rejections -------------------------------------------------

// TestACME_EAB_Rejections walks every way an External Account Binding can fail
// and asserts the account is refused. Each case uses a fresh account key, and
// each asserts the negative outcome twice: the HTTP response is a problem
// document with the expected ACME error type, and no account row was persisted
// for that key. An implementation that accepted any of these would let a client
// without valid operator credentials — or with credentials bound to a different
// account key or a different endpoint — register.
func TestACME_EAB_Rejections(t *testing.T) {
	env := newTestEnv(t, withEAB)

	cases := []struct {
		name string
		// build returns the externalAccountBinding value to send. A nil return
		// omits the field.
		build      func(t *testing.T, rc *rawClient, newAccountURL string) json.RawMessage
		wantStatus int
		wantType   string
	}{
		{
			name: "missing-binding",
			build: func(*testing.T, *rawClient, string) json.RawMessage {
				return nil
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probExternalBinding,
		},
		{
			name: "empty-object",
			build: func(*testing.T, *rawClient, string) json.RawMessage {
				return json.RawMessage(`{}`)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "unknown-kid",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", "no-such-kid", u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "empty-kid",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", "", u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "wrong-mac-key",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", eabGoodKID, u, eabOtherKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "mac-key-of-another-kid",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// A genuine credential for kid-padded, presented under kid-good.
				return buildEAB(t, "HS256", eabGoodKID, u, eabPaddedKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "mac-over-a-different-payload",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// The MAC covers the right protected header but the *old* payload,
				// while a different payload is transmitted.
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				p.payload = b64([]byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`))
				return p.raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "mac-over-a-different-protected-header",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// Signature computed over the correct header, then the header swapped
				// for another (still naming a configured kid).
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				swapped := b64([]byte(`{"alg":"HS256","kid":"` + eabGoodKID + `","url":"` + u + `","extra":1}`))
				p.protected = &swapped
				return p.raw()
			},
			wantStatus: http.StatusUnauthorized,
			wantType:   probUnauthorized,
		},
		{
			name: "url-claim-for-another-endpoint",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// A correctly-MAC'd binding intended for a different ACME server.
				return buildEAB(t, "HS256", eabGoodKID, "https://other.example.test/acme/new-account",
					eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "url-claim-for-another-resource-same-host",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", eabGoodKID, u+"-not-really", eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			// RFC 8555 §7.3.4 makes "url" mandatory in the EAB protected header. A
			// binding with no url is bound to no endpoint at all, so accepting it
			// would silently discard the endpoint binding the field exists to give.
			name: "url-claim-absent",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				hdr, err := json.Marshal(map[string]any{"alg": "HS256", "kid": eabGoodKID})
				if err != nil {
					t.Fatalf("marshal protected header: %v", err)
				}
				prot := b64(hdr)
				pl := b64(rc.accountJWK())
				return eabParts{protected: &prot, payload: pl,
					signature: eabMAC(t, "HS256", eabGoodKey, prot+"."+pl)}.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "url-claim-empty",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", eabGoodKID, "", eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "url-claim-wrong-type",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				hdr, err := json.Marshal(map[string]any{"alg": "HS256", "kid": eabGoodKID, "url": 42})
				if err != nil {
					t.Fatalf("marshal protected header: %v", err)
				}
				prot := b64(hdr)
				pl := b64(rc.accountJWK())
				return eabParts{protected: &prot, payload: pl,
					signature: eabMAC(t, "HS256", eabGoodKey, prot+"."+pl)}.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "alg-none",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "none", eabGoodKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "alg-asymmetric-smuggled-into-mac-field",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// "RS256" with an HMAC over the account key: if the server honored the
				// advertised alg it would try to verify an RSA signature with the HMAC
				// secret as the key.
				return buildEAB(t, "RS256", eabGoodKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "alg-es256-smuggled-into-mac-field",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "ES256", eabGoodKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "alg-hs512-not-accepted",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// A structurally valid HS512 binding: the server pins HS256.
				return buildEAB(t, "HS512", eabGoodKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "alg-hs384-not-accepted",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS384", eabGoodKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "protected-header-missing",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				p.protected = nil
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "protected-header-empty-string",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				empty := ""
				p.protected = &empty
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "protected-header-empty-object",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				empty := b64([]byte(`{}`))
				p.protected = &empty
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "payload-binds-a-different-account-key",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// THE binding property: a perfectly valid operator credential over
				// somebody else's account key must not authorize *this* key.
				victim := newRawClient(t, env.dirURL)
				return buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, victim.accountJWK()).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "payload-is-not-a-jwk",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, []byte(`{"hello":"world"}`)).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "payload-empty",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				return buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, nil).raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "signature-not-base64url",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				p.signature = "!!!not-base64!!!"
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "signature-standard-base64",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// A MAC encoded with the standard (+/ and =) alphabet is not a valid
				// JWS signature and must not be accepted.
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				sig, err := base64.RawURLEncoding.DecodeString(p.signature)
				if err != nil {
					t.Fatalf("decoding fixture signature: %v", err)
				}
				p.signature = base64.StdEncoding.EncodeToString(sig)
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "payload-not-base64url",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				p.payload = "###"
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "protected-not-base64url",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				p := buildEAB(t, "HS256", eabGoodKID, u, eabGoodKey, rc.accountJWK())
				bad := "@@@"
				p.protected = &bad
				return p.raw()
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "binding-is-a-json-string",
			build: func(*testing.T, *rawClient, string) json.RawMessage {
				return json.RawMessage(`"not-a-jws"`)
			},
			wantStatus: http.StatusBadRequest,
			wantType:   probMalformed,
		},
		{
			name: "server-side-key-unusable",
			build: func(t *testing.T, rc *rawClient, u string) json.RawMessage {
				// The kid exists but its configured key decodes in neither encoding:
				// that is a server misconfiguration, and it must fail closed.
				return buildEAB(t, "HS256", eabBrokenKID, u, eabGoodKey, rc.accountJWK()).raw()
			},
			wantStatus: http.StatusInternalServerError,
			wantType:   probServerInternal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRawClient(t, env.dirURL)
			resp, body := rc.registerEAB(tc.build(t, rc, rc.dir.NewAccount))
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("newAccount status = %d, want %d: %s", resp.StatusCode, tc.wantStatus, body)
			}
			var prob Problem
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatalf("response is not a problem document: %v (%s)", err, body)
			}
			if prob.Type != tc.wantType {
				t.Errorf("problem type = %q, want %q: %s", prob.Type, tc.wantType, body)
			}
			// Nothing may have been persisted for this account key.
			if acct, err := env.db.GetACMEAccountByThumbprint(rc.thumbprint()); err != nil {
				t.Fatalf("GetACMEAccountByThumbprint: %v", err)
			} else if acct != nil {
				t.Errorf("an account (%s) was created despite a rejected EAB", acct.ID)
			}
		})
	}
}

// TestACME_EAB_Accepts confirms a correctly-constructed binding registers the
// account and records which operator credential authorized it, for both accepted
// config encodings of the HMAC key.
func TestACME_EAB_Accepts(t *testing.T) {
	env := newTestEnv(t, withEAB)

	for _, tc := range []struct {
		name   string
		kid    string
		macKey []byte
	}{
		{"raw-base64url-config-key", eabGoodKID, eabGoodKey},
		{"padded-standard-base64-config-key", eabPaddedKID, eabPaddedKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRawClient(t, env.dirURL)
			eab := buildEAB(t, "HS256", tc.kid, rc.dir.NewAccount, tc.macKey, rc.accountJWK()).raw()
			resp, body := rc.registerEAB(eab)
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("newAccount status = %d, want 201: %s", resp.StatusCode, body)
			}
			if rc.kid == "" {
				t.Fatal("newAccount returned no Location (account URL)")
			}
			acct, err := env.db.GetACMEAccount(idFromURL(rc.kid))
			if err != nil || acct == nil {
				t.Fatalf("GetACMEAccount: %v", err)
			}
			if acct.EABKid != tc.kid {
				t.Errorf("persisted EABKid = %q, want %q", acct.EABKid, tc.kid)
			}
			if acct.Thumbprint != rc.thumbprint() {
				t.Errorf("persisted thumbprint = %q, want the account key's %q", acct.Thumbprint, rc.thumbprint())
			}
			// The account is usable, i.e. the binding really did register this key.
			if r, b := rc.post(rc.kid, nil, false); r.StatusCode != http.StatusOK {
				t.Fatalf("POST-as-GET on the new account = %d, want 200: %s", r.StatusCode, b)
			}
		})
	}
}

// TestACME_EAB_DirectoryAdvertisesRequirement confirms a client can discover the
// requirement (RFC 8555 §7.1.1 meta.externalAccountRequired) instead of having to
// guess from a rejection.
func TestACME_EAB_DirectoryAdvertisesRequirement(t *testing.T) {
	env := newTestEnv(t, withEAB)
	resp, err := http.Get(env.dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var dir struct {
		Meta struct {
			ExternalAccountRequired bool `json:"externalAccountRequired"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if !dir.Meta.ExternalAccountRequired {
		t.Error("directory meta.externalAccountRequired = false with RequireEAB set")
	}
}

// TestACME_EAB_NotRequiredWhenDisabled confirms the gate is scoped to the
// RequireEAB setting: with EAB off, registration proceeds without a binding (and
// no EAB kid is recorded), so the tests above are really exercising the gate
// rather than some unrelated rejection.
func TestACME_EAB_NotRequiredWhenDisabled(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	resp, body := rc.registerEAB(nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount without EAB = %d, want 201: %s", resp.StatusCode, body)
	}
	acct, err := env.db.GetACMEAccount(idFromURL(rc.kid))
	if err != nil || acct == nil {
		t.Fatalf("GetACMEAccount: %v", err)
	}
	if acct.EABKid != "" {
		t.Errorf("EABKid = %q, want empty when EAB is not required", acct.EABKid)
	}
}

// TestACME_EAB_ReplayAcrossAccountKeys is the end-to-end form of the binding
// property: a complete, previously-accepted EAB blob captured off the wire must
// not let a *second*, attacker-held account key register. Only the account key
// named inside the binding may use it.
func TestACME_EAB_ReplayAcrossAccountKeys(t *testing.T) {
	env := newTestEnv(t, withEAB)

	victim := newRawClient(t, env.dirURL)
	eab := buildEAB(t, "HS256", eabGoodKID, victim.dir.NewAccount, eabGoodKey, victim.accountJWK()).raw()
	if resp, body := victim.registerEAB(eab); resp.StatusCode != http.StatusCreated {
		t.Fatalf("victim newAccount = %d, want 201: %s", resp.StatusCode, body)
	}

	// The attacker holds the captured binding but a different account key.
	attacker := newRawClient(t, env.dirURL)
	resp, body := attacker.registerEAB(eab)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed EAB under a different account key = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	_ = json.Unmarshal(body, &prob)
	if prob.Type != probMalformed {
		t.Errorf("problem type = %q, want %q: %s", prob.Type, probMalformed, body)
	}
	if !strings.Contains(prob.Detail, "account key") {
		t.Errorf("problem detail %q does not explain the key mismatch", prob.Detail)
	}
	if acct, _ := env.db.GetACMEAccountByThumbprint(attacker.thumbprint()); acct != nil {
		t.Errorf("attacker account %s was created from a replayed EAB", acct.ID)
	}
}
