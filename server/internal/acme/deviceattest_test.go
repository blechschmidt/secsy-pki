//go:build sqlite

package acme

// Coverage for the device-attest-01 challenge (draft-ietf-acme-device-attest) and
// its base64url decoder. device-attest-01 is unusual among ACME challenges: the
// attestation object IS the proof of possession, so unlike the ordinary
// attestation gate on other enrollment paths it must fail closed even under the
// "permissive" policy mode. These tests pin that down, plus every malformed-input
// path, and assert each denial is recorded as a denied cert.attestation audit
// event rather than silently passing the authorization.

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ---- decodeBase64URL ------------------------------------------------------

// TestDecodeBase64URL pins the accepted encodings. The attestation object arrives
// base64url per the draft; the decoder tolerates the padded form but must refuse
// the standard alphabet ("+" and "/"), whitespace, and any other stray byte,
// because a lenient decoder would silently reshape attacker-controlled bytes
// before they reach the CBOR/WebAuthn parser.
func TestDecodeBase64URL(t *testing.T) {
	const plain = "hello, attestation"
	rawURL := base64.RawURLEncoding.EncodeToString([]byte(plain))
	padURL := base64.URLEncoding.EncodeToString([]byte(plain))

	// Bytes whose base64 encoding differs between the URL and standard alphabets
	// (they produce '-'/'_' vs '+'/'/').
	tricky := []byte{0xfb, 0xff, 0xbf}
	trickyURL := base64.RawURLEncoding.EncodeToString(tricky)
	trickyStd := base64.RawStdEncoding.EncodeToString(tricky)

	t.Run("accepted", func(t *testing.T) {
		for _, tc := range []struct {
			name, in string
			want     string
		}{
			{"raw-base64url", rawURL, plain},
			{"padded-base64url", padURL, plain},
			{"empty", "", ""},
			{"url-alphabet-special-chars", trickyURL, string(tricky)},
			// encoding/base64 ignores CR and LF by design. That is benign — the
			// decoded bytes are unchanged, so no byte smuggling is possible — but
			// assert the exact decoded value so it stays that way.
			{"trailing-newline-ignored-by-stdlib", rawURL + "\n", plain},
			{"embedded-crlf-ignored-by-stdlib", rawURL[:4] + "\r\n" + rawURL[4:], plain},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := decodeBase64URL(tc.in)
				if err != nil {
					t.Fatalf("decodeBase64URL(%q) = error %v, want success", tc.in, err)
				}
				if string(got) != tc.want {
					t.Errorf("decodeBase64URL(%q) = %q, want %q", tc.in, got, tc.want)
				}
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		for _, tc := range []struct{ name, in string }{
			{"standard-alphabet-plus-and-slash", trickyStd},
			{"standard-alphabet-with-padding", base64.StdEncoding.EncodeToString(tricky)},
			{"leading-space", " " + rawURL},
			{"trailing-space", rawURL + " "},
			{"internal-space", rawURL[:4] + " " + rawURL[4:]},
			{"tab", "\t" + rawURL},
			{"invalid-char-bang", "aGVsbG8!"},
			{"invalid-char-hash", "###"},
			{"invalid-char-percent", "%41%42"},
			{"over-padded", "aGVsbG8=="},
			{"truncated-padding", "YQ="},
			{"padding-in-the-middle", "aGV=bG8"},
			{"lone-padding", "="},
			{"single-char-group", "a"},
			{"nul-byte", "aGVs\x00bG8"},
			{"non-ascii", "aGVsbG8é"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got, err := decodeBase64URL(tc.in); err == nil {
					t.Errorf("decodeBase64URL(%q) = %q, nil error; want an error", tc.in, got)
				}
			})
		}
	})
}

// ---- validateDeviceAttest01: policy plumbing ------------------------------

// attestRoots returns a non-empty trust pool, which NewVerifier demands before it
// will accept a "require" policy.
func attestRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	key := newP256(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Device Manufacturer Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// withAttestation enables the device-attest-01 challenge in the given mode.
func withAttestation(t *testing.T, mode attestation.Mode) func(*Config) {
	t.Helper()
	roots := attestRoots(t)
	return func(cfg *Config) {
		v, err := attestation.NewVerifier(attestation.Options{Roots: roots, DefaultMode: mode})
		if err != nil {
			t.Fatalf("NewVerifier(%s): %v", mode, err)
		}
		cfg.Attestation = v
	}
}

// TestDeviceAttest01_NotEnabled covers the guard that refuses the challenge when
// the profile's attestation policy is off (or no verifier is configured at all):
// the challenge should never have been offered, so it must be refused outright
// rather than treated as a pass.
func TestDeviceAttest01_NotEnabled(t *testing.T) {
	env := newTestEnv(t) // no attestation verifier configured
	rc := newRawClient(t, env.dirURL)
	rc.register()
	rec, err := env.db.GetACMEAccount(idFromURL(rc.kid))
	if err != nil || rec == nil {
		t.Fatalf("GetACMEAccount: %v", err)
	}
	acct := &acmeAccount{rec: rec}
	authz := &models.ACMEAuthorization{ID: "authz-off", AccountID: rec.ID,
		IdentifierType: "dns", IdentifierValue: "attest-off.example.test"}
	r := httptest.NewRequest(http.MethodPost, "/acme/chall/whatever", nil)

	prob := env.srv.validateDeviceAttest01(r, acct, authz, []byte(`{"attObj":"AA"}`), "token.thumb")
	if prob == nil {
		t.Fatal("validateDeviceAttest01 accepted a challenge with attestation disabled")
	}
	if prob.Type != probMalformed {
		t.Errorf("problem type = %q, want %q (%s)", prob.Type, probMalformed, prob.Detail)
	}

	// Same when a verifier exists but the profile's mode is off.
	off, err := attestation.NewVerifier(attestation.Options{DefaultMode: attestation.ModeOff})
	if err != nil {
		t.Fatalf("NewVerifier(off): %v", err)
	}
	env.srv.cfg.Attestation = off
	if prob := env.srv.validateDeviceAttest01(r, acct, authz, nil, "token.thumb"); prob == nil {
		t.Fatal("validateDeviceAttest01 accepted a challenge under mode=off")
	} else if prob.Type != probMalformed {
		t.Errorf("mode=off problem type = %q, want %q", prob.Type, probMalformed)
	}
}

// ---- validateDeviceAttest01: end-to-end over the challenge handler --------

// attestChallenge places an order and returns the device-attest-01 challenge URL
// the server offers for it, plus the authorization URL.
func attestChallenge(t *testing.T, rc *rawClient, domain string) (challURL, authzURL string) {
	t.Helper()
	resp, body, ord, _ := rc.newOrder("", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", resp.StatusCode, body)
	}
	if len(ord.Authorizations) != 1 {
		t.Fatalf("order has %d authorizations, want 1: %s", len(ord.Authorizations), body)
	}
	authzURL = ord.Authorizations[0]
	_, ab := rc.post(authzURL, nil, false)
	var az rawAuthz
	if err := json.Unmarshal(ab, &az); err != nil {
		t.Fatalf("decode authz: %v (%s)", err, ab)
	}
	for _, ch := range az.Challenges {
		if ch.Type == models.ACMEChallengeDeviceAttest01 {
			return ch.URL, authzURL
		}
	}
	t.Fatalf("server did not offer a device-attest-01 challenge: %s", ab)
	return "", ""
}

// respondChallenge returns the challenge object after responding with payload.
func respondChallenge(t *testing.T, rc *rawClient, challURL string, payload []byte) struct {
	Status string   `json:"status"`
	Error  *Problem `json:"error"`
} {
	t.Helper()
	resp, body := rc.post(challURL, payload, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge respond status = %d, want 200: %s", resp.StatusCode, body)
	}
	var out struct {
		Status string   `json:"status"`
		Error  *Problem `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode challenge: %v (%s)", err, body)
	}
	return out
}

// TestDeviceAttest01_FailureModes drives every way a device-attest-01 response can
// be rejected, in BOTH policy modes. The permissive cases are the security point:
// for this challenge the attestation object is the only evidence, so "permissive"
// must not degrade into "accept anything" the way it legitimately does on the
// enrollment paths where attestation is merely supplementary.
func TestDeviceAttest01_FailureModes(t *testing.T) {
	garbage := base64.RawURLEncoding.EncodeToString([]byte("this is not a CBOR attestation object"))

	payloads := []struct {
		name    string
		payload []byte
	}{
		{"no-attobj-field", []byte(`{}`)},
		{"empty-attobj", []byte(`{"attObj":""}`)},
		{"attobj-null", []byte(`{"attObj":null}`)},
		{"payload-not-json", []byte("not json at all")},
		{"payload-json-array", []byte(`[1,2,3]`)},
		{"attobj-wrong-type", []byte(`{"attObj":{"nested":true}}`)},
		{"attobj-not-base64url", []byte(`{"attObj":"!!!not-base64!!!"}`)},
		{"attobj-standard-base64", []byte(`{"attObj":"` + base64.StdEncoding.EncodeToString([]byte{0xfb, 0xff, 0xbf}) + `"}`)},
		{"attobj-not-cbor", []byte(`{"attObj":"` + garbage + `"}`)},
		{"attobj-empty-cbor-map", []byte(`{"attObj":"` + base64.RawURLEncoding.EncodeToString([]byte{0xa0}) + `"}`)},
	}

	for _, mode := range []attestation.Mode{attestation.ModeRequire, attestation.ModePermissive} {
		t.Run(string(mode), func(t *testing.T) {
			env := newTestEnv(t, withAttestation(t, mode))
			for _, tc := range payloads {
				t.Run(tc.name, func(t *testing.T) {
					rc := newRawClient(t, env.dirURL)
					rc.register()
					challURL, authzURL := attestChallenge(t, rc, tc.name+".attest.example.test")

					got := respondChallenge(t, rc, challURL, tc.payload)
					if got.Status != "invalid" {
						t.Fatalf("challenge status = %q, want invalid (mode=%s): %+v", got.Status, mode, got)
					}
					if got.Error == nil {
						t.Fatal("invalid challenge carries no error document")
					}
					if got.Error.Type != probBadAttestation {
						t.Errorf("challenge error type = %q, want %q (detail %q)",
							got.Error.Type, probBadAttestation, got.Error.Detail)
					}
					// The authorization must have failed with it — never be left
					// pending or, worse, become valid.
					_, ab := rc.post(authzURL, nil, false)
					var az rawAuthz
					_ = json.Unmarshal(ab, &az)
					if az.Status != "invalid" {
						t.Errorf("authorization status = %q, want invalid: %s", az.Status, ab)
					}
				})
			}

			// Every denial must be on the audit record as a denied cert.attestation
			// event; a silent failure would leave an operator blind to attestation
			// probing.
			events, _, err := env.db.ListEvents(audit.ActionCertAttestation, "", "", 500, 0)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			denied := 0
			for _, e := range events {
				if e.Result == audit.ResultDenied {
					denied++
				}
				if e.Result == audit.ResultSuccess {
					t.Errorf("a cert.attestation success event was recorded although every "+
						"attestation failed: %+v", e)
				}
			}
			if denied < len(payloads) {
				t.Errorf("recorded %d denied cert.attestation events, want at least %d",
					denied, len(payloads))
			}
		})
	}
}

// TestDeviceAttest01_RequireModeOffersOnlyAttestation confirms the policy wiring
// the tests above depend on: under "require" the server must not also offer
// http-01/dns-01/tls-alpn-01, or a client could sidestep hardware attestation by
// solving a network challenge instead.
func TestDeviceAttest01_RequireModeOffersOnlyAttestation(t *testing.T) {
	env := newTestEnv(t, withAttestation(t, attestation.ModeRequire))
	rc := newRawClient(t, env.dirURL)
	rc.register()

	_, _, ord, _ := rc.newOrder("", "only-attest.example.test")
	if len(ord.Authorizations) != 1 {
		t.Fatalf("order has %d authorizations, want 1", len(ord.Authorizations))
	}
	_, ab := rc.post(ord.Authorizations[0], nil, false)
	var az rawAuthz
	if err := json.Unmarshal(ab, &az); err != nil {
		t.Fatalf("decode authz: %v (%s)", err, ab)
	}
	if len(az.Challenges) != 1 || az.Challenges[0].Type != models.ACMEChallengeDeviceAttest01 {
		types := make([]string, 0, len(az.Challenges))
		for _, ch := range az.Challenges {
			types = append(types, ch.Type)
		}
		t.Fatalf("challenges offered under mode=require = %v, want only device-attest-01", types)
	}
}

// TestDeviceAttest01_MalformedAttObjIsNotIssuance is the end-of-the-line
// assertion: an order whose only authorization failed attestation can never be
// finalized into a certificate.
func TestDeviceAttest01_MalformedAttObjIsNotIssuance(t *testing.T) {
	env := newTestEnv(t, withAttestation(t, attestation.ModeRequire))
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "no-issuance.attest.example.test"
	resp, body, ord, _ := rc.newOrder("", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder = %d: %s", resp.StatusCode, body)
	}
	_, ab := rc.post(ord.Authorizations[0], nil, false)
	var az rawAuthz
	_ = json.Unmarshal(ab, &az)
	if len(az.Challenges) == 0 {
		t.Fatalf("no challenges offered: %s", ab)
	}
	if got := respondChallenge(t, rc, az.Challenges[0].URL, []byte(`{"attObj":"AAAA"}`)); got.Status != "invalid" {
		t.Fatalf("challenge status = %q, want invalid", got.Status)
	}

	key := newP256(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr := base64.RawURLEncoding.EncodeToString(csrDER)
	fresp, fbody := rc.post(ord.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode == http.StatusOK {
		t.Fatalf("finalize succeeded for an order whose attestation failed: %s", fbody)
	}
}

// ---- recordAttestFailure --------------------------------------------------

// TestRecordAttestFailure covers the denial recorder directly, including the
// missing-vs-invalid distinction it labels metrics with, and confirms it always
// produces a badAttestationStatement problem with a 403 status.
func TestRecordAttestFailure(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	rec, err := env.db.GetACMEAccount(idFromURL(rc.kid))
	if err != nil || rec == nil {
		t.Fatalf("GetACMEAccount: %v", err)
	}
	acct := &acmeAccount{rec: rec}
	r := httptest.NewRequest(http.MethodPost, "/acme/chall/x", nil)

	for _, tc := range []struct {
		name    string
		missing bool
		authz   *models.ACMEAuthorization
	}{
		{"missing-evidence-order-bound", true,
			&models.ACMEAuthorization{ID: "a1", OrderID: "order-1"}},
		{"invalid-evidence-order-bound", false,
			&models.ACMEAuthorization{ID: "a2", OrderID: "order-2"}},
		{"invalid-evidence-standalone-preauth", false,
			&models.ACMEAuthorization{ID: "a3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail := "deliberate failure: " + tc.name
			prob := env.srv.recordAttestFailure(r, acct, tc.authz, attestation.ModeRequire, tc.missing, detail)
			if prob == nil {
				t.Fatal("recordAttestFailure returned nil; a denial must always be a problem")
			}
			if prob.Type != probBadAttestation {
				t.Errorf("problem type = %q, want %q", prob.Type, probBadAttestation)
			}
			if prob.httpStatus() != http.StatusForbidden {
				t.Errorf("problem status = %d, want 403", prob.httpStatus())
			}
			if prob.Detail == "" {
				t.Error("problem carries no detail")
			}

			events, _, err := env.db.ListEvents(audit.ActionCertAttestation, "", "", 50, 0)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			var found bool
			for _, e := range events {
				if e.Result == audit.ResultDenied && e.Detail == detail && e.Target == authzTarget(tc.authz) {
					found = true
				}
			}
			if !found {
				t.Errorf("no denied cert.attestation audit event for target %q: %+v",
					authzTarget(tc.authz), events)
			}
		})
	}
}

// TestProblemError covers the error interface on Problem, which is how ACME
// problems surface when they flow through ordinary Go error handling.
func TestProblemError(t *testing.T) {
	withDetail := newProblem(probBadAttestation, http.StatusForbidden, "device attestation failed")
	if got, want := withDetail.Error(), probBadAttestation+": device attestation failed"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	bare := &Problem{Type: probUnauthorized}
	if got := bare.Error(); got != probUnauthorized {
		t.Errorf("Error() = %q, want %q", got, probUnauthorized)
	}
	// It really satisfies error.
	var err error = withDetail
	if err.Error() == "" {
		t.Error("Problem does not render as an error")
	}
}
