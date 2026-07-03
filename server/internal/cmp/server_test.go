//go:build sqlite

package cmp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

const (
	testReference = "device-fleet-1"
	testSecret    = "correct horse battery staple"
)

func softwareProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	p, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func pkcs11Provider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run eval \"$(scripts/setup-softhsm.sh --export-env)\"")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: module,
			Pin:        pin,
			TokenLabel: token,
		},
	})
	if err != nil {
		t.Fatalf("pkcs11 provider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "cmptest-" + base + "-" + hex.EncodeToString(b[:])
}

// testEnv holds a CMP server wired to a fresh CA over the given provider.
type testEnv struct {
	srv      *Server
	db       *database.DB
	rootCert *x509.Certificate
}

func newTestEnv(t *testing.T, provider keyprovider.Provider) *testEnv {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "cmp-test.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    uniqueLabel(t, "root"),
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "CMP Test Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert, err := pki.ParseCertificatePEM([]byte(root.Certificate))
	if err != nil {
		t.Fatalf("parsing root cert: %v", err)
	}

	srv := New(db, provider, Config{
		CAID:    root.ID,
		Profile: "client",
		Secrets: []Secret{{Reference: testReference, Secret: testSecret, Profile: "client"}},
	})
	return &testEnv{srv: srv, db: db, rootCert: rootCert}
}

// post drives one PKIMessage exchange through the HTTP handler.
func (e *testEnv) post(t *testing.T, reqDER []byte) []byte {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, e.srv.cfg.Path, bytes.NewReader(reqDER))
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	e.srv.handle(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != contentType {
		t.Errorf("response Content-Type = %q, want %q", got, contentType)
	}
	return w.Body.Bytes()
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// enroll performs an ir enrollment and returns the issued certificate and key.
func (e *testEnv) enroll(t *testing.T, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := newKey(t)
	reqDER, err := BuildInitializationRequest(testReference, testSecret,
		pkix.Name{CommonName: cn}, key, RequestOptions{DNSNames: []string{cn}})
	if err != nil {
		t.Fatalf("BuildInitializationRequest: %v", err)
	}
	res, err := ParseResponse(e.post(t, reqDER))
	if err != nil {
		t.Fatalf("ParseResponse(ir): %v", err)
	}
	if res.BodyTag != bodyIP {
		t.Fatalf("response body = %d, want ip (%d): %s", res.BodyTag, bodyIP, res.StatusText)
	}
	if !res.Accepted() || res.Certificate == nil {
		t.Fatalf("ir not accepted (status=%d %q)", res.Status, res.StatusText)
	}
	if err := res.Certificate.CheckSignatureFrom(e.rootCert); err != nil {
		t.Fatalf("issued cert not signed by CA: %v", err)
	}
	return res.Certificate, key
}

func TestCMPFlows(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			env := newTestEnv(t, mk(t))
			t.Run("ir", func(t *testing.T) { testIR(t, env) })
			t.Run("kur", func(t *testing.T) { testKUR(t, env) })
			t.Run("rr", func(t *testing.T) { testRR(t, env) })
			t.Run("bad_secret", func(t *testing.T) { testBadSecret(t, env) })
			t.Run("unknown_reference", func(t *testing.T) { testUnknownReference(t, env) })
		})
	}
}

// testIR covers the initialization-request happy path.
func testIR(t *testing.T, env *testEnv) {
	cert, key := env.enroll(t, "ir-device.example.com")
	if cert.Subject.CommonName != "ir-device.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	// The issued certificate must bind the requested public key.
	pub := cert.PublicKey.(*ecdsa.PublicKey)
	kpub := key.Public().(*ecdsa.PublicKey)
	if pub.X.Cmp(kpub.X) != 0 || pub.Y.Cmp(kpub.Y) != 0 {
		t.Error("issued certificate does not bind the requested key")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "ir-device.example.com" {
		t.Errorf("DNS SANs = %v", cert.DNSNames)
	}
	// It must be recorded for renewal/revocation.
	if rec, err := env.db.GetIssuedCertificate(env.srv.cfg.CAID, cert.SerialNumber.String()); err != nil || rec == nil {
		t.Fatalf("issued certificate not recorded: rec=%v err=%v", rec, err)
	}
}

// testKUR covers the key-update happy path: an existing certificate's key signs
// the request, which rekeys to a fresh key.
func testKUR(t *testing.T, env *testEnv) {
	oldCert, oldKey := env.enroll(t, "kur-device.example.com")
	newKeyPair := newKey(t)

	reqDER, err := BuildKeyUpdateRequest(oldCert, oldKey, oldCert.Subject, newKeyPair, RequestOptions{})
	if err != nil {
		t.Fatalf("BuildKeyUpdateRequest: %v", err)
	}
	respDER := env.post(t, reqDER)

	res, err := ParseResponse(respDER)
	if err != nil {
		t.Fatalf("ParseResponse(kur): %v", err)
	}
	if res.BodyTag != bodyKUP {
		t.Fatalf("response body = %d, want kup (%d): %s", res.BodyTag, bodyKUP, res.StatusText)
	}
	if !res.Accepted() || res.Certificate == nil {
		t.Fatalf("kur not accepted (status=%d %q)", res.Status, res.StatusText)
	}
	// The new certificate must bind the new key and keep the subject.
	pub := res.Certificate.PublicKey.(*ecdsa.PublicKey)
	if pub.X.Cmp(newKeyPair.X) != 0 {
		t.Error("kur certificate does not bind the new key")
	}
	if res.Certificate.Subject.CommonName != oldCert.Subject.CommonName {
		t.Errorf("kur subject CN = %q, want %q", res.Certificate.Subject.CommonName, oldCert.Subject.CommonName)
	}
	if res.Certificate.SerialNumber.Cmp(oldCert.SerialNumber) == 0 {
		t.Error("kur reused the prior serial number")
	}

	// The kur response is signed by the CA: its protection must verify against
	// the CA certificate.
	msg, err := parseMessage(respDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignatureProtection(env.rootCert, msg); err != nil {
		t.Errorf("kur response protection did not verify against the CA: %v", err)
	}
}

// testRR covers revocation-request self-revocation via signature protection.
func testRR(t *testing.T, env *testEnv) {
	cert, key := env.enroll(t, "rr-device.example.com")

	reqDER, err := BuildRevocationRequest(cert, key, RequestOptions{})
	if err != nil {
		t.Fatalf("BuildRevocationRequest: %v", err)
	}
	res, err := ParseResponse(env.post(t, reqDER))
	if err != nil {
		t.Fatalf("ParseResponse(rr): %v", err)
	}
	if res.BodyTag != bodyRP {
		t.Fatalf("response body = %d, want rp (%d): %s", res.BodyTag, bodyRP, res.StatusText)
	}
	if !res.Accepted() {
		t.Fatalf("rr not accepted (status=%d %q)", res.Status, res.StatusText)
	}
	// The certificate must now be revoked in the store.
	revoked, err := env.db.GetRevokedCertificate(env.srv.cfg.CAID, cert.SerialNumber.String())
	if err != nil || revoked == nil {
		t.Fatalf("certificate not revoked: revoked=%v err=%v", revoked, err)
	}
}

// testBadSecret confirms MAC-verification failure is reported as a protocol
// error, not an issued certificate.
func testBadSecret(t *testing.T, env *testEnv) {
	key := newKey(t)
	reqDER, err := BuildInitializationRequest(testReference, "not-the-secret",
		pkix.Name{CommonName: "attacker.example.com"}, key, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseResponse(env.post(t, reqDER))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.BodyTag != bodyError {
		t.Fatalf("response body = %d, want error (%d)", res.BodyTag, bodyError)
	}
	if res.Status != statusRejection {
		t.Errorf("status = %d, want rejection (%d)", res.Status, statusRejection)
	}
	if res.Certificate != nil {
		t.Error("a certificate was issued despite a bad MAC")
	}
}

// testUnknownReference confirms an unknown senderKID is rejected.
func testUnknownReference(t *testing.T, env *testEnv) {
	key := newKey(t)
	reqDER, err := BuildInitializationRequest("no-such-reference", testSecret,
		pkix.Name{CommonName: "ghost.example.com"}, key, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ParseResponse(env.post(t, reqDER))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.BodyTag != bodyError || res.Status != statusRejection {
		t.Fatalf("unknown reference not rejected: body=%d status=%d", res.BodyTag, res.Status)
	}
}
