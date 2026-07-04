//go:build sqlite

// These tests exercise the BRSKI registrar and the built-in MASA end-to-end
// against the software key provider: a synthetic pledge drives the full voucher
// exchange, and the fail-closed policy checks (untrusted IDevID, failed
// proximity/serial assertion) are verified to block. A SoftHSM-backed variant
// that additionally drives the EST handoff to HSM issuance lives in
// internal/e2e/brski_test.go.
package brski

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
)

// harness bundles the actors of a BRSKI exchange with software keys.
type harness struct {
	reg     *Registrar
	clock   func() time.Time
	setTime func(time.Time)

	mfrCert *x509.Certificate // manufacturer root / IDevID trust anchor + MASA anchor
	mfrPool *x509.CertPool

	masaKey  crypto.Signer
	masaCert *x509.Certificate // MASA voucher signer

	regKey  crypto.Signer
	regCert *x509.Certificate // registrar domain identity (pinned)

	idevidKey  crypto.Signer
	idevidCert *x509.Certificate // pledge IDevID
	serial     string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Now()
	current := now
	clock := func() time.Time { return current }
	setTime := func(tm time.Time) { current = tm }

	mfrKey, mfrCert := testCA(t, "Test Manufacturer Root")
	mfrPool := x509.NewCertPool()
	mfrPool.AddCert(mfrCert)

	masaKey, masaCert := issueLeaf(t, "Test MASA", "", mfrKey, mfrCert)
	regKey, regCert := selfSignedIdentity(t, "domain-registrar.example")

	const serial = "PLEDGE-0000-0001"
	idevidKey, idevidCert := issueLeaf(t, "pledge.example", serial, mfrKey, mfrCert)

	db, err := database.New("sqlite", t.TempDir()+"/brski.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	masa, err := NewService(ServiceConfig{
		Signer:      masaKey,
		Cert:        masaCert,
		Chain:       []*x509.Certificate{mfrCert},
		IDevIDRoots: mfrPool,
		Now:         clock,
		Log:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	proximity := true
	reg, err := New(db, Config{
		CAID:             "domain-ca",
		Profile:          "client",
		DomainCert:       regCert,
		RegistrarKey:     regKey,
		RegistrarCert:    regCert,
		IDevIDRoots:      mfrPool,
		MASA:             InProcessMASA{Service: masa},
		RequireProximity: &proximity,
		PledgeTTL:        10 * time.Minute,
		Now:              clock,
	})
	if err != nil {
		t.Fatalf("New registrar: %v", err)
	}

	return &harness{
		reg: reg, clock: clock, setTime: setTime,
		mfrCert: mfrCert, mfrPool: mfrPool,
		masaKey: masaKey, masaCert: masaCert,
		regKey: regKey, regCert: regCert,
		idevidKey: idevidKey, idevidCert: idevidCert, serial: serial,
	}
}

// buildPVR assembles and signs a pledge voucher-request with the IDevID key.
func (h *harness) buildPVR(t *testing.T, nonce []byte, serial string, proximity *x509.Certificate) []byte {
	t.Helper()
	v := &Voucher{
		CreatedOn:    h.clock(),
		Nonce:        nonce,
		SerialNumber: serial,
		Assertion:    AssertionProximity,
	}
	if proximity != nil {
		v.ProximityRegistrarCert = proximity.Raw
	}
	j, err := MarshalVoucherRequest(v)
	if err != nil {
		t.Fatalf("MarshalVoucherRequest: %v", err)
	}
	signed, err := signVoucherCMS(j, h.idevidKey, h.idevidCert, nil)
	if err != nil {
		t.Fatalf("signVoucherCMS: %v", err)
	}
	return signed
}

func (h *harness) postVoucher(pvr []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/.well-known/brski/requestvoucher", bytes.NewReader(pvr))
	rec := httptest.NewRecorder()
	h.reg.handleRequestVoucher(rec, req)
	return rec
}

// TestVoucherExchangeHappyPath drives the full pledge → registrar → MASA → voucher
// flow and checks that the returned voucher is MASA-signed, pins the registrar's
// domain certificate, echoes the nonce, and authorizes the pledge to enroll.
func TestVoucherExchangeHappyPath(t *testing.T) {
	h := newHarness(t)
	nonce := randomBytes(t, 16)
	rec := h.postVoucher(h.buildPVR(t, nonce, h.serial, h.regCert))

	if rec.Code != http.StatusOK {
		t.Fatalf("requestvoucher status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != MediaTypeVoucherCMS {
		t.Fatalf("Content-Type = %q, want %q", ct, MediaTypeVoucherCMS)
	}

	// Pledge-side verification: the voucher must be signed by a certificate that
	// chains to the pre-installed MASA trust anchor.
	sd, content, err := parseSignedVoucherCMS(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("voucher CMS: %v", err)
	}
	if err := verifyCertChain(h.mfrPool, nil, sd.SignerCertificate(), h.clock()); err != nil {
		t.Fatalf("voucher signer does not chain to the MASA anchor: %v", err)
	}
	v, err := ParseVoucher(content)
	if err != nil {
		t.Fatalf("ParseVoucher: %v", err)
	}
	if !bytes.Equal(v.PinnedDomainCert, h.regCert.Raw) {
		t.Fatal("pinned-domain-cert is not the registrar domain certificate the pledge connected to")
	}
	if !bytes.Equal(v.Nonce, nonce) {
		t.Fatal("voucher nonce does not echo the pledge nonce")
	}
	if v.SerialNumber != h.serial {
		t.Fatalf("voucher serial = %q, want %q", v.SerialNumber, h.serial)
	}

	// The pledge is now authorized to EST-enroll under the recorded profile.
	profile, actor, ok := h.reg.AuthorizePledge(h.idevidCert)
	if !ok {
		t.Fatal("pledge should be authorized to enroll after a successful voucher exchange")
	}
	if profile != "client" {
		t.Fatalf("authorized profile = %q, want client", profile)
	}
	if actor == "" {
		t.Fatal("authorized actor label should be set")
	}
}

// TestUntrustedIDevIDRejected verifies that a pledge whose IDevID does not chain
// to a trusted manufacturer root is refused fail-closed.
func TestUntrustedIDevIDRejected(t *testing.T) {
	h := newHarness(t)
	// Re-key the pledge with a self-signed IDevID that no configured root vouches
	// for.
	rogueKey, rogueCert := selfSignedIdentity(t, "rogue.example")
	h.idevidKey, h.idevidCert = rogueKey, rogueCert

	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), "rogue-serial", h.regCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("untrusted IDevID: status = %d, want 403", rec.Code)
	}
	if _, _, ok := h.reg.AuthorizePledge(rogueCert); ok {
		t.Fatal("a refused pledge must not be authorized to enroll")
	}
}

// TestProximityMismatchRejected verifies that a pledge that pinned some other
// certificate (not this registrar's domain certificate) is refused.
func TestProximityMismatchRejected(t *testing.T) {
	h := newHarness(t)
	_, otherCert := selfSignedIdentity(t, "attacker-registrar.example")
	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), h.serial, otherCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("proximity mismatch: status = %d, want 403", rec.Code)
	}
	if _, _, ok := h.reg.AuthorizePledge(h.idevidCert); ok {
		t.Fatal("a proximity-rejected pledge must not be authorized")
	}
}

// TestSerialMismatchRejected verifies that a voucher-request whose asserted
// serial-number disagrees with the IDevID is refused.
func TestSerialMismatchRejected(t *testing.T) {
	h := newHarness(t)
	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), "DIFFERENT-SERIAL", h.regCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("serial mismatch: status = %d, want 403", rec.Code)
	}
}

// TestMissingProximityRejected verifies that a voucher-request lacking any
// proximity-registrar-cert is refused when proximity is required.
func TestMissingProximityRejected(t *testing.T) {
	h := newHarness(t)
	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), h.serial, nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing proximity: status = %d, want 403", rec.Code)
	}
}

// TestMalformedVoucherRequestRejected verifies that a non-CMS body is rejected as
// a bad request, not a policy denial.
func TestMalformedVoucherRequestRejected(t *testing.T) {
	h := newHarness(t)
	rec := h.postVoucher([]byte("this is not a CMS SignedData"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed request: status = %d, want 400", rec.Code)
	}
}

// TestPledgeAuthorizationExpires verifies that the EST-handoff authorization is
// time-bounded: once the TTL elapses the pledge is no longer authorized.
func TestPledgeAuthorizationExpires(t *testing.T) {
	h := newHarness(t)
	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), h.serial, h.regCert))
	if rec.Code != http.StatusOK {
		t.Fatalf("requestvoucher status = %d", rec.Code)
	}
	if _, _, ok := h.reg.AuthorizePledge(h.idevidCert); !ok {
		t.Fatal("pledge should be authorized immediately after bootstrapping")
	}
	// Advance the clock past the pledge TTL (but not past the certificate
	// validity, which spans 24h).
	h.setTime(h.clock().Add(11 * time.Minute))
	if _, _, ok := h.reg.AuthorizePledge(h.idevidCert); ok {
		t.Fatal("pledge authorization should expire after the TTL")
	}
}

// TestStatusTelemetryAccepted verifies that voucher_status and enrollstatus
// reports are accepted and recorded.
func TestStatusTelemetryAccepted(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/voucher_status", "/enrollstatus"} {
		body, _ := json.Marshal(statusReport{Version: "1", Status: true, Reason: "ok"})
		req := httptest.NewRequest(http.MethodPost, "/.well-known/brski"+path, bytes.NewReader(body))
		rec := httptest.NewRecorder()
		switch path {
		case "/voucher_status":
			h.reg.handleVoucherStatus(rec, req)
		case "/enrollstatus":
			h.reg.handleEnrollStatus(rec, req)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
	}
}

// TestVoucherJSONRoundTrip checks the RFC 8366 wrapper key and base64 binary
// encoding survive a marshal/parse round trip for both artifact kinds.
func TestVoucherJSONRoundTrip(t *testing.T) {
	created := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	v := &Voucher{
		CreatedOn:        created,
		Assertion:        AssertionLogged,
		SerialNumber:     "ABC123",
		Nonce:            []byte{1, 2, 3, 4},
		PinnedDomainCert: []byte{5, 6, 7, 8},
		IDevIDIssuer:     []byte{9, 10},
	}
	data, err := MarshalVoucher(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(voucherWrapperKey)) {
		t.Fatalf("voucher JSON missing wrapper key: %s", data)
	}
	got, err := ParseVoucher(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SerialNumber != v.SerialNumber || !bytes.Equal(got.Nonce, v.Nonce) ||
		!bytes.Equal(got.PinnedDomainCert, v.PinnedDomainCert) || !got.CreatedOn.Equal(created) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	// A voucher document must not parse under the voucher-request wrapper key.
	if _, err := ParseVoucherRequest(data); err == nil {
		t.Fatal("voucher parsed under the voucher-request wrapper key; wrappers must be distinct")
	}
}

// TestMASANoncelessVoucher verifies the built-in MASA falls back to an expiring
// voucher when the pledge request carries no nonce.
func TestMASANoncelessVoucher(t *testing.T) {
	h := newHarness(t)
	rec := h.postVoucher(h.buildPVR(t, nil, h.serial, h.regCert))
	if rec.Code != http.StatusOK {
		t.Fatalf("nonceless requestvoucher status = %d, body=%s", rec.Code, rec.Body.String())
	}
	content, err := parseVoucherContent(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseVoucher(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Nonce) != 0 {
		t.Fatal("nonceless request should not yield a nonce in the voucher")
	}
	if v.ExpiresOn == nil {
		t.Fatal("nonceless voucher must carry expires-on")
	}
}

// TestNoncelessMASAAcceptsNoncefulPledge verifies the registrar relays a
// nonceless voucher (expires-on, no echoed nonce) even when the pledge presented
// a nonce: the registrar's coherence check enforces nonce echo only when the
// voucher is itself nonceful, leaving nonceless acceptance to the pledge.
func TestNoncelessMASAAcceptsNoncefulPledge(t *testing.T) {
	h := newHarness(t)
	nonceless, err := NewService(ServiceConfig{
		Signer:      h.masaKey,
		Cert:        h.masaCert,
		Chain:       []*x509.Certificate{h.mfrCert},
		IDevIDRoots: h.mfrPool,
		Nonceless:   true,
		Now:         h.clock,
		Log:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	h.reg.cfg.MASA = InProcessMASA{Service: nonceless}

	rec := h.postVoucher(h.buildPVR(t, randomBytes(t, 16), h.serial, h.regCert))
	if rec.Code != http.StatusOK {
		t.Fatalf("nonceless voucher for a nonceful pledge: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	content, err := parseVoucherContent(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseVoucher(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Nonce) != 0 {
		t.Fatal("nonceless MASA should not echo a nonce")
	}
	if v.ExpiresOn == nil {
		t.Fatal("nonceless voucher must carry expires-on")
	}
}

// ---- certificate helpers --------------------------------------------------

func testCA(t *testing.T, cn string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func issueLeaf(t *testing.T, cn, serialAttr string, caKey crypto.Signer, caCert *x509.Certificate) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: cn, SerialNumber: serialAttr},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func selfSignedIdentity(t *testing.T, cn string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
