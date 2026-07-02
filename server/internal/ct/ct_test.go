package ct

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// mockLog is an in-process RFC 6962 log used for testing. It signs SCTs with an
// ECDSA key over the precertificate entry exactly as a real log would, so the
// SCTs it returns verify against the same code paths a relying party uses.
type mockLog struct {
	key    *ecdsa.PrivateKey
	issuer *x509.Certificate

	mu        sync.Mutex
	calls     int
	failFirst int  // fail this many initial requests (exercise retries)
	alwaysErr bool // always return an error (exercise failure policy)
}

func (m *mockLog) logID() [32]byte {
	spki, _ := x509.MarshalPKIXPublicKey(m.key.Public())
	return sha256.Sum256(spki)
}

func (m *mockLog) publicKeyPEM(t *testing.T) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(m.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
}

func (m *mockLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	n := m.calls
	m.mu.Unlock()

	if m.alwaysErr || n <= m.failFirst {
		http.Error(w, "log unavailable", http.StatusInternalServerError)
		return
	}

	var req addPreChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Chain) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	precertDER, err := base64.StdEncoding.DecodeString(req.Chain[0])
	if err != nil {
		http.Error(w, "bad precert", http.StatusBadRequest)
		return
	}
	tbs, err := TBSWithoutExtension(precertDER, OIDPoison)
	if err != nil {
		http.Error(w, "cannot parse precert", http.StatusBadRequest)
		return
	}

	const timestamp = uint64(1_600_000_000_000)
	ikh := sha256.Sum256(m.issuer.RawSubjectPublicKeyInfo)

	var b cryptobyte.Builder
	b.AddUint8(0)          // version v1
	b.AddUint8(0)          // signature_type = certificate_timestamp
	b.AddUint64(timestamp) //
	b.AddUint16(1)         // entry_type = precert_entry
	b.AddBytes(ikh[:])     // issuer_key_hash
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {}) // empty extensions
	input, err := b.Bytes()
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(input)
	sig, err := ecdsa.SignASN1(rand.Reader, m.key, digest[:])
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}

	var sb cryptobyte.Builder
	sb.AddUint8(hashAlgSHA256)
	sb.AddUint8(sigAlgECDSA)
	sb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	dsBytes, _ := sb.Bytes()

	id := m.logID()
	resp := addChainResponse{
		SCTVersion: 0,
		ID:         base64.StdEncoding.EncodeToString(id[:]),
		Timestamp:  timestamp,
		Signature:  base64.StdEncoding.EncodeToString(dsBytes),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// newMockLog builds a mock log signing under the given issuer.
func newMockLog(t *testing.T, issuer *x509.Certificate) *mockLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mockLog{key: key, issuer: issuer}
}

// testCA builds a self-signed CA certificate and its signer.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CT Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// buildLeaf builds a leaf certificate under the CA carrying the given extra
// extension (poison for a precertificate, SCT list for a final certificate),
// returning its DER. The serial, subject, validity, and — critically — the leaf
// public key are held fixed by the caller so a precertificate and its final
// certificate differ only in the trailing extension, as required for the
// embedded SCTs to verify.
func buildLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafPub interface{}, serial *big.Int, extra pkix.Extension) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:    serial,
		Subject:         pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:        []string{"leaf.example.com", "www.example.com"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(12 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{extra},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newLeafKey returns a fresh leaf key whose public half is reused across the
// precertificate and final certificate of one issuance.
func newLeafKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestSubmitEmbedAndVerify is the end-to-end proof: submit a precertificate to
// two logs, embed the returned SCTs in a final certificate, then verify each
// embedded SCT the way a relying party would — by reconstructing the TBS from
// the final certificate with the SCT list removed. It also asserts the poison
// extension never reaches the final certificate.
func TestSubmitEmbedAndVerify(t *testing.T) {
	caCert, caKey := testCA(t)
	log1 := newMockLog(t, caCert)
	log2 := newMockLog(t, caCert)
	srv1 := httptest.NewServer(log1)
	defer srv1.Close()
	srv2 := httptest.NewServer(log2)
	defer srv2.Close()

	sub, err := NewSubmitter([]LogConfig{
		{Name: "log1", URL: srv1.URL, PublicKeyPEM: log1.publicKeyPEM(t)},
		{Name: "log2", URL: srv2.URL, PublicKeyPEM: log2.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}

	serial := big.NewInt(0x1122334455)
	leafKey := newLeafKey(t)
	precertDER := buildLeaf(t, caCert, caKey, leafKey.Public(), serial, PoisonExtension())

	res, err := sub.Submit(context.Background(), SubmitRequest{
		PrecertDER:     precertDER,
		Issuer:         caCert,
		IssuerChainDER: [][]byte{caCert.Raw},
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(res.SCTs) != 2 {
		t.Fatalf("got %d SCTs, want 2 (results: %+v)", len(res.SCTs), res.Results)
	}

	// Embed the SCTs into a final certificate (poison replaced by SCT list).
	sctExt, err := SCTListExtension(res.SCTs)
	if err != nil {
		t.Fatalf("SCTListExtension: %v", err)
	}
	finalDER := buildLeaf(t, caCert, caKey, leafKey.Public(), serial, sctExt)
	finalCert, err := x509.ParseCertificate(finalDER)
	if err != nil {
		t.Fatalf("parsing final cert: %v", err)
	}

	// Poison must be gone; SCT list must be present.
	if hasExtension(finalCert, OIDPoison) {
		t.Error("final certificate still carries the poison extension")
	}
	var sctExtValue []byte
	for _, e := range finalCert.Extensions {
		if e.Id.Equal(OIDSCTList) {
			sctExtValue = e.Value
		}
	}
	if sctExtValue == nil {
		t.Fatal("final certificate is missing the SCT list extension")
	}

	// Relying-party verification: reconstruct the signed TBS from the FINAL
	// certificate (SCT list removed) and verify every embedded SCT against it.
	tbs, err := TBSWithoutExtension(finalDER, OIDSCTList)
	if err != nil {
		t.Fatalf("reconstructing TBS from final cert: %v", err)
	}
	scts, err := ParseSCTListExtension(sctExtValue)
	if err != nil {
		t.Fatalf("ParseSCTListExtension: %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("parsed %d embedded SCTs, want 2", len(scts))
	}
	keysByID := map[[32]byte]*ecdsa.PublicKey{
		log1.logID(): &log1.key.PublicKey,
		log2.logID(): &log2.key.PublicKey,
	}
	for i, sct := range scts {
		pub, ok := keysByID[sct.LogID]
		if !ok {
			t.Fatalf("SCT %d has an unknown log id", i)
		}
		if err := sct.Verify(pub, caCert, tbs); err != nil {
			t.Errorf("embedded SCT %d failed verification: %v", i, err)
		}
	}
}

// TestSubmitRejectsTamperedSCT ensures signature verification actually rejects a
// forged/altered SCT rather than accepting it on count alone.
func TestSubmitRejectsTamperedSCT(t *testing.T) {
	caCert, caKey := testCA(t)
	log1 := newMockLog(t, caCert)
	srv := httptest.NewServer(log1)
	defer srv.Close()

	// Configure the submitter with a DIFFERENT (wrong) key for the log, so the
	// genuine SCT signature will not verify.
	wrong := newMockLog(t, caCert)
	sub, err := NewSubmitter([]LogConfig{
		{Name: "log1", URL: srv.URL, PublicKeyPEM: wrong.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}

	precertDER := buildLeaf(t, caCert, caKey, newLeafKey(t).Public(), big.NewInt(99), PoisonExtension())
	res, err := sub.Submit(context.Background(), SubmitRequest{
		PrecertDER: precertDER, Issuer: caCert, IssuerChainDER: [][]byte{caCert.Raw},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(res.SCTs) != 0 {
		t.Fatalf("got %d SCTs, want 0 (a mismatched-key SCT must be rejected)", len(res.SCTs))
	}
	// But the mismatch is a wrong-key error, not a log-id mismatch.
	if len(res.Results) != 1 || res.Results[0].OK {
		t.Fatalf("expected one failed result, got %+v", res.Results)
	}
}

// TestSubmitRetries confirms a transient log failure is retried and eventually
// succeeds within the retry budget.
func TestSubmitRetries(t *testing.T) {
	caCert, caKey := testCA(t)
	log1 := newMockLog(t, caCert)
	log1.failFirst = 2 // fail twice, succeed on the third attempt
	srv := httptest.NewServer(log1)
	defer srv.Close()

	sub, err := NewSubmitter([]LogConfig{
		{Name: "log1", URL: srv.URL, PublicKeyPEM: log1.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	precertDER := buildLeaf(t, caCert, caKey, newLeafKey(t).Public(), big.NewInt(7), PoisonExtension())

	res, err := sub.Submit(context.Background(), SubmitRequest{
		PrecertDER: precertDER, Issuer: caCert, IssuerChainDER: [][]byte{caCert.Raw},
		Timeout: 5 * time.Second, Retries: 3,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(res.SCTs) != 1 {
		t.Fatalf("got %d SCTs, want 1 after retries (results: %+v)", len(res.SCTs), res.Results)
	}
}

// TestSubmitUnknownLog verifies that referencing an unregistered log is a hard
// error (operator misconfiguration), not silently ignored.
func TestSubmitUnknownLog(t *testing.T) {
	caCert, caKey := testCA(t)
	sub, err := NewSubmitter(nil, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	precertDER := buildLeaf(t, caCert, caKey, newLeafKey(t).Public(), big.NewInt(3), PoisonExtension())
	if _, err := sub.Submit(context.Background(), SubmitRequest{
		Logs: []string{"nope"}, PrecertDER: precertDER, Issuer: caCert,
	}); err == nil {
		t.Fatal("expected an error submitting to an unknown log")
	}
}

func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}
