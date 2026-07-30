//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ctMockLog is an in-process RFC 6962 log for the CA-layer issuance tests. It
// signs SCTs with an ECDSA key over the precertificate entry, mirroring a real
// log so the SCTs embedded by the issuance path verify.
type ctMockLog struct {
	key *ecdsa.PrivateKey

	mu        sync.Mutex
	calls     int
	alwaysErr bool
}

func newCTMockLog(t *testing.T) *ctMockLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &ctMockLog{key: key}
}

func (m *ctMockLog) publicKeyPEM(t *testing.T) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(m.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
}

func (m *ctMockLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if m.alwaysErr {
		http.Error(w, "log unavailable", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Chain []string `json:"chain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Chain) < 2 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	precertDER, _ := base64.StdEncoding.DecodeString(req.Chain[0])
	issuerDER, _ := base64.StdEncoding.DecodeString(req.Chain[1])
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		http.Error(w, "bad issuer", http.StatusBadRequest)
		return
	}
	tbs, err := ct.TBSWithoutExtension(precertDER, ct.OIDPoison)
	if err != nil {
		http.Error(w, "bad precert", http.StatusBadRequest)
		return
	}

	const timestamp = uint64(1_600_000_000_000)
	ikh := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint8(0)
	b.AddUint64(timestamp)
	b.AddUint16(1)
	b.AddBytes(ikh[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {})
	input, _ := b.Bytes()
	digest := sha256.Sum256(input)
	sig, _ := ecdsa.SignASN1(rand.Reader, m.key, digest[:])

	var sb cryptobyte.Builder
	sb.AddUint8(4) // sha256
	sb.AddUint8(3) // ecdsa
	sb.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	dsBytes, _ := sb.Bytes()

	spki, _ := x509.MarshalPKIXPublicKey(m.key.Public())
	id := sha256.Sum256(spki)
	resp := map[string]interface{}{
		"sct_version": 0,
		"id":          base64.StdEncoding.EncodeToString(id[:]),
		"timestamp":   timestamp,
		"extensions":  "",
		"signature":   base64.StdEncoding.EncodeToString(dsBytes),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// withCTSubmitter installs a CT submitter and profile set for the duration of a
// test, restoring the previous globals afterwards so tests do not interfere.
func withCTSubmitter(t *testing.T, sub *ct.Submitter, profiles []Profile) {
	t.Helper()
	prevSub := ctSubmitter
	prevProfiles := customProfiles
	SetCTSubmitter(sub)
	if err := SetCustomProfiles(profiles); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() {
		ctSubmitter = prevSub
		customProfiles = prevProfiles
	})
}

// TestIssueWithCTEmbedsAndVerifies issues a certificate under a CT-enabled
// profile against two mock logs and verifies the resulting certificate carries
// a verifiable SCT list (and no poison). It runs against both the software
// provider and — when configured — SoftHSM, so the precertificate and final
// certificate are genuinely signed on the HSM.
func TestIssueWithCTEmbedsAndVerifies(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runCTEmbed(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runCTEmbed(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "ct-embed-"+tag)

	log1 := newCTMockLog(t)
	log2 := newCTMockLog(t)
	srv1 := httptest.NewServer(log1)
	defer srv1.Close()
	srv2 := httptest.NewServer(log2)
	defer srv2.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv1.URL, PublicKeyPEM: log1.publicKeyPEM(t)},
		{Name: "log2", URL: srv2.URL, PublicKeyPEM: log2.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 2, Retries: 2, TimeoutSeconds: 5},
	}})

	csr := makeCSR(t, "ct-leaf.example.com", []string{"ct-leaf.example.com"})
	res, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct"})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	if res.CT == nil || !res.CT.Enabled || !res.CT.Embedded {
		t.Fatalf("CT status not embedded: %+v", res.CT)
	}
	if res.CT.SCTCount != 2 {
		t.Errorf("SCTCount = %d, want 2", res.CT.SCTCount)
	}
	if res.Record.CTStatus != models.CTStatusSubmitted {
		t.Errorf("record CTStatus = %q, want %q", res.Record.CTStatus, models.CTStatusSubmitted)
	}

	cert := res.Certificate
	if hasOID(cert, ct.OIDPoison) {
		t.Error("issued certificate carries the poison extension")
	}
	var sctVal []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(ct.OIDSCTList) {
			sctVal = e.Value
		}
	}
	if sctVal == nil {
		t.Fatal("issued certificate is missing the SCT list extension")
	}

	// Verify each embedded SCT the way a relying party would.
	tbs, err := ct.TBSWithoutExtension(cert.Raw, ct.OIDSCTList)
	if err != nil {
		t.Fatalf("TBSWithoutExtension: %v", err)
	}
	scts, err := ct.ParseSCTListExtension(sctVal)
	if err != nil {
		t.Fatalf("ParseSCTListExtension: %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("embedded %d SCTs, want 2", len(scts))
	}
	rootCert := mustParse(t, root.Certificate)
	keys := map[[32]byte]*ecdsa.PublicKey{
		logID(log1): &log1.key.PublicKey,
		logID(log2): &log2.key.PublicKey,
	}
	for i, sct := range scts {
		pub, ok := keys[sct.LogID]
		if !ok {
			t.Fatalf("SCT %d from unknown log", i)
		}
		if err := sct.Verify(pub, rootCert, tbs); err != nil {
			t.Errorf("embedded SCT %d failed verification: %v", i, err)
		}
	}

	// The stored record should round-trip the CT status through the database.
	stored, err := mgr.db.GetIssuedCertificate(root.ID, res.Serial.String())
	if err != nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
	if stored.CTStatus != models.CTStatusSubmitted || stored.SCTCount != 2 {
		t.Errorf("stored CT status = %q count=%d, want submitted/2", stored.CTStatus, stored.SCTCount)
	}
}

// TestIssueWithCTFailClosed verifies that when the SCT policy cannot be met and
// the profile is fail-closed, issuance is rejected.
func TestIssueWithCTFailClosed(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ct-closed")

	log1 := newCTMockLog(t)
	log1.alwaysErr = true // log is down
	srv := httptest.NewServer(log1)
	defer srv.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv.URL, PublicKeyPEM: log1.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct-closed",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 1, FailOpen: false, TimeoutSeconds: 2},
	}})

	csr := makeCSR(t, "closed.example.com", nil)
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct-closed"}); err == nil {
		t.Fatal("expected fail-closed issuance to be rejected when the log is down")
	}
}

// TestIssueWithCTFailOpen verifies that when the SCT policy cannot be met but
// the profile is fail-open, issuance proceeds without an SCT list and the status
// is recorded as failed-open.
func TestIssueWithCTFailOpen(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ct-open")

	log1 := newCTMockLog(t)
	log1.alwaysErr = true
	srv := httptest.NewServer(log1)
	defer srv.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv.URL, PublicKeyPEM: log1.publicKeyPEM(t)},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct-open",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 1, FailOpen: true, TimeoutSeconds: 2},
	}})

	csr := makeCSR(t, "open.example.com", nil)
	res, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct-open"})
	if err != nil {
		t.Fatalf("fail-open issuance should succeed: %v", err)
	}
	if res.CT.Embedded {
		t.Error("no SCTs should be embedded when the only log is down")
	}
	if !res.CT.FailedOpen {
		t.Error("CT status should record that fail-open was applied")
	}
	if hasOID(res.Certificate, ct.OIDSCTList) {
		t.Error("no SCT list extension should be present under fail-open with zero SCTs")
	}
	if hasOID(res.Certificate, ct.OIDPoison) {
		t.Error("issued certificate must never carry the poison extension")
	}
	if res.Record.CTStatus != models.CTStatusFailedOpen {
		t.Errorf("record CTStatus = %q, want %q", res.Record.CTStatus, models.CTStatusFailedOpen)
	}
}

// TestIssueWithCTOperatorDiversityPasses issues under a profile requiring SCTs
// from two DISTINCT operators, with two healthy logs run by two different
// operators. Issuance succeeds and the achieved operator count is recorded.
func TestIssueWithCTOperatorDiversityPasses(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ct-ops-pass")

	log1 := newCTMockLog(t)
	log2 := newCTMockLog(t)
	srv1 := httptest.NewServer(log1)
	defer srv1.Close()
	srv2 := httptest.NewServer(log2)
	defer srv2.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv1.URL, PublicKeyPEM: log1.publicKeyPEM(t), Operator: "OperatorA"},
		{Name: "log2", URL: srv2.URL, PublicKeyPEM: log2.publicKeyPEM(t), Operator: "OperatorB"},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct-ops",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 2, MinDistinctOperators: 2, TimeoutSeconds: 5, Retries: 2},
	}})

	csr := makeCSR(t, "ops-pass.example.com", nil)
	res, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct-ops"})
	if err != nil {
		t.Fatalf("diverse issuance should succeed: %v", err)
	}
	if !res.CT.Embedded || res.CT.SCTCount != 2 {
		t.Fatalf("CT status not embedded with 2 SCTs: %+v", res.CT)
	}
	if res.CT.Operators != 2 {
		t.Errorf("CT.Operators = %d, want 2", res.CT.Operators)
	}
	if res.CT.FailedOpen {
		t.Error("policy was met; FailedOpen must be false")
	}
	if res.Record.CTStatus != models.CTStatusSubmitted {
		t.Errorf("record CTStatus = %q, want %q", res.Record.CTStatus, models.CTStatusSubmitted)
	}
}

// TestIssueWithCTOperatorDiversityFailClosed proves that meeting min_scts is not
// enough: two healthy logs that share ONE operator satisfy min_scts=2 but not
// min_distinct_operators=2, so a fail-closed profile rejects issuance even though
// two valid SCTs were obtained.
func TestIssueWithCTOperatorDiversityFailClosed(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ct-ops-closed")

	log1 := newCTMockLog(t)
	log2 := newCTMockLog(t)
	srv1 := httptest.NewServer(log1)
	defer srv1.Close()
	srv2 := httptest.NewServer(log2)
	defer srv2.Close()

	// Both logs are healthy (2 usable SCTs) but run by the SAME operator.
	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv1.URL, PublicKeyPEM: log1.publicKeyPEM(t), Operator: "SoleOperator"},
		{Name: "log2", URL: srv2.URL, PublicKeyPEM: log2.publicKeyPEM(t), Operator: "SoleOperator"},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct-ops-closed",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 2, MinDistinctOperators: 2, FailOpen: false, TimeoutSeconds: 5, Retries: 1},
	}})

	csr := makeCSR(t, "ops-closed.example.com", nil)
	_, err = mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct-ops-closed"})
	if err == nil {
		t.Fatal("expected fail-closed issuance to be rejected when SCTs come from too few operators")
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Errorf("rejection should cite operator diversity, got: %v", err)
	}
}

// TestIssueWithCTOperatorDiversityFailOpen is the fail-open counterpart: the same
// single-operator SCT set does not meet min_distinct_operators, but a fail-open
// profile issues anyway. Because the SCTs WERE obtained, they are still embedded
// (unlike a down-log fail-open), the achieved (insufficient) operator count is
// recorded, and the record is flagged failed_open rather than masked as
// submitted.
func TestIssueWithCTOperatorDiversityFailOpen(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ct-ops-open")

	log1 := newCTMockLog(t)
	log2 := newCTMockLog(t)
	srv1 := httptest.NewServer(log1)
	defer srv1.Close()
	srv2 := httptest.NewServer(log2)
	defer srv2.Close()

	sub, err := ct.NewSubmitter([]ct.LogConfig{
		{Name: "log1", URL: srv1.URL, PublicKeyPEM: log1.publicKeyPEM(t), Operator: "SoleOperator"},
		{Name: "log2", URL: srv2.URL, PublicKeyPEM: log2.publicKeyPEM(t), Operator: "SoleOperator"},
	}, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	withCTSubmitter(t, sub, []Profile{{
		Name:            "server-ct-ops-open",
		KeyUsages:       []string{"digitalSignature"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		CT:              &CTConfig{Enabled: true, MinSCTs: 2, MinDistinctOperators: 2, FailOpen: true, TimeoutSeconds: 5, Retries: 1},
	}})

	csr := makeCSR(t, "ops-open.example.com", nil)
	res, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server-ct-ops-open"})
	if err != nil {
		t.Fatalf("fail-open issuance should succeed: %v", err)
	}
	if !res.CT.Embedded || res.CT.SCTCount != 2 {
		t.Errorf("SCTs were obtained and should be embedded: %+v", res.CT)
	}
	if res.CT.Operators != 1 {
		t.Errorf("CT.Operators = %d, want 1 (both SCTs from one operator)", res.CT.Operators)
	}
	if !res.CT.FailedOpen {
		t.Error("operator-diversity shortfall under fail-open must set FailedOpen")
	}
	if res.Record.CTStatus != models.CTStatusFailedOpen {
		t.Errorf("record CTStatus = %q, want %q", res.Record.CTStatus, models.CTStatusFailedOpen)
	}
	// The SCT list is genuinely embedded even though the policy failed open.
	if !hasOID(res.Certificate, ct.OIDSCTList) {
		t.Error("SCT list extension should be present (SCTs were obtained)")
	}
}

func hasOID(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func logID(m *ctMockLog) [32]byte {
	spki, _ := x509.MarshalPKIXPublicKey(m.key.Public())
	return sha256.Sum256(spki)
}
