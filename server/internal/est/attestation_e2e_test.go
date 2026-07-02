//go:build sqlite

// End-to-end test of the EST enrollment path with the Task 49 hardware
// key-attestation gate active. It stands up the real EST server against the
// software key provider (no HSM required), configures a profile that REQUIRES
// attestation, and checks that:
//
//   - a simpleenroll carrying a valid attestation bundle bound to the CSR key
//     is issued a certificate, and
//   - a simpleenroll with no attestation is rejected fail-closed (HTTP 403),
//     and a hash-chained cert.attestation audit event records the denial.
package est

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// estAttestPKI is a throwaway manufacturer PKI used to sign attestation certs.
type estAttestPKI struct {
	root     *x509.Certificate
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
}

func newESTAttestPKI(t *testing.T) *estAttestPKI {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EST Attest Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := mustCert(t, rootTmpl, rootTmpl, rootKey, &rootKey.PublicKey)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "EST Attest Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	inter := mustCert(t, interTmpl, root, rootKey, &interKey.PublicKey)
	return &estAttestPKI{root: root, inter: inter, interKey: interKey}
}

func (p *estAttestPKI) attestLeaf(t *testing.T, deviceKey crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "Device Attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	return mustCert(t, tmpl, p.inter, p.interKey, deviceKey)
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

func (p *estAttestPKI) verifier(t *testing.T) *attestation.Verifier {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(p.root)
	v, err := attestation.NewVerifier(attestation.Options{
		Roots:         roots,
		Intermediates: []*x509.Certificate{p.inter},
		DefaultMode:   attestation.ModeRequire,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// makeAttestedCSR builds a CSR whose public key is deviceKey and which carries
// an attestation bundle certifying that same key.
func makeAttestedCSR(t *testing.T, deviceKey *ecdsa.PrivateKey, chain []*x509.Certificate) []byte {
	t.Helper()
	var exts []pkix.Extension
	if len(chain) > 0 {
		oid, val, err := attestation.BuildCSRAttestationExtension(chain)
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, pkix.Extension{Id: oid, Value: val})
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "attested-device"},
		ExtraExtensions: exts,
	}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEST_Attestation_RequireEnforced(t *testing.T) {
	pki := newESTAttestPKI(t)
	srv, ts, caCert := newTestEST(t, Config{
		Users:       map[string]User{"device": {Password: "pw", Profile: "client"}},
		Attestation: pki.verifier(t),
	}, false)

	// 1. Enrollment WITH a valid attestation bundle succeeds.
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := pki.attestLeaf(t, deviceKey.Public())
	csrDER := makeAttestedCSR(t, deviceKey, []*x509.Certificate{leaf})

	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	req.SetBasicAuth("device", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attested enroll status = %d, want 200: %s", resp.StatusCode, body)
	}
	issued := parseEnrollResponse(t, body)
	if err := issued.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}

	// 2. Enrollment WITHOUT attestation is rejected fail-closed.
	plainKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	plainCSR := makeAttestedCSR(t, plainKey, nil)
	req2, _ := http.NewRequest("POST", ts.URL+"/.well-known/est/simpleenroll",
		strings.NewReader(base64.StdEncoding.EncodeToString(plainCSR)))
	req2.SetBasicAuth("device", "pw")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("unattested enroll status = %d, want 403", resp2.StatusCode)
	}

	// 3. A cert.attestation audit event recorded the denial, and the audit chain
	//    verifies end to end.
	events, err := srv.db.ListAllEventsAsc()
	if err != nil {
		t.Fatalf("listing audit events: %v", err)
	}
	var sawDenied, sawSuccess bool
	for _, e := range events {
		if e.Action != audit.ActionCertAttestation {
			continue
		}
		switch e.Result {
		case audit.ResultDenied:
			sawDenied = true
		case audit.ResultSuccess:
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Error("expected a successful cert.attestation audit event")
	}
	if !sawDenied {
		t.Error("expected a denied cert.attestation audit event")
	}
	if vr := audit.VerifyChain(events); !vr.Valid {
		t.Errorf("audit chain invalid: %s", vr.Reason)
	}
}
