package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// testCA builds a self-signed CA certificate and its signer for unit tests.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := CACertRequest{
		Subject:   pkix.Name{CommonName: "Unit Test CA"},
		PublicKey: key.Public(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	der, err := CreateCACertificate(key, nil, req)
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCreateLeafCertificate(t *testing.T) {
	caCert, caKey := testCA(t)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := CreateLeafCertificate(caKey, caCert, LeafCertRequest{
		Subject:     pkix.Name{CommonName: "leaf.test"},
		PublicKey:   leafKey.Public(),
		Serial:      big.NewInt(2),
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"leaf.test"},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf did not verify: %v", err)
	}
	if leaf.IsCA {
		t.Error("leaf should not be a CA")
	}
	if len(leaf.SubjectKeyId) == 0 {
		t.Error("leaf missing subject key identifier")
	}
	if len(leaf.AuthorityKeyId) == 0 {
		t.Error("leaf missing authority key identifier")
	}
}

func TestCreateLeafRejectsExpiryBeyondIssuer(t *testing.T) {
	caCert, caKey := testCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := CreateLeafCertificate(caKey, caCert, LeafCertRequest{
		Subject:   pkix.Name{CommonName: "too-long.test"},
		PublicKey: leafKey.Public(),
		Serial:    big.NewInt(2),
		NotBefore: time.Now(),
		NotAfter:  caCert.NotAfter.Add(time.Hour), // past issuer expiry
	})
	if err == nil {
		t.Fatal("expected error when leaf outlives issuer")
	}
}

func TestCreateCRL(t *testing.T) {
	caCert, caKey := testCA(t)
	der, err := CreateCRL(caKey, caCert, CRLRequest{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		Revoked: []RevokedEntry{
			{Serial: big.NewInt(42), RevokedAt: time.Now(), Reason: RevocationReasonKeyCompromise},
		},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("unexpected CRL entries: %+v", crl.RevokedCertificateEntries)
	}
}

func TestCreateOCSPResponse(t *testing.T) {
	caCert, caKey := testCA(t)
	respDER, err := CreateOCSPResponse(caKey, caCert, OCSPResponseSpec{
		Serial:     big.NewInt(7),
		Status:     OCSPRevoked,
		RevokedAt:  time.Now(),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, caCert)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Errorf("status = %d, want Revoked", resp.Status)
	}
	if resp.SerialNumber.Cmp(big.NewInt(7)) != 0 {
		t.Errorf("serial = %s, want 7", resp.SerialNumber)
	}
}

func TestParseRevocationReason(t *testing.T) {
	cases := map[string]int{
		"":                     RevocationReasonUnspecified,
		"keyCompromise":        RevocationReasonKeyCompromise,
		"SUPERSEDED":           RevocationReasonSuperseded,
		"cessationOfOperation": RevocationReasonCessationOfOperation,
	}
	for name, want := range cases {
		got, err := ParseRevocationReason(name)
		if err != nil {
			t.Errorf("ParseRevocationReason(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseRevocationReason(%q) = %d, want %d", name, got, want)
		}
	}
	if _, err := ParseRevocationReason("bogus"); err == nil {
		t.Error("expected error for unknown reason")
	}
}

// TestRevocationReasonName checks the code->name rendering, including that every
// named reason round-trips through ParseRevocationReason and an unknown code
// renders as reason(N).
func TestRevocationReasonName(t *testing.T) {
	cases := map[int]string{
		RevocationReasonUnspecified:          "unspecified",
		RevocationReasonKeyCompromise:        "keyCompromise",
		RevocationReasonCACompromise:         "cACompromise",
		RevocationReasonAffiliationChanged:   "affiliationChanged",
		RevocationReasonSuperseded:           "superseded",
		RevocationReasonCessationOfOperation: "cessationOfOperation",
		RevocationReasonCertificateHold:      "certificateHold",
		RevocationReasonRemoveFromCRL:        "removeFromCRL",
		RevocationReasonPrivilegeWithdrawn:   "privilegeWithdrawn",
		RevocationReasonAACompromise:         "aACompromise",
	}
	for code, want := range cases {
		if got := RevocationReasonName(code); got != want {
			t.Errorf("RevocationReasonName(%d) = %q, want %q", code, got, want)
		}
		// removeFromCRL (8) is never a valid revocation *request* reason, so it does
		// not round-trip through ParseRevocationReason; the other names must.
		if code == RevocationReasonRemoveFromCRL {
			continue
		}
		if back, err := ParseRevocationReason(want); err != nil || back != code {
			t.Errorf("round-trip ParseRevocationReason(%q) = %d, %v; want %d", want, back, err, code)
		}
	}
	if got := RevocationReasonName(4242); got != "reason(4242)" {
		t.Errorf("RevocationReasonName(4242) = %q, want reason(4242)", got)
	}
}

// goMarksSANCritical reports whether crypto/x509, minting a certificate with the
// given subject and a DNS SAN, marks the subjectAltName extension critical. That
// is crypto/x509's own implementation of the RFC 5280 §4.2.1.6 rule
// emptyASN1Subject is meant to mirror, so it serves as an independent oracle.
func goMarksSANCritical(t *testing.T, subject pkix.Name) bool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"san.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDSubjectAltName) {
			return ext.Critical
		}
	}
	t.Fatal("crypto/x509 emitted no subjectAltName extension")
	return false
}

// TestEmptyASN1SubjectMatchesCryptoX509 checks the criticality decision against
// crypto/x509's own. It only matters when a leaf carries a UPN — then the whole
// subjectAltName is hand-rolled and this predicate is the only thing deciding
// criticality. Getting it wrong in either direction is a real defect: a
// certificate with an empty subject and a non-critical SAN violates RFC 5280
// §4.2.1.6 (and CA/B linting), while a critical SAN on a certificate that does
// have a subject makes strict relying parties reject it.
func TestEmptyASN1SubjectMatchesCryptoX509(t *testing.T) {
	cases := []struct {
		name    string
		subject pkix.Name
	}{
		{"empty", pkix.Name{}},
		{"common name", pkix.Name{CommonName: "leaf.example"}},
		{"empty common name string", pkix.Name{CommonName: ""}},
		{"organization only", pkix.Name{Organization: []string{"Example Org"}}},
		{"country only", pkix.Name{Country: []string{"DE"}}},
		{"serial number attribute only", pkix.Name{SerialNumber: "12345"}},
		{"extra names only", pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: []int{2, 5, 4, 3}, Value: "via-ExtraNames.example"}, // id-at-commonName
		}}},
		// Names is only populated when parsing; ToRDNSequence ignores it, so a
		// subject carrying nothing else still encodes empty — for both of us.
		{"parsed-only Names field", pkix.Name{Names: []pkix.AttributeTypeAndValue{
			{Type: []int{2, 5, 4, 3}, Value: "ignored.example"},
		}}},
		{"empty organization slice", pkix.Name{Organization: []string{}}},
		{"organization with an empty string", pkix.Name{Organization: []string{""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := goMarksSANCritical(t, tc.subject)
			got := emptyASN1Subject(&x509.Certificate{Subject: tc.subject})
			if got != want {
				t.Errorf("emptyASN1Subject = %v, but crypto/x509 marks the SAN critical = %v", got, want)
			}
		})
	}
}

// TestLeafWithUPNMarksSANCriticalOnlyWhenSubjectIsEmpty exercises the predicate
// through the code that actually uses it: a leaf carrying a UPN, whose SAN is
// hand-rolled end to end.
func TestLeafWithUPNMarksSANCriticalOnlyWhenSubjectIsEmpty(t *testing.T) {
	caCert, caKey := testCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name         string
		subject      pkix.Name
		wantCritical bool
	}{
		{"with a subject", pkix.Name{CommonName: "alice"}, false},
		{"empty subject", pkix.Name{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := CreateLeafCertificate(caKey, caCert, LeafCertRequest{
				Subject:   tc.subject,
				PublicKey: key.Public(),
				Serial:    big.NewInt(77),
				NotBefore: time.Now().Add(-time.Minute),
				NotAfter:  time.Now().Add(time.Hour),
				KeyUsage:  x509.KeyUsageDigitalSignature,
				UPNs:      []string{"alice@EXAMPLE.COM"},
			})
			if err != nil {
				t.Fatalf("CreateLeafCertificate: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			var found bool
			for _, ext := range cert.Extensions {
				if !ext.Id.Equal(OIDSubjectAltName) {
					continue
				}
				found = true
				if ext.Critical != tc.wantCritical {
					t.Errorf("SAN critical = %v, want %v", ext.Critical, tc.wantCritical)
				}
			}
			if !found {
				t.Fatal("leaf carries no subjectAltName extension")
			}
			if upns := UPNsFromCertificate(cert); len(upns) != 1 || upns[0] != "alice@EXAMPLE.COM" {
				t.Errorf("UPNs = %q, want [alice@EXAMPLE.COM]", upns)
			}
		})
	}
}

// TestEmptyASN1SubjectScopeGuard records why emptyASN1Subject may look at
// template.Subject alone: crypto/x509 prefers template.RawSubject when deciding
// the same question, but LeafCertRequest has no RawSubject field, so the leaf
// templates this predicate sees never set one. If that changes, the predicate has
// to change with it — otherwise a leaf with a raw DN and an empty Subject would
// get a wrongly critical SAN.
func TestEmptyASN1SubjectScopeGuard(t *testing.T) {
	if _, ok := reflect.TypeOf(LeafCertRequest{}).FieldByName("RawSubject"); ok {
		t.Error("LeafCertRequest gained a RawSubject field: emptyASN1Subject only inspects template.Subject " +
			"and must be taught to prefer RawSubject, as crypto/x509 does")
	}
	// Demonstrates the divergence the guard protects against, so the reasoning is
	// checkable rather than asserted: with a non-empty RawSubject and an empty
	// Subject the predicate still reports "empty".
	rawSubject, err := asn1.Marshal(pkix.Name{CommonName: "raw-only"}.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshaling raw subject: %v", err)
	}
	if !emptyASN1Subject(&x509.Certificate{RawSubject: rawSubject}) {
		t.Log("emptyASN1Subject now honors RawSubject; the field guard above can be dropped")
	}
}
