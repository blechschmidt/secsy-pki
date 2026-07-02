package certpolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestPolicyExtensionsParsedByStdlib(t *testing.T) {
	skip := 0
	cfg := PolicyConfig{
		OIDs:                  []string{"1.3.6.1.4.1.99999.1.1", "anyPolicy"},
		CPS:                   "https://cps.example.com/cps",
		Mappings:              []string{"1.3.6.1.4.1.99999.1.1:1.3.6.1.4.1.88888.2.2"},
		RequireExplicitPolicy: &skip,
	}
	p, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	exts, err := p.Extensions()
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	if len(exts) != 3 {
		t.Fatalf("expected 3 extensions (policies, mappings, constraints), got %d", len(exts))
	}

	der := selfSignedWithExts(t, exts)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("stdlib parse: %v", err)
	}

	// The certificatePolicies extension must be recognized by the standard library.
	wantAny := AnyPolicyOID()
	var haveCustom, haveAny bool
	for _, oid := range cert.PolicyIdentifiers {
		if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}) {
			haveCustom = true
		}
		if oid.Equal(wantAny) {
			haveAny = true
		}
	}
	if !haveCustom || !haveAny {
		t.Errorf("policy identifiers = %v (custom=%v any=%v)", cert.PolicyIdentifiers, haveCustom, haveAny)
	}

	// policyConstraints must be present and critical.
	oidPC := asn1.ObjectIdentifier{2, 5, 29, 36}
	var found bool
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidPC) {
			found = true
			if !e.Critical {
				t.Errorf("policyConstraints must be critical")
			}
			// requireExplicitPolicy [0] SkipCerts = 0
			var pc struct {
				Require asn1.RawValue `asn1:"optional,tag:0"`
				Inhibit asn1.RawValue `asn1:"optional,tag:1"`
			}
			if _, err := asn1.Unmarshal(e.Value, &pc); err != nil {
				t.Errorf("policyConstraints decode: %v", err)
			}
			if len(pc.Require.Bytes) != 1 || pc.Require.Bytes[0] != 0 {
				t.Errorf("requireExplicitPolicy skipCerts = %v, want [0]", pc.Require.Bytes)
			}
		}
	}
	if !found {
		t.Errorf("policyConstraints extension not found")
	}
}

func selfSignedWithExts(t *testing.T, exts []pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "policy-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestParseOID(t *testing.T) {
	if oid, err := ParseOID("anyPolicy"); err != nil || !oid.Equal(AnyPolicyOID()) {
		t.Errorf("anyPolicy: %v %v", oid, err)
	}
	if _, err := ParseOID("not-an-oid"); err == nil {
		t.Errorf("expected error for bad OID")
	}
}
