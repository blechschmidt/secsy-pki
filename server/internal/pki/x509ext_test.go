package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedWith issues a throwaway self-signed certificate carrying exts, and
// returns the re-parsed certificate. It is the only honest way to test an
// extension encoder: the DER has to survive a real X.509 parser, not just a
// round trip through the same code that produced it.
func selfSignedWith(t *testing.T, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ext encoder test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate we just made: %v", err)
	}
	return cert
}

func findExt(t *testing.T, cert *x509.Certificate, oid asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e
		}
	}
	t.Fatalf("certificate carries no %s extension", oid)
	return pkix.Extension{}
}

// TestGeneralNamesExtension_AllTypes encodes every GeneralName alternative this
// package supports into a subjectAltName and checks that crypto/x509 — which
// parses SANs strictly — decodes each one back to the value put in.
func TestGeneralNamesExtension_AllTypes(t *testing.T) {
	upn, err := OtherNameUTF8(OIDUserPrincipalName, "svc@CORP.EXAMPLE")
	if err != nil {
		t.Fatalf("building UPN otherName: %v", err)
	}
	dn := pkix.RDNSequence{
		[]pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Org"}},
		[]pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "DE"}},
	}
	gn := GeneralNames{
		OtherNames:    []OtherName{upn},
		Emails:        []string{"pki@example.test"},
		DNSNames:      []string{"ca.example.test"},
		DirNames:      []pkix.RDNSequence{dn},
		URIs:          []string{"https://ca.example.test/"},
		IPs:           []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")},
		RegisteredIDs: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 7}},
	}
	ext, err := GeneralNamesExtension(OIDSubjectAltName, false, gn)
	if err != nil {
		t.Fatalf("GeneralNamesExtension: %v", err)
	}
	cert := selfSignedWith(t, []pkix.Extension{ext})

	if got := cert.EmailAddresses; len(got) != 1 || got[0] != "pki@example.test" {
		t.Errorf("rfc822Name SANs = %v, want [pki@example.test]", got)
	}
	if got := cert.DNSNames; len(got) != 1 || got[0] != "ca.example.test" {
		t.Errorf("dNSName SANs = %v, want [ca.example.test]", got)
	}
	if got := cert.URIs; len(got) != 1 || got[0].String() != "https://ca.example.test/" {
		t.Errorf("URI SANs = %v, want [https://ca.example.test/]", got)
	}
	if len(cert.IPAddresses) != 2 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) ||
		!cert.IPAddresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("iPAddress SANs = %v, want [192.0.2.10 2001:db8::1]", cert.IPAddresses)
	}
	// crypto/x509 does not surface otherName/directoryName/registeredID, so they
	// are checked by walking the raw GeneralNames: each must be present with the
	// right tag, and the whole SEQUENCE must consume exactly.
	tags := generalNameTags(t, findExt(t, cert, OIDSubjectAltName).Value)
	want := []int{0, 1, 2, 4, 6, 7, 7, 8}
	if len(tags) != len(want) {
		t.Fatalf("SAN carries %d general names (tags %v), want %d (%v)", len(tags), tags, len(want), want)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Errorf("general name %d has tag %d, want %d", i, tags[i], want[i])
		}
	}
	// The UPN must round-trip through the dedicated parser, proving the generic
	// otherName encoder agrees with the UPN-specific one already in this package.
	upns := UPNsFromCertificate(cert)
	if len(upns) != 1 || upns[0] != "svc@CORP.EXAMPLE" {
		t.Errorf("UPNs = %v, want [svc@CORP.EXAMPLE]", upns)
	}
}

// generalNameTags walks a DER GeneralNames SEQUENCE and returns the
// context-specific tag of each entry, failing when anything is left over.
func generalNameTags(t *testing.T, value []byte) []int {
	t.Helper()
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(value, &seq)
	if err != nil {
		t.Fatalf("GeneralNames is not valid DER: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("GeneralNames has %d trailing bytes", len(rest))
	}
	if seq.Tag != asn1.TagSequence || seq.Class != asn1.ClassUniversal {
		t.Fatalf("GeneralNames is not a SEQUENCE (class %d tag %d)", seq.Class, seq.Tag)
	}
	var tags []int
	body := seq.Bytes
	for len(body) > 0 {
		var gn asn1.RawValue
		body, err = asn1.Unmarshal(body, &gn)
		if err != nil {
			t.Fatalf("GeneralName is not valid DER: %v", err)
		}
		if gn.Class != asn1.ClassContextSpecific {
			t.Fatalf("GeneralName has class %d, want context-specific", gn.Class)
		}
		tags = append(tags, gn.Tag)
	}
	return tags
}

func TestGeneralNamesExtension_RejectsEmpty(t *testing.T) {
	if _, err := GeneralNamesExtension(OIDSubjectAltName, false, GeneralNames{}); err == nil {
		t.Fatal("expected an error for an empty GeneralNames set")
	}
}

// TestAccessSyntaxExtension_SIA checks the subjectInfoAccess encoding against
// crypto/x509's own AIA parser, which uses the identical ASN.1 structure: a
// certificate whose AIA was built by this encoder must parse into the same
// OCSP/caIssuers lists crypto/x509 would have produced.
func TestAccessSyntaxExtension_SIA(t *testing.T) {
	ext, err := AccessSyntaxExtension(OIDAuthorityInfoAccess, []AccessDescription{
		{Method: OIDAccessMethodOCSP, URI: "http://ocsp.example.test/"},
		{Method: OIDAccessMethodCAIssuers, URI: "http://pki.example.test/root.cer"},
	})
	if err != nil {
		t.Fatalf("AccessSyntaxExtension: %v", err)
	}
	if ext.Critical {
		t.Error("authorityInfoAccess must be non-critical")
	}
	cert := selfSignedWith(t, []pkix.Extension{ext})
	if got := cert.OCSPServer; len(got) != 1 || got[0] != "http://ocsp.example.test/" {
		t.Errorf("OCSPServer = %v, want [http://ocsp.example.test/]", got)
	}
	if got := cert.IssuingCertificateURL; len(got) != 1 || got[0] != "http://pki.example.test/root.cer" {
		t.Errorf("IssuingCertificateURL = %v, want [http://pki.example.test/root.cer]", got)
	}

	// The same encoder under the SIA OID must produce a parseable extension too.
	sia, err := AccessSyntaxExtension(OIDSubjectInfoAccess, []AccessDescription{
		{Method: OIDAccessMethodCARepository, URI: "http://pki.example.test/certs/"},
		{Method: OIDAccessMethodTimeStamping, URI: "http://tsa.example.test/"},
	})
	if err != nil {
		t.Fatalf("AccessSyntaxExtension(SIA): %v", err)
	}
	cert2 := selfSignedWith(t, []pkix.Extension{sia})
	var decoded []struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}
	if _, err := asn1.Unmarshal(findExt(t, cert2, OIDSubjectInfoAccess).Value, &decoded); err != nil {
		t.Fatalf("decoding SIA: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("SIA has %d access descriptions, want 2", len(decoded))
	}
	if !decoded[0].Method.Equal(OIDAccessMethodCARepository) || string(decoded[0].Location.Bytes) != "http://pki.example.test/certs/" {
		t.Errorf("SIA[0] = %s %q", decoded[0].Method, decoded[0].Location.Bytes)
	}
	if !decoded[1].Method.Equal(OIDAccessMethodTimeStamping) || string(decoded[1].Location.Bytes) != "http://tsa.example.test/" {
		t.Errorf("SIA[1] = %s %q", decoded[1].Method, decoded[1].Location.Bytes)
	}
}

func TestAccessSyntaxExtension_Rejects(t *testing.T) {
	if _, err := AccessSyntaxExtension(OIDSubjectInfoAccess, nil); err == nil {
		t.Error("expected an error for an empty access-description list")
	}
	if _, err := AccessSyntaxExtension(OIDSubjectInfoAccess, []AccessDescription{{Method: OIDAccessMethodOCSP}}); err == nil {
		t.Error("expected an error for an access description with no URI")
	}
	if _, err := AccessSyntaxExtension(OIDSubjectInfoAccess, []AccessDescription{{URI: "http://x/"}}); err == nil {
		t.Error("expected an error for an access description with no method")
	}
}

// TestDistributionPointsExtension checks the freshestCRL encoding against
// crypto/x509's cRLDistributionPoints parser, which shares the syntax exactly —
// so parsing a certificate whose CRLDP was produced here proves the DER right.
func TestDistributionPointsExtension(t *testing.T) {
	ext, err := DistributionPointsExtension(asn1.ObjectIdentifier{2, 5, 29, 31},
		[]string{"http://crl.example.test/root.crl", "ldap://dir.example.test/cn=root"})
	if err != nil {
		t.Fatalf("DistributionPointsExtension: %v", err)
	}
	cert := selfSignedWith(t, []pkix.Extension{ext})
	want := []string{"http://crl.example.test/root.crl", "ldap://dir.example.test/cn=root"}
	if len(cert.CRLDistributionPoints) != len(want) {
		t.Fatalf("CRLDistributionPoints = %v, want %v", cert.CRLDistributionPoints, want)
	}
	for i := range want {
		if cert.CRLDistributionPoints[i] != want[i] {
			t.Errorf("CRLDistributionPoints[%d] = %q, want %q", i, cert.CRLDistributionPoints[i], want[i])
		}
	}

	// Under the freshestCRL OID the extension must still parse, and must be
	// non-critical as RFC 5280 §4.2.1.15 requires.
	fresh, err := DistributionPointsExtension(OIDFreshestCRL, []string{"http://crl.example.test/delta.crl"})
	if err != nil {
		t.Fatalf("DistributionPointsExtension(freshestCRL): %v", err)
	}
	if fresh.Critical {
		t.Error("freshestCRL must be non-critical")
	}
	cert2 := selfSignedWith(t, []pkix.Extension{fresh})
	if findExt(t, cert2, OIDFreshestCRL).Critical {
		t.Error("freshestCRL in the issued certificate is critical")
	}
}

func TestInhibitAnyPolicyExtension(t *testing.T) {
	ext, err := InhibitAnyPolicyExtension(2)
	if err != nil {
		t.Fatalf("InhibitAnyPolicyExtension: %v", err)
	}
	if !ext.Critical {
		t.Error("inhibitAnyPolicy must be critical (RFC 5280 §4.2.1.14)")
	}
	cert := selfSignedWith(t, []pkix.Extension{ext})
	var skipCerts int
	if _, err := asn1.Unmarshal(findExt(t, cert, OIDInhibitAnyPolicy).Value, &skipCerts); err != nil {
		t.Fatalf("decoding inhibitAnyPolicy: %v", err)
	}
	if skipCerts != 2 {
		t.Errorf("inhibitAnyPolicy skipCerts = %d, want 2", skipCerts)
	}
	if _, err := InhibitAnyPolicyExtension(-1); err == nil {
		t.Error("expected an error for a negative skipCerts")
	}
}

func TestSubjectDirectoryAttributesExtension(t *testing.T) {
	// countryOfCitizenship (1.3.6.1.5.5.7.9.4), a PrintableString.
	country, err := asn1.MarshalWithParams("DE", "printable")
	if err != nil {
		t.Fatalf("encoding attribute value: %v", err)
	}
	ext, err := SubjectDirectoryAttributesExtension([]DirectoryAttribute{
		{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 4}, Values: [][]byte{country}},
	})
	if err != nil {
		t.Fatalf("SubjectDirectoryAttributesExtension: %v", err)
	}
	if ext.Critical {
		t.Error("subjectDirectoryAttributes must be non-critical")
	}
	cert := selfSignedWith(t, []pkix.Extension{ext})
	var attrs []struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(findExt(t, cert, OIDSubjectDirectoryAttributes).Value, &attrs); err != nil {
		t.Fatalf("decoding subjectDirectoryAttributes: %v", err)
	}
	if len(attrs) != 1 || len(attrs[0].Values) != 1 {
		t.Fatalf("decoded %d attributes, want 1 with 1 value", len(attrs))
	}
	if string(attrs[0].Values[0].Bytes) != "DE" {
		t.Errorf("attribute value = %q, want DE", attrs[0].Values[0].Bytes)
	}
	if _, err := SubjectDirectoryAttributesExtension(nil); err == nil {
		t.Error("expected an error for an empty attribute list")
	}
}

func TestNetscapeExtensions(t *testing.T) {
	comment, err := NetscapeCommentExtension("Issued by the Northwind PKI")
	if err != nil {
		t.Fatalf("NetscapeCommentExtension: %v", err)
	}
	certType, err := NetscapeCertTypeExtension([]int{NetscapeCertTypeSSLCA, NetscapeCertTypeSMIMECA})
	if err != nil {
		t.Fatalf("NetscapeCertTypeExtension: %v", err)
	}
	cert := selfSignedWith(t, []pkix.Extension{comment, certType})

	var got string
	if _, err := asn1.UnmarshalWithParams(findExt(t, cert, OIDNetscapeComment).Value, &got, "ia5"); err != nil {
		t.Fatalf("decoding netscape comment: %v", err)
	}
	if got != "Issued by the Northwind PKI" {
		t.Errorf("netscape comment = %q", got)
	}

	var bits asn1.BitString
	if _, err := asn1.Unmarshal(findExt(t, cert, OIDNetscapeCertType).Value, &bits); err != nil {
		t.Fatalf("decoding netscape cert type: %v", err)
	}
	// sslCA is bit 5 and smimeCA bit 6; nothing else may be set.
	for bit := 0; bit <= 7; bit++ {
		want := bit == NetscapeCertTypeSSLCA || bit == NetscapeCertTypeSMIMECA
		if got := bits.At(bit) == 1; got != want {
			t.Errorf("netscape cert type bit %d = %v, want %v", bit, got, want)
		}
	}
	if _, err := NetscapeCertTypeExtension([]int{9}); err == nil {
		t.Error("expected an error for an out-of-range netscape cert-type bit")
	}
	if _, err := NetscapeCommentExtension("  "); err == nil {
		t.Error("expected an error for an empty netscape comment")
	}
}
