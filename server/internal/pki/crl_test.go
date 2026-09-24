package pki

// Hand-rolled DER for the CRL partitioning extensions (crl.go).
//
// crypto/x509 cannot emit a Delta CRL Indicator, an Issuing Distribution Point,
// or a Freshest CRL, so crl.go assembles all three by hand out of asn1.RawValue
// nesting. Getting a context tag or a constructed bit wrong there produces DER
// that still *encodes* — it just means something else, or nothing, to the relying
// party that has to decide whether a certificate is revoked. The tests below
// therefore lean on independent decoders: crypto/x509's CRLDistributionPoints
// parser (and its own encoder, byte for byte, where the two agree) for the
// distribution-point syntax, and exact known-answer DER for the parts crypto/x509
// cannot read back.

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// oidExtensionCRLDistributionPoints is the certificate extension whose value
// shares the CRLDistributionPoints syntax with the Freshest CRL extension.
var oidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

// certWithCRLDistributionPoints mints a certificate carrying value as the raw
// CRLDistributionPoints extension and returns what crypto/x509's parser makes of
// it. That parser is an independent implementation of RFC 5280 §4.2.1.13, which
// is precisely the syntax the Freshest CRL extension reuses.
func certWithCRLDistributionPoints(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	key := newECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "crldp-roundtrip"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionCRLDistributionPoints, Value: value},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate rejected our CRLDistributionPoints encoding: %v", err)
	}
	return cert
}

// TestGeneralNamesURIsEncoding pins the GeneralName run: each URI is a
// context-specific, *primitive* [6] (uniformResourceIdentifier) holding the bytes
// verbatim, emitted in the order given and with nothing wrapped around the run.
func TestGeneralNamesURIsEncoding(t *testing.T) {
	// Zero URIs must produce no bytes at all (not an empty SEQUENCE).
	for _, empty := range [][]string{nil, {}} {
		got, err := generalNamesURIs(empty)
		if err != nil {
			t.Fatalf("generalNamesURIs(%v): %v", empty, err)
		}
		if len(got) != 0 {
			t.Errorf("generalNamesURIs(%v) = %x, want no bytes", empty, got)
		}
	}

	one, err := generalNamesURIs([]string{"http://crl.example/a.crl"})
	if err != nil {
		t.Fatalf("generalNamesURIs: %v", err)
	}
	want := append([]byte{0x86, byte(len("http://crl.example/a.crl"))}, "http://crl.example/a.crl"...)
	if !bytes.Equal(one, want) {
		t.Errorf("single URI = %x, want %x", one, want)
	}

	// Several URIs concatenate in order, with no enclosing SEQUENCE.
	uris := []string{"http://a.example/x.crl", "http://b.example/y.crl", "http://c.example/z.crl"}
	many, err := generalNamesURIs(uris)
	if err != nil {
		t.Fatalf("generalNamesURIs: %v", err)
	}
	var expect []byte
	for _, u := range uris {
		expect = append(expect, 0x86, byte(len(u)))
		expect = append(expect, u...)
	}
	if !bytes.Equal(many, expect) {
		t.Errorf("three URIs = %x, want %x", many, expect)
	}

	// A URI longer than 127 bytes forces long-form DER lengths; the header must
	// grow rather than the value being truncated to fit a short form.
	long := "http://crl.example/" + strings.Repeat("p", 200) + ".crl"
	got, err := generalNamesURIs([]string{long})
	if err != nil {
		t.Fatalf("generalNamesURIs(long): %v", err)
	}
	if got[0] != 0x86 || got[1] != 0x81 || int(got[2]) != len(long) {
		t.Errorf("long URI header = %x, want 86 81 %02x", got[:3], len(long))
	}
	if string(got[3:]) != long {
		t.Error("long URI value was not emitted verbatim")
	}
}

// TestMarshalCRLDistributionPointsMatchesGoEncoder compares the hand-rolled
// encoding against the one crypto/x509 produces for a single distribution point.
// For one URI the two must agree byte for byte — that is the strongest available
// statement that the A0/A0/86 nesting and the context tags are right.
func TestMarshalCRLDistributionPointsMatchesGoEncoder(t *testing.T) {
	const uri = "http://crl.example/shard-1.crl"
	key := newECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crldp-oracle"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		CRLDistributionPoints: []string{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	var want []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionCRLDistributionPoints) {
			want = ext.Value
		}
	}
	if want == nil {
		t.Fatal("crypto/x509 emitted no CRLDistributionPoints extension")
	}

	got, err := marshalCRLDistributionPoints([]string{uri})
	if err != nil {
		t.Fatalf("marshalCRLDistributionPoints: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("marshalCRLDistributionPoints = %x, crypto/x509 emits %x", got, want)
	}
}

// TestMarshalCRLDistributionPointsRoundTrip hands the encoding to crypto/x509's
// parser for one, several, degenerate, oversized and non-ASCII URIs, and requires
// every URI back out in the order it went in.
func TestMarshalCRLDistributionPointsRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		uris []string
	}{
		{"one", []string{"http://crl.example/a.crl"}},
		{"three mirrors", []string{
			"http://crl.example/a.crl",
			"http://mirror1.example/a.crl",
			"ldap://directory.example/cn=CA,dc=example?certificateRevocationList",
		}},
		{"empty string URI", []string{""}},
		{"very long URI", []string{"http://crl.example/" + strings.Repeat("segment/", 40) + "a.crl"}},
		// RFC 5280 tags a URI GeneralName as IA5String, so a non-ASCII URI is not
		// strictly conforming (callers are expected to percent-encode). What must
		// hold regardless is that the bytes survive unchanged rather than being
		// silently mangled — crypto/x509's own encoder behaves identically here.
		{"non-ASCII URI", []string{"http://crl.example/grüße.crl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := marshalCRLDistributionPoints(tc.uris)
			if err != nil {
				t.Fatalf("marshalCRLDistributionPoints: %v", err)
			}
			cert := certWithCRLDistributionPoints(t, value)
			if len(cert.CRLDistributionPoints) != len(tc.uris) {
				t.Fatalf("parsed %d URIs (%q), want %d (%q)",
					len(cert.CRLDistributionPoints), cert.CRLDistributionPoints, len(tc.uris), tc.uris)
			}
			for i, want := range tc.uris {
				if cert.CRLDistributionPoints[i] != want {
					t.Errorf("URI[%d] = %q, want %q", i, cert.CRLDistributionPoints[i], want)
				}
			}
		})
	}
}

// TestMarshalCRLDistributionPointsUsesOneDistributionPoint pins the semantics of
// several URLs: RFC 5280 §4.2.1.13 says multiple names inside one
// DistributionPoint are alternative locations for *the same* CRL, while separate
// DistributionPoint entries may name *different* CRLs. A shard published to
// several mirrors is the former, so all URLs must share a single
// DistributionPoint — splitting them (which is what crypto/x509's own encoder
// does for its typed field) would tell a relying party the mirrors are
// independent CRLs.
func TestMarshalCRLDistributionPointsUsesOneDistributionPoint(t *testing.T) {
	value, err := marshalCRLDistributionPoints([]string{
		"http://crl.example/a.crl",
		"http://mirror.example/a.crl",
	})
	if err != nil {
		t.Fatalf("marshalCRLDistributionPoints: %v", err)
	}
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(value, &outer); err != nil || len(rest) != 0 {
		t.Fatalf("CRLDistributionPoints is not a single DER value: err=%v rest=%d", err, len(rest))
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		t.Fatalf("CRLDistributionPoints outer value = class %d tag %d compound %v, want a SEQUENCE",
			outer.Class, outer.Tag, outer.IsCompound)
	}
	count := 0
	for rest := outer.Bytes; len(rest) > 0; count++ {
		var dp asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &dp)
		if err != nil {
			t.Fatalf("decoding DistributionPoint %d: %v", count, err)
		}
	}
	if count != 1 {
		t.Errorf("encoded %d DistributionPoint entries for two mirrors, want 1", count)
	}
}

// TestMarshalCRLDistributionPointsZeroURIs documents the degenerate call. It is
// unreachable from CreateCRL (crlExtraExtensions only encodes a non-empty
// FreshestCRLURLs list), and it must at least not produce something a relying
// party misreads: the result stays parseable and yields no distribution points.
func TestMarshalCRLDistributionPointsZeroURIs(t *testing.T) {
	for _, empty := range [][]string{nil, {}} {
		value, err := marshalCRLDistributionPoints(empty)
		if err != nil {
			t.Fatalf("marshalCRLDistributionPoints(%v): %v", empty, err)
		}
		cert := certWithCRLDistributionPoints(t, value)
		if len(cert.CRLDistributionPoints) != 0 {
			t.Errorf("zero URIs produced %q", cert.CRLDistributionPoints)
		}
	}
}

// TestDistributionPointFieldNesting checks the shared "distributionPoint [0]
// DistributionPointName { fullName [0] GeneralNames }" element directly:
// DistributionPointName is a CHOICE, so its [0] tag cannot be implicit — the
// encoding must be two nested constructed [0]s (A0 { A0 { 86 ... } }), not one.
func TestDistributionPointFieldNesting(t *testing.T) {
	const uri = "http://crl.example/a.crl"
	got, err := distributionPointField([]string{uri})
	if err != nil {
		t.Fatalf("distributionPointField: %v", err)
	}
	names := append([]byte{0x86, byte(len(uri))}, uri...)
	inner := append([]byte{0xA0, byte(len(names))}, names...)
	want := append([]byte{0xA0, byte(len(inner))}, inner...)
	if !bytes.Equal(got, want) {
		t.Fatalf("distributionPointField = %x, want %x", got, want)
	}
}

// TestMarshalIssuingDistributionPointKnownAnswer pins the IDP encoding against
// hand-computed DER. crypto/x509 has no IDP parser, so there is no Go oracle;
// the companion openssl test (crl_openssl_test.go) provides the independent
// decode, and this test locks the bytes so a regression is a diff and not a
// guess.
func TestMarshalIssuingDistributionPointKnownAnswer(t *testing.T) {
	const uri = "http://crl.example/s1.crl" // 25 bytes
	uriDER := append([]byte{0x86, byte(len(uri))}, uri...)

	t.Run("url and onlyContainsUserCerts", func(t *testing.T) {
		fullName := append([]byte{0xA0, byte(len(uriDER))}, uriDER...)
		dp := append([]byte{0xA0, byte(len(fullName))}, fullName...)
		// onlyContainsUserCerts [1] BOOLEAN TRUE, implicit primitive context tag.
		content := append(append([]byte{}, dp...), 0x81, 0x01, 0xFF)
		want := append([]byte{0x30, byte(len(content))}, content...)

		got, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{
			DistributionPointURLs: []string{uri},
			OnlyContainsUserCerts: true,
		})
		if err != nil {
			t.Fatalf("marshalIssuingDistributionPoint: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("IDP = %x, want %x", got, want)
		}
	})

	t.Run("flag only", func(t *testing.T) {
		// With no distribution point the SEQUENCE holds just the flag.
		want := []byte{0x30, 0x03, 0x81, 0x01, 0xFF}
		got, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{OnlyContainsUserCerts: true})
		if err != nil {
			t.Fatalf("marshalIssuingDistributionPoint: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("IDP = %x, want %x", got, want)
		}
	})

	t.Run("url only", func(t *testing.T) {
		fullName := append([]byte{0xA0, byte(len(uriDER))}, uriDER...)
		dp := append([]byte{0xA0, byte(len(fullName))}, fullName...)
		want := append([]byte{0x30, byte(len(dp))}, dp...)
		got, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{
			DistributionPointURLs: []string{uri},
		})
		if err != nil {
			t.Fatalf("marshalIssuingDistributionPoint: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("IDP = %x, want %x", got, want)
		}
	})
}

// TestMarshalIssuingDistributionPointRejectsEmptyScope guards the one input that
// would emit a meaningless critical extension: an IDP that scopes nothing. RFC
// 5280 §5.2.5 marks the extension critical, so a relying party that cannot make
// sense of it must reject the whole CRL — i.e. an empty IDP would take the
// revocation data offline.
func TestMarshalIssuingDistributionPointRejectsEmptyScope(t *testing.T) {
	if _, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{}); err == nil {
		t.Fatal("an IDP with neither a distribution point nor a scope flag was accepted")
	}
	if _, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{DistributionPointURLs: []string{}}); err == nil {
		t.Fatal("an IDP with an empty URL slice and no flag was accepted")
	}
}

// TestMarshalIssuingDistributionPointRoundTripsDistributionPoint decodes the
// distributionPoint field back out of the IDP with crypto/x509, by re-wrapping it
// in the CRLDistributionPoints shape the two extensions share. That confirms the
// URLs inside an IDP are readable by a real GeneralNames decoder — which is what
// a relying party matching a certificate's CRLDP against the CRL's IDP does.
func TestMarshalIssuingDistributionPointRoundTripsDistributionPoint(t *testing.T) {
	uris := []string{"http://crl.example/s1.crl", "http://mirror.example/s1.crl"}
	idp, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{
		DistributionPointURLs: uris,
		OnlyContainsUserCerts: true,
	})
	if err != nil {
		t.Fatalf("marshalIssuingDistributionPoint: %v", err)
	}

	// Peel the IDP SEQUENCE and take its first element, the distributionPoint [0].
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(idp, &seq); err != nil {
		t.Fatalf("IDP is not a SEQUENCE: %v", err)
	}
	var dpField asn1.RawValue
	trailer, err := asn1.Unmarshal(seq.Bytes, &dpField)
	if err != nil {
		t.Fatalf("decoding distributionPoint: %v", err)
	}
	if dpField.Class != asn1.ClassContextSpecific || dpField.Tag != 0 || !dpField.IsCompound {
		t.Fatalf("distributionPoint = class %d tag %d compound %v, want constructed [0]",
			dpField.Class, dpField.Tag, dpField.IsCompound)
	}
	if !bytes.Equal(trailer, []byte{0x81, 0x01, 0xFF}) {
		t.Errorf("trailing IDP content = %x, want onlyContainsUserCerts [1] TRUE", trailer)
	}

	// Re-wrap distributionPoint as CRLDistributionPoints ::= SEQUENCE OF
	// SEQUENCE { distributionPoint [0] ... } and let crypto/x509 read the URLs.
	dpDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: dpField.FullBytes,
	})
	if err != nil {
		t.Fatalf("re-wrapping DistributionPoint: %v", err)
	}
	outer, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: dpDER,
	})
	if err != nil {
		t.Fatalf("re-wrapping CRLDistributionPoints: %v", err)
	}
	cert := certWithCRLDistributionPoints(t, outer)
	if len(cert.CRLDistributionPoints) != len(uris) {
		t.Fatalf("recovered %q, want %q", cert.CRLDistributionPoints, uris)
	}
	for i, want := range uris {
		if cert.CRLDistributionPoints[i] != want {
			t.Errorf("URI[%d] = %q, want %q", i, cert.CRLDistributionPoints[i], want)
		}
	}
}

// TestEncodeCRLPEMRoundTrip pins the PEM wrapper. The label has to be exactly
// "X509 CRL": that is what openssl crl and every CRL consumer looks for, and a
// "CRL" or "X509 CRL " label makes the published artifact unreadable.
func TestEncodeCRLPEMRoundTrip(t *testing.T) {
	caCert, caKey := testCA(t)
	der, err := CreateCRL(caKey, caCert, CRLRequest{
		Number:     big.NewInt(4),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	out := EncodeCRLPEM(der)
	if !bytes.HasPrefix(out, []byte("-----BEGIN X509 CRL-----\n")) {
		t.Errorf("unexpected PEM header: %q", firstLine(out))
	}
	if !bytes.HasSuffix(out, []byte("-----END X509 CRL-----\n")) {
		t.Error("PEM output must end with the armor footer and a newline")
	}
	block, rest := pem.Decode(out)
	if block == nil {
		t.Fatal("EncodeCRLPEM produced output pem.Decode rejects")
	}
	if block.Type != "X509 CRL" {
		t.Errorf("block type = %q, want \"X509 CRL\"", block.Type)
	}
	if !bytes.Equal(block.Bytes, der) {
		t.Error("PEM round-trip changed the DER")
	}
	if len(rest) != 0 {
		t.Errorf("%d bytes trail the single block", len(rest))
	}
	if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		t.Fatalf("the CRL inside the PEM no longer parses: %v", err)
	}

	// An empty input still yields a well-formed (if empty) block rather than nil.
	if block, _ := pem.Decode(EncodeCRLPEM(nil)); block == nil || block.Type != "X509 CRL" || len(block.Bytes) != 0 {
		t.Errorf("EncodeCRLPEM(nil) = %q", EncodeCRLPEM(nil))
	}
}

// TestCreateCRLPartitionedExtensions builds the full delta/partitioned CRL the
// sharding publisher emits and checks the three hand-rolled extensions survive
// x509.CreateRevocationList intact, with the criticality RFC 5280 mandates:
// Issuing Distribution Point (§5.2.5) and Delta CRL Indicator (§5.2.4) critical,
// Freshest CRL (§5.2.6) non-critical.
func TestCreateCRLPartitionedExtensions(t *testing.T) {
	caCert, caKey := testCA(t)
	shardURL := "http://crl.example/leaf-shard-3.crl"
	deltaURL := "http://crl.example/leaf-shard-3-delta.crl"

	der, err := CreateCRL(caKey, caCert, CRLRequest{
		Number:          big.NewInt(12),
		ThisUpdate:      time.Now().Add(-time.Minute),
		NextUpdate:      time.Now().Add(time.Hour),
		BaseCRLNumber:   big.NewInt(11),
		FreshestCRLURLs: []string{deltaURL},
		IDP: &IssuingDistributionPoint{
			DistributionPointURLs: []string{shardURL},
			OnlyContainsUserCerts: true,
		},
		Revoked: []RevokedEntry{{Serial: big.NewInt(99), RevokedAt: time.Now().Add(-time.Hour), Reason: RevocationReasonSuperseded}},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}

	wantIDP, err := marshalIssuingDistributionPoint(IssuingDistributionPoint{
		DistributionPointURLs: []string{shardURL},
		OnlyContainsUserCerts: true,
	})
	if err != nil {
		t.Fatalf("marshalIssuingDistributionPoint: %v", err)
	}
	wantFresh, err := marshalCRLDistributionPoints([]string{deltaURL})
	if err != nil {
		t.Fatalf("marshalCRLDistributionPoints: %v", err)
	}

	found := map[string]pkix.Extension{}
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidIssuingDistributionPoint):
			found["idp"] = ext
		case ext.Id.Equal(oidDeltaCRLIndicator):
			found["delta"] = ext
		case ext.Id.Equal(oidFreshestCRL):
			found["fresh"] = ext
		}
	}
	idp, ok := found["idp"]
	if !ok {
		t.Fatal("CRL carries no Issuing Distribution Point extension")
	}
	if !idp.Critical {
		t.Error("Issuing Distribution Point must be critical (RFC 5280 §5.2.5)")
	}
	if !bytes.Equal(idp.Value, wantIDP) {
		t.Errorf("IDP value = %x, want %x", idp.Value, wantIDP)
	}

	delta, ok := found["delta"]
	if !ok {
		t.Fatal("CRL carries no Delta CRL Indicator extension")
	}
	if !delta.Critical {
		t.Error("Delta CRL Indicator must be critical (RFC 5280 §5.2.4)")
	}
	var base *big.Int
	if rest, err := asn1.Unmarshal(delta.Value, &base); err != nil || len(rest) != 0 {
		t.Errorf("Delta CRL Indicator does not decode as an INTEGER: err=%v rest=%d", err, len(rest))
	} else if base.Cmp(big.NewInt(11)) != 0 {
		t.Errorf("base CRL number = %v, want 11", base)
	}

	fresh, ok := found["fresh"]
	if !ok {
		t.Fatal("CRL carries no Freshest CRL extension")
	}
	if fresh.Critical {
		t.Error("Freshest CRL must be non-critical (RFC 5280 §5.2.6)")
	}
	if !bytes.Equal(fresh.Value, wantFresh) {
		t.Errorf("Freshest CRL value = %x, want %x", fresh.Value, wantFresh)
	}
}

// TestCreateCRLRejectsInvalidDeltaNumbering covers the ordering invariant a delta
// CRL depends on: the base CRL number must be strictly below the delta's own
// number, or a relying party cannot tell which list supersedes which.
func TestCreateCRLRejectsInvalidDeltaNumbering(t *testing.T) {
	caCert, caKey := testCA(t)
	base := CRLRequest{
		Number:     big.NewInt(5),
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
	}
	for _, bad := range []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(-1)} {
		req := base
		req.BaseCRLNumber = bad
		if _, err := CreateCRL(caKey, caCert, req); err == nil {
			t.Errorf("CreateCRL accepted base CRL number %v against delta number %v", bad, req.Number)
		}
	}
	// An empty IDP must fail the whole CRL rather than emit a meaningless
	// critical extension.
	req := base
	req.IDP = &IssuingDistributionPoint{}
	if _, err := CreateCRL(caKey, caCert, req); err == nil {
		t.Error("CreateCRL accepted an IDP that scopes nothing")
	}
}
