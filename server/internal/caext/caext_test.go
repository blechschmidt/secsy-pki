package caext

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// issue builds a self-signed CA certificate carrying the compiled Config and
// returns the re-parsed result, so every assertion is made against DER that a
// real X.509 parser accepted.
func issue(t *testing.T, cfg *Config) *x509.Certificate {
	t.Helper()
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := built.ApplyValidity(notBefore, notAfter); err != nil {
		t.Fatalf("ApplyValidity: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := pki.CreateCACertificate(key, nil, pki.CACertRequest{
		Subject:               pkix.Name{CommonName: "caext test CA"},
		PublicKey:             &key.PublicKey,
		Serial:                big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              built.KeyUsage,
		SubjectKeyID:          built.SubjectKeyID,
		CRLDistributionPoints: built.CRLDistributionPoints,
		OCSPServer:            built.OCSPServers,
		IssuingCertificateURL: built.CAIssuers,
		ExtraExtensions:       built.Extensions,
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate we just made: %v", err)
	}
	return cert
}

func hasExt(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// TestZeroConfigIsTheOldDefault pins the behaviour an existing deployment relies
// on: a request that configures no extensions must produce exactly the CA
// certificate secsy-pki produced before this package existed.
func TestZeroConfigIsTheOldDefault(t *testing.T) {
	var cfg *Config
	if !cfg.IsZero() {
		t.Error("a nil Config should report IsZero")
	}
	if !(&Config{}).IsZero() {
		t.Error("an empty Config should report IsZero")
	}
	cert := issue(t, nil)
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	if cert.KeyUsage != want {
		t.Errorf("key usage = %b, want %b", cert.KeyUsage, want)
	}
	if !cert.IsCA {
		t.Error("certificate is not a CA")
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
		t.Errorf("unconfigured certificate carries extKeyUsage %v/%v", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	// Only the four extensions the CA path has always emitted.
	for _, e := range cert.Extensions {
		switch e.Id.String() {
		case "2.5.29.15", "2.5.29.19", "2.5.29.14", "2.5.29.35":
		default:
			t.Errorf("unconfigured certificate carries an unexpected extension %s", e.Id)
		}
	}
}

// TestFullExtensionSet drives every field of Config at once and checks each
// extension landed, which is also the fixture an operator's "everything on" CA
// would produce.
func TestFullExtensionSet(t *testing.T) {
	inhibit := 1
	cfg := &Config{
		KeyUsages:           []string{"keyCertSign", "cRLSign"},
		ExtKeyUsages:        []string{"serverAuth", "clientAuth", "msSmartcardLogon", "1.3.6.1.4.1.99999.3"},
		ExtKeyUsageCritical: true,
		SubjectAltName: &GeneralNamesConfig{
			DNS:           []string{"ca.example.test"},
			IP:            []string{"192.0.2.10"},
			Email:         []string{"pki@example.test"},
			URI:           []string{"https://ca.example.test/"},
			UPN:           []string{"svc@CORP.EXAMPLE"},
			DirNames:      []string{"O=Example Org,C=DE"},
			RegisteredIDs: []string{"1.3.6.1.4.1.99999.9"},
			OtherNames: []OtherNameConfig{
				{OID: "1.3.6.1.4.1.99999.10", Encoding: "ia5", Value: "other-name"},
			},
		},
		IssuerAltName:         &GeneralNamesConfig{URI: []string{"https://root.example.test/"}},
		CRLDistributionPoints: []string{"http://crl.example.test/root.crl"},
		FreshestCRL:           []string{"http://crl.example.test/delta.crl"},
		OCSPServers:           []string{"http://ocsp.example.test/"},
		CAIssuers:             []string{"http://pki.example.test/root.cer"},
		CARepositories:        []string{"http://pki.example.test/certs/"},
		TimestampServers:      []string{"http://tsa.example.test/"},
		InhibitAnyPolicy:      &inhibit,
		PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Fraction: 0.5},
		SubjectDirectoryAttributes: []AttributeConfig{
			{OID: "1.3.6.1.5.5.7.9.4", Encoding: "printable", Values: []string{"DE"}},
		},
		MustStaple:       true,
		TLSFeatures:      []int{5, 17},
		OCSPNoCheck:      true,
		NetscapeComment:  "Northwind issuing CA",
		NetscapeCertType: []string{"sslCA", "smimeCA"},
		SubjectKeyID:     "de:ad:be:ef:00:11:22:33",
		Custom: []CustomExtension{
			{OID: "1.3.6.1.4.1.99999.100", Critical: true, Encoding: "utf8", Value: "enterprise marker"},
			{OID: "1.3.6.1.4.1.99999.101", Encoding: "der-hex", Value: "0500"},
		},
	}
	cert := issue(t, cfg)

	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b, want certSign|crlSign", cert.KeyUsage)
	}
	if string(cert.SubjectKeyId) != "\xde\xad\xbe\xef\x00\x11\x22\x33" {
		t.Errorf("subject key id = %x, want deadbeef00112233", cert.SubjectKeyId)
	}

	eku, ok := hasExt(cert, asn1.ObjectIdentifier{2, 5, 29, 37})
	if !ok {
		t.Fatal("no extKeyUsage extension")
	}
	if !eku.Critical {
		t.Error("extKeyUsage should be critical when ext_key_usage_critical is set")
	}
	wantEKU := map[string]bool{
		"1.3.6.1.5.5.7.3.1": false, "1.3.6.1.5.5.7.3.2": false,
		"1.3.6.1.4.1.311.20.2.2": false, "1.3.6.1.4.1.99999.3": false,
	}
	var ekuOIDs []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(eku.Value, &ekuOIDs); err != nil {
		t.Fatalf("decoding extKeyUsage: %v", err)
	}
	for _, oid := range ekuOIDs {
		if _, want := wantEKU[oid.String()]; !want {
			t.Errorf("unexpected extended key usage %s", oid)
			continue
		}
		wantEKU[oid.String()] = true
	}
	for oid, seen := range wantEKU {
		if !seen {
			t.Errorf("missing extended key usage %s", oid)
		}
	}

	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "ca.example.test" {
		t.Errorf("DNS SANs = %v", cert.DNSNames)
	}
	if upns := pki.UPNsFromCertificate(cert); len(upns) != 1 || upns[0] != "svc@CORP.EXAMPLE" {
		t.Errorf("UPNs = %v", upns)
	}
	if _, ok := hasExt(cert, pki.OIDIssuerAltName); !ok {
		t.Error("no issuerAltName extension")
	}
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "http://crl.example.test/root.crl" {
		t.Errorf("CRLDP = %v", cert.CRLDistributionPoints)
	}
	if len(cert.OCSPServer) != 1 || len(cert.IssuingCertificateURL) != 1 {
		t.Errorf("AIA = %v / %v", cert.OCSPServer, cert.IssuingCertificateURL)
	}
	for _, oid := range []asn1.ObjectIdentifier{
		pki.OIDFreshestCRL, pki.OIDSubjectInfoAccess, pki.OIDInhibitAnyPolicy,
		pki.OIDPrivateKeyUsagePeriod, pki.OIDSubjectDirectoryAttributes,
		pki.OIDTLSFeature, pki.OIDOCSPNoCheck, pki.OIDNetscapeComment, pki.OIDNetscapeCertType,
		{1, 3, 6, 1, 4, 1, 99999, 100}, {1, 3, 6, 1, 4, 1, 99999, 101},
	} {
		if _, ok := hasExt(cert, oid); !ok {
			t.Errorf("missing extension %s", oid)
		}
	}

	// must_staple plus an explicit list must de-duplicate rather than emit 5 twice.
	tf, _ := hasExt(cert, pki.OIDTLSFeature)
	features, err := pki.ParseTLSFeature(tf.Value)
	if err != nil {
		t.Fatalf("decoding tlsfeature: %v", err)
	}
	if len(features) != 2 || features[0] != 5 || features[1] != 17 {
		t.Errorf("tls features = %v, want [5 17]", features)
	}

	// The private-key usage period must be the configured half of the validity.
	pkupExt, _ := hasExt(cert, pki.OIDPrivateKeyUsagePeriod)
	pkup, err := pki.ParsePrivateKeyUsagePeriod(pkupExt.Value)
	if err != nil {
		t.Fatalf("decoding privateKeyUsagePeriod: %v", err)
	}
	half := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
	if d := pkup.NotAfter.Sub(half); d > time.Minute || d < -time.Minute {
		t.Errorf("privateKeyUsagePeriod notAfter = %s, want ~%s", pkup.NotAfter, half)
	}
	if !pkup.NotBefore.Equal(cert.NotBefore) {
		t.Errorf("privateKeyUsagePeriod notBefore = %s, want %s", pkup.NotBefore, cert.NotBefore)
	}
}

// TestKeyUsageRules covers the one key-usage invariant worth enforcing: a CA
// certificate that cannot sign certificates is a configuration mistake, not a
// choice, and must be refused up front rather than failing path validation later.
func TestKeyUsageRules(t *testing.T) {
	if _, err := (&Config{KeyUsages: []string{"digitalSignature"}}).Build(); err == nil {
		t.Error("expected an error for a CA key usage set without certSign")
	} else if !strings.Contains(err.Error(), "certSign") {
		t.Errorf("error should name certSign, got %v", err)
	}
	if _, err := (&Config{KeyUsages: []string{"certSign", "notAUsage"}}).Build(); err == nil {
		t.Error("expected an error for an unknown key usage")
	}
	// Both spellings of each bit must be accepted.
	built, err := (&Config{KeyUsages: []string{"keyCertSign", "cRLSign", "nonRepudiation"}}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageContentCommitment
	if built.KeyUsage != want {
		t.Errorf("key usage = %b, want %b", built.KeyUsage, want)
	}
}

func TestExtKeyUsageResolution(t *testing.T) {
	if _, err := (&Config{ExtKeyUsages: []string{"nonsense"}}).Build(); err == nil {
		t.Error("expected an error for an unresolvable extended key usage")
	}
	if _, err := (&Config{ExtKeyUsageCritical: true}).Build(); err == nil {
		t.Error("expected an error when ext_key_usage_critical is set without any usage")
	}
	// A duplicate name collapses rather than emitting the OID twice.
	built, err := (&Config{ExtKeyUsages: []string{"serverAuth", "1.3.6.1.5.5.7.3.1"}}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var oids []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(built.Extensions[0].Value, &oids); err != nil {
		t.Fatalf("decoding extKeyUsage: %v", err)
	}
	if len(oids) != 1 {
		t.Errorf("extKeyUsage carries %d OIDs, want 1 after de-duplication", len(oids))
	}
}

func TestPrivateKeyUsagePeriodForms(t *testing.T) {
	notBefore := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(1000 * 24 * time.Hour)

	cases := []struct {
		name string
		cfg  PrivateKeyUsagePeriodConfig
		want time.Time
	}{
		{"duration", PrivateKeyUsagePeriodConfig{Duration: "100d"}, notBefore.Add(100 * 24 * time.Hour)},
		{"fraction", PrivateKeyUsagePeriodConfig{Fraction: 0.25}, notBefore.Add(250 * 24 * time.Hour)},
		{"explicit", PrivateKeyUsagePeriodConfig{NotAfter: "2031-01-01T00:00:00Z"}, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)},
		// A window longer than the certificate is clamped to the expiry.
		{"clamped", PrivateKeyUsagePeriodConfig{Duration: "5000d"}, notAfter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.resolve(notBefore, notAfter)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !got.NotAfter.Equal(tc.want) {
				t.Errorf("notAfter = %s, want %s", got.NotAfter, tc.want)
			}
		})
	}

	for _, bad := range []PrivateKeyUsagePeriodConfig{
		{},                                       // nothing set
		{Duration: "100d", Fraction: 0.5},        // two forms
		{Duration: "100d", NotAfter: "2031-..."}, // two forms
		{Fraction: 2},                            // out of range
		{Duration: "soon"},                       // unparseable
		{NotBefore: "yesterday"},                 // unparseable
	} {
		cfg := bad
		if err := cfg.validate(); err == nil {
			t.Errorf("expected an error for %+v", bad)
		}
	}
}

func TestEncodeValue(t *testing.T) {
	cases := []struct {
		enc, value string
		wantTag    int
	}{
		{"utf8", "hello", asn1.TagUTF8String},
		{"", "hello", asn1.TagUTF8String}, // default
		{"ia5", "hello", asn1.TagIA5String},
		{"printable", "HELLO", asn1.TagPrintableString},
		{"oid", "1.2.3.4", asn1.TagOID},
		{"int", "-42", asn1.TagInteger},
		{"bool", "true", asn1.TagBoolean},
		{"null", "", asn1.TagNull},
		{"octet-string", "de:ad", asn1.TagOctetString},
		{"bit-string", "dead", asn1.TagBitString},
		{"der-hex", "0c0568656c6c6f", asn1.TagUTF8String},
		{"der-base64", "DAVoZWxsbw==", asn1.TagUTF8String},
	}
	for _, tc := range cases {
		t.Run(tc.enc+"/"+tc.value, func(t *testing.T) {
			der, err := EncodeValue(tc.enc, tc.value)
			if err != nil {
				t.Fatalf("EncodeValue(%q, %q): %v", tc.enc, tc.value, err)
			}
			var probe asn1.RawValue
			rest, err := asn1.Unmarshal(der, &probe)
			if err != nil {
				t.Fatalf("result is not valid DER: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("result has %d trailing bytes", len(rest))
			}
			if probe.Tag != tc.wantTag {
				t.Errorf("tag = %d, want %d", probe.Tag, tc.wantTag)
			}
		})
	}

	for _, bad := range [][2]string{
		{"utf8", ""},            // empty value
		{"hex", "zz"},           // bad hex
		{"der-hex", "0c05"},     // truncated DER
		{"der-hex", "05000500"}, // trailing element
		{"der-base64", "!!!"},   // bad base64
		{"int", "lots"},         // bad integer
		{"bool", "maybe"},       // bad boolean
		{"oid", "7"},            // single-arc OID
		{"nope", "x"},           // unknown encoding
	} {
		if _, err := EncodeValue(bad[0], bad[1]); err == nil {
			t.Errorf("expected an error for EncodeValue(%q, %q)", bad[0], bad[1])
		}
	}
}

// TestDuplicateOIDRejected guards the one way the custom escape hatch can
// produce an unparseable certificate: two extensions with the same OID, which
// RFC 5280 forbids and crypto/x509 would emit anyway.
func TestDuplicateOIDRejected(t *testing.T) {
	_, err := (&Config{
		MustStaple: true,
		Custom:     []CustomExtension{{OID: pki.OIDTLSFeature.String(), Encoding: "der-hex", Value: "0500"}},
	}).Build()
	if err == nil {
		t.Fatal("expected an error for a custom extension duplicating tlsfeature")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("error should say the extension is configured twice, got %v", err)
	}
}

func TestInvalidConfigsRejected(t *testing.T) {
	cases := map[string]*Config{
		"bad custom OID":        {Custom: []CustomExtension{{OID: "nope", Value: "x"}}},
		"bad SAN IP":            {SubjectAltName: &GeneralNamesConfig{IP: []string{"299.0.0.1"}}},
		"bad SAN DN":            {SubjectAltName: &GeneralNamesConfig{DirNames: []string{"XX=1"}}},
		"bad registered id":     {SubjectAltName: &GeneralNamesConfig{RegisteredIDs: []string{"7"}}},
		"empty SAN":             {SubjectAltName: &GeneralNamesConfig{Critical: true}},
		"bad netscape type":     {NetscapeCertType: []string{"webserver"}},
		"bad subject key id":    {SubjectKeyID: "not-hex"},
		"bad directory attr":    {SubjectDirectoryAttributes: []AttributeConfig{{OID: "1.2.3", Values: nil}}},
		"bad pkup":              {PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{}},
		"bad otherName OID":     {SubjectAltName: &GeneralNamesConfig{OtherNames: []OtherNameConfig{{OID: "x", Value: "y"}}}},
		"bad otherName value":   {SubjectAltName: &GeneralNamesConfig{OtherNames: []OtherNameConfig{{OID: "1.2.3", Encoding: "int", Value: "y"}}}},
		"bad directory attr v":  {SubjectDirectoryAttributes: []AttributeConfig{{OID: "1.2.3", Encoding: "int", Values: []string{"x"}}}},
		"empty SAN after trim":  {SubjectAltName: &GeneralNamesConfig{DNS: []string{"   "}}},
		"empty custom der":      {Custom: []CustomExtension{{OID: "1.2.3", Encoding: "der-hex", Value: ""}}},
		"inhibit any negative":  {InhibitAnyPolicy: intp(-1)},
		"empty netscape commnt": {NetscapeComment: " "},
	}
	for name, cfg := range cases {
		// "empty netscape commnt" trims to nothing, which IsZero treats as absent
		// and Build therefore ignores; assert that rather than an error.
		if name == "empty netscape commnt" {
			if !cfg.IsZero() {
				t.Errorf("%s: a whitespace-only comment should read as unset", name)
			}
			continue
		}
		if _, err := cfg.Build(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestBlankListEntriesAreDropped keeps a console form honest: an empty textarea
// posts blank entries, and those must read as "nothing configured" rather than
// failing the request or encoding an empty GeneralName.
func TestBlankListEntriesAreDropped(t *testing.T) {
	built, err := (&Config{
		CRLDistributionPoints: []string{"  ", ""},
		OCSPServers:           []string{""},
		CAIssuers:             []string{" "},
		CARepositories:        []string{""},
		FreshestCRL:           []string{"   "},
	}).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(built.CRLDistributionPoints) != 0 || len(built.OCSPServers) != 0 || len(built.CAIssuers) != 0 {
		t.Errorf("blank entries survived: %+v", built)
	}
	if len(built.Extensions) != 0 {
		t.Errorf("blank entries produced %d extensions", len(built.Extensions))
	}
}

func intp(v int) *int { return &v }

// TestEKUCatalogue checks every catalogued name resolves to a syntactically
// valid OID and that no two names share one, so the table cannot silently rot.
func TestEKUCatalogue(t *testing.T) {
	seen := map[string]string{}
	for name, oid := range ExtKeyUsageOIDs {
		if len(oid) < 2 {
			t.Errorf("%s resolves to the invalid OID %v", name, oid)
		}
		if _, err := asn1.Marshal(oid); err != nil {
			t.Errorf("%s resolves to an unencodable OID %v: %v", name, oid, err)
		}
		if prev, dup := seen[oid.String()]; dup {
			t.Errorf("%s and %s both resolve to %s", prev, name, oid)
		}
		seen[oid.String()] = name
	}
	if len(ExtKeyUsageOIDs) < 40 {
		t.Errorf("the EKU catalogue has shrunk to %d entries", len(ExtKeyUsageOIDs))
	}
}
