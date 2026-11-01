package celpolicy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Tests for the certificate-side facts. These derive from the to-be-signed
// template, which is what makes a rule true of the certificate rather than of
// one surface's request JSON — so the tests are about faithfulness: every fact a
// rule can read must be the fact the certificate would carry.

func TestFromLeafRequestCarriesEverySANType(t *testing.T) {
	base := pki.LeafCertRequest{
		Subject: pkix.Name{
			CommonName:         "www.example.com",
			Organization:       []string{"Acme", "Acme Inc"},
			OrganizationalUnit: []string{"PKI"},
			Country:            []string{"DE"},
			Locality:           []string{"Berlin"},
			Province:           []string{"BE"},
			StreetAddress:      []string{"Somestreet 1"},
			PostalCode:         []string{"10115"},
			SerialNumber:       "SN-1",
		},
		DNSNames:       []string{"www.example.com", "*.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.1.2.3"), net.ParseIP("2001:db8::1")},
		EmailAddresses: []string{"ops@example.com"},
		URIs:           []string{"spiffe://acme/ns/payments/sa/api"},
		UPNs:           []string{"user@CORP.EXAMPLE.COM"},
		Serial:         big.NewInt(1234567890),
	}
	got := FromLeafRequest(base)

	if got.Subject.CommonName != "www.example.com" {
		t.Errorf("common_name = %q", got.Subject.CommonName)
	}
	if len(got.Subject.Organization) != 2 || got.Subject.OrganizationalUnit[0] != "PKI" {
		t.Errorf("subject attributes lost: %+v", got.Subject)
	}
	if got.Subject.Country[0] != "DE" || got.Subject.Locality[0] != "Berlin" ||
		got.Subject.Province[0] != "BE" || got.Subject.StreetAddress[0] != "Somestreet 1" ||
		got.Subject.PostalCode[0] != "10115" || got.Subject.SerialNumber != "SN-1" {
		t.Errorf("subject attributes lost: %+v", got.Subject)
	}
	if got.Subject.DN == "" {
		t.Error("the RFC 2253 subject form is empty")
	}
	if len(got.DNSNames) != 2 || len(got.EmailAddresses) != 1 || len(got.URIs) != 1 || len(got.UPNs) != 1 {
		t.Errorf("SAN sets lost entries: %+v", got)
	}
	if len(got.IPAddresses) != 2 || got.IPAddresses[0] != "10.1.2.3" {
		t.Errorf("ip_addresses = %v, want textual form", got.IPAddresses)
	}
	if got.SANCount != 7 {
		t.Errorf("san_count = %d, want 7 (2 DNS + 2 IP + 1 email + 1 URI + 1 UPN)", got.SANCount)
	}
	if !got.Wildcard {
		t.Error("wildcard = false for a request carrying *.example.com")
	}
	if got.Serial != "1234567890" {
		t.Errorf("serial = %q", got.Serial)
	}
	if got.MaxPathLen != -1 {
		t.Errorf("max_path_len = %d, want -1 when the request sets none", got.MaxPathLen)
	}
	// The IP SANs must be usable by the network library, which is the point of
	// rendering them as strings.
	in := Input{Request: got}
	if d := Shared().Evaluate([]Rule{rule("ip", `cidr("10.0.0.0/8").containsIP(request.ip_addresses[0])`)}, in); !d.Allowed {
		t.Errorf("the rendered IP SAN is not parseable by cidr().containsIP(): %+v", d.Violations)
	}
}

func TestWildcardDetection(t *testing.T) {
	cases := map[string]bool{
		"*.example.com":   true,
		"www.example.com": false,
		"*":               false, // a bare star is not a wildcard DNS name
		"a.*.example.com": false, // not a leading-label wildcard
	}
	for name, want := range cases {
		got := FromLeafRequest(pki.LeafCertRequest{DNSNames: []string{name}})
		if got.Wildcard != want {
			t.Errorf("%q: wildcard = %v, want %v", name, got.Wildcard, want)
		}
	}
}

// TestValidityDaysCountsWholeDays pins the arithmetic a lifetime ceiling is
// written against. It truncates, which is what ca.durationDays does for the
// preview response and the API's validity_days — and agreement there matters
// more than precision, because a template's notBefore is backdated by a few
// minutes of clock skew: with rounding-up, a rule written `validity_days <= 90`
// would refuse the very 90-day request the profile was configured to allow. An
// operator who needs the exact window compares request.validity, a duration.
func TestValidityDaysCountsWholeDays(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		window time.Duration
		want   int
	}{
		{24 * time.Hour, 1},
		{90 * 24 * time.Hour, 90},
		{90*24*time.Hour + 5*time.Minute, 90}, // the clock-skew backdating
		{90*24*time.Hour - time.Minute, 89},
		{time.Hour, 0}, // a sub-day certificate
		{0, 0},
	}
	for _, c := range cases {
		got := FromLeafRequest(pki.LeafCertRequest{NotBefore: now, NotAfter: now.Add(c.window)})
		if got.ValidityDays != c.want {
			t.Errorf("window %v: validity_days = %d, want %d", c.window, got.ValidityDays, c.want)
		}
		if c.window > 0 && got.Validity != c.window {
			t.Errorf("window %v: validity = %v", c.window, got.Validity)
		}
	}
	// A zero/reversed window reports nothing rather than a negative lifetime.
	got := FromLeafRequest(pki.LeafCertRequest{NotBefore: now, NotAfter: now.Add(-time.Hour)})
	if got.Validity != 0 || got.ValidityDays != 0 {
		t.Errorf("a reversed window produced validity %v / %d days", got.Validity, got.ValidityDays)
	}
}

func TestKeyUsageNamesAreTheProfileVocabulary(t *testing.T) {
	base := pki.LeafCertRequest{
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	got := FromLeafRequest(base)
	if len(got.KeyUsages) != 2 {
		t.Fatalf("key_usages = %v", got.KeyUsages)
	}
	// Sorted, so a rule, an audit record and a preview never disagree about order.
	if got.KeyUsages[0] != "digitalSignature" || got.KeyUsages[1] != "keyEncipherment" {
		t.Errorf("key_usages = %v, want the sorted profile vocabulary", got.KeyUsages)
	}
	// EKU order is the profile's, because the certificate will carry that order.
	if got.ExtKeyUsages[0] != "serverAuth" || got.ExtKeyUsages[1] != "clientAuth" {
		t.Errorf("ext_key_usages = %v, want the profile's order", got.ExtKeyUsages)
	}
	// Every name must round-trip through the forward map the profiles are written
	// against, or a rule would be comparing against a vocabulary that does not
	// exist.
	for _, n := range got.KeyUsages {
		if _, ok := pki.X509KeyUsageFromString[n]; !ok {
			t.Errorf("key usage %q is not a name a profile can be written with", n)
		}
	}
	for _, n := range got.ExtKeyUsages {
		if _, ok := pki.X509ExtKeyUsageFromString[n]; !ok {
			t.Errorf("ext key usage %q is not a name a profile can be written with", n)
		}
	}
	if len(FromLeafRequest(pki.LeafCertRequest{}).KeyUsages) != 0 {
		t.Error("an empty bitmask produced usage names")
	}
}

// TestUnnamedEKUIsVisible: an EKU outside this PKI's vocabulary must be exposed,
// not dropped. For a restriction engine, silently hiding an extended key usage
// is the dangerous direction.
func TestUnnamedEKUIsVisible(t *testing.T) {
	got := FromLeafRequest(pki.LeafCertRequest{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny, x509.ExtKeyUsageIPSECTunnel},
	})
	if len(got.ExtKeyUsages) != 2 {
		t.Fatalf("ext_key_usages = %v; an unnamed EKU was dropped", got.ExtKeyUsages)
	}
	if got.ExtKeyUsages[0] != "any" || got.ExtKeyUsages[1] != "ipsecTunnel" {
		t.Errorf("ext_key_usages = %v", got.ExtKeyUsages)
	}
}

func TestKeyInfoDescribesEveryKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		pub   interface{}
		alg   string
		size  int
		curve string
	}{
		{"rsa", rsaKey.Public(), "RSA", 2048, ""},
		{"ecdsa", ecKey.Public(), "ECDSA", 384, "P-384"},
		{"ed25519", edPub, "Ed25519", 256, ""},
	}
	for _, c := range cases {
		got := FromLeafRequest(pki.LeafCertRequest{PublicKey: c.pub}).Key
		if got.Algorithm != c.alg || got.Size != c.size || got.Curve != c.curve {
			t.Errorf("%s: key = %+v, want %s/%d/%q", c.name, got, c.alg, c.size, c.curve)
		}
		want, err := keycheck.Fingerprint(c.pub)
		if err != nil {
			t.Fatal(err)
		}
		if got.Fingerprint != want {
			t.Errorf("%s: fingerprint = %q, want the SPKI fingerprint %q the blocklist uses", c.name, got.Fingerprint, want)
		}
	}

	// An absent or unrecognized key reads as "unknown" with a zero size, so a
	// minimum-strength rule refuses it rather than passing it.
	none := FromLeafRequest(pki.LeafCertRequest{}).Key
	if none.Algorithm != "unknown" || none.Size != 0 {
		t.Errorf("a missing key reads as %+v", none)
	}
	in := Input{Request: FromLeafRequest(pki.LeafCertRequest{})}
	d := Shared().Evaluate([]Rule{rule("strength", `request.key.size >= 2048`)}, in)
	if d.Allowed {
		t.Error("a minimum-strength rule passed a request with no subject key")
	}
}

func TestExtensionOIDsAreExposed(t *testing.T) {
	base := pki.LeafCertRequest{ExtraExtensions: []pkix.Extension{
		{Id: pki.OIDTLSFeature},
		{Id: []int{2, 5, 29, 32}},
	}}
	got := FromLeafRequest(base)
	if len(got.ExtensionOIDs) != 2 {
		t.Fatalf("extension_oids = %v", got.ExtensionOIDs)
	}
	if got.ExtensionOIDs[0] != "1.3.6.1.5.5.7.1.24" || got.ExtensionOIDs[1] != "2.5.29.32" {
		t.Errorf("extension_oids = %v, want dotted OIDs", got.ExtensionOIDs)
	}
	in := Input{Request: got}
	d := Shared().Evaluate([]Rule{rule("oids", `"2.5.29.32" in request.extension_oids`)}, in)
	if !d.Allowed {
		t.Errorf("a rule over extension_oids failed: %+v", d.Violations)
	}
}

func TestMaxPathLenIsReported(t *testing.T) {
	n := 2
	got := FromLeafRequest(pki.LeafCertRequest{IsCA: true, MaxPathLen: &n})
	if !got.IsCA || got.MaxPathLen != 2 {
		t.Errorf("is_ca/max_path_len = %v/%d", got.IsCA, got.MaxPathLen)
	}
}

func TestFromCSRDerivesTheSameFacts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://acme/ns/payments/sa/api")
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "www.example.com", Organization: []string{"Acme"}},
		DNSNames:       []string{"www.example.com", "*.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.1.2.3")},
		EmailAddresses: []string{"ops@example.com"},
		URIs:           []*url.URL{uri},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	got := FromCSR(csr)
	if got.Subject.CommonName != "www.example.com" || len(got.DNSNames) != 2 || !got.Wildcard {
		t.Errorf("CSR facts = %+v", got)
	}
	if got.SANCount != 5 {
		t.Errorf("san_count = %d, want 5 (2 DNS + 1 IP + 1 email + 1 URI)", got.SANCount)
	}
	if got.URIs[0] != "spiffe://acme/ns/payments/sa/api" {
		t.Errorf("uris = %v", got.URIs)
	}
	if got.Key.Algorithm != "ECDSA" || got.Key.Fingerprint == "" {
		t.Errorf("key = %+v", got.Key)
	}
	// A nil CSR must not panic and must not look like a permissive request.
	if n := FromCSR(nil); n.MaxPathLen != -1 || n.SANCount != 0 {
		t.Errorf("FromCSR(nil) = %+v", n)
	}
}

// TestActivationIsAlwaysComplete: every declared variable must be present, or
// an evaluation fails — which on this path is a denied certificate.
func TestActivationIsAlwaysComplete(t *testing.T) {
	act := Input{}.Activation()
	for _, v := range Vars() {
		if _, ok := act[v.Name()]; !ok {
			t.Errorf("the activation of a zero Input omits the declared variable %q", v.Name())
		}
	}
	// A zero input must still evaluate every shape of expression without erroring.
	for _, expr := range []string{
		`request.dns_names.size() == 0`,
		`request.subject.organization.size() == 0`,
		`!has(jwt.anything)`,
		`!has(body.anything)`,
		`!url.present && path == ""`,
		`!principal.authenticated && principal.roles.size() == 0`,
		`principal.tenant_roles.size() == 0`,
		`now > timestamp("2000-01-01T00:00:00Z")`,
		`request.source == "unknown" && request.operation == "issue"`,
	} {
		d := Shared().Evaluate([]Rule{rule("zero", expr)}, Input{})
		if !d.Allowed {
			detail := ""
			if len(d.Violations) > 0 {
				detail = d.Violations[0].Error
			}
			t.Errorf("%q over a zero input: %s", expr, detail)
		}
	}
}

// TestActivationFillsNowWhenUnset so a rule comparing against `now` cannot
// silently see the zero time.
func TestActivationFillsNowWhenUnset(t *testing.T) {
	act := Input{}.Activation()
	ts, ok := act[VarNow].(time.Time)
	if !ok {
		t.Fatalf("now is %T", act[VarNow])
	}
	if ts.IsZero() || time.Since(ts) > time.Minute {
		t.Errorf("now = %v, want the current time", ts)
	}
}

func TestPrincipalFromDerivesTenants(t *testing.T) {
	p := PrincipalFrom("sub", "a@b.io", "A", true, false,
		[]string{"issuer"}, []string{"g"}, map[string][]string{"z": {"admin"}, "a": {"issuer"}}, "entra")
	if !p.Authenticated {
		t.Error("a resolved principal must read as authenticated")
	}
	if len(p.Tenants) != 2 || p.Tenants[0] != "a" || p.Tenants[1] != "z" {
		t.Errorf("tenants = %v, want the sorted tenant-role keys", p.Tenants)
	}
	if p.AuthProvider != "entra" {
		t.Errorf("auth_provider = %q", p.AuthProvider)
	}
}

func TestURLFromNilRequest(t *testing.T) {
	if got := URLFrom(nil); got.Present {
		t.Errorf("URLFrom(nil) = %+v, want the zero (absent) URL", got)
	}
}
