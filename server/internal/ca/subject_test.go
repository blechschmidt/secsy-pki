package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/caext"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Task 222: the CA-creation request grew a full distinguished name and a full
// extension set. These are the HSM-free halves of that — subject mapping,
// algorithm selection, and the extension merge that stamps a CACertRequest —
// tested without generating a key.

// TestPKIXNameStrictMapsEveryAttribute checks each CASubject field reaches the
// DN, including the two that have to travel through ExtraNames because
// pkix.Name has no field for them.
func TestPKIXNameStrictMapsEveryAttribute(t *testing.T) {
	name, err := PKIXNameStrict(models.CASubject{
		CommonName:         "Example Root CA",
		Organization:       "Example Org",
		OrganizationalUnit: "PKI",
		Country:            "DE",
		Province:           "Hamburg",
		Locality:           "Hamburg",
		SerialNumber:       "HRB 12345",
		Street:             "Hafenstrasse 1",
		PostalCode:         "20457",
		DomainComponents:   []string{"com", "example"},
		EmailAddress:       "pki@example.test",
		ExtraNames: []models.CASubjectAttribute{
			{Type: "organizationIdentifier", Value: "VATDE-123456789"},
			{Type: "businessCategory", Value: "Private Organization"},
			{Type: "2.5.4.12", Value: "Root Authority"},
			{Type: "jurisdictionC", Value: "DE"},
		},
	})
	if err != nil {
		t.Fatalf("PKIXNameStrict: %v", err)
	}

	if name.CommonName != "Example Root CA" || name.SerialNumber != "HRB 12345" {
		t.Errorf("CN/serialNumber = %q/%q", name.CommonName, name.SerialNumber)
	}
	for field, got := range map[string][]string{
		"O": name.Organization, "OU": name.OrganizationalUnit, "C": name.Country,
		"ST": name.Province, "L": name.Locality,
		"street": name.StreetAddress, "postalCode": name.PostalCode,
	} {
		if len(got) != 1 || got[0] == "" {
			t.Errorf("subject %s = %v, want one value", field, got)
		}
	}

	// ExtraNames carries the two IA5String-defined attributes and the four
	// generic ones, in the order given.
	wantTypes := []string{
		"0.9.2342.19200300.100.1.25", "0.9.2342.19200300.100.1.25", // dc, dc
		"1.2.840.113549.1.9.1",     // email
		"2.5.4.97",                 // organizationIdentifier
		"2.5.4.15",                 // businessCategory
		"2.5.4.12",                 // title, by OID
		"1.3.6.1.4.1.311.60.2.1.3", // jurisdictionC
	}
	if len(name.ExtraNames) != len(wantTypes) {
		t.Fatalf("ExtraNames = %d entries, want %d: %+v", len(name.ExtraNames), len(wantTypes), name.ExtraNames)
	}
	for i, want := range wantTypes {
		if got := name.ExtraNames[i].Type.String(); got != want {
			t.Errorf("ExtraNames[%d].Type = %s, want %s", i, got, want)
		}
	}

	// domainComponent and emailAddress must be IA5String, which is how they are
	// defined and what strict DN-matching relying parties expect. The other
	// attributes stay plain strings so pkix picks PrintableString/UTF8String.
	for _, i := range []int{0, 1, 2} {
		raw, ok := name.ExtraNames[i].Value.(asn1.RawValue)
		if !ok {
			t.Errorf("ExtraNames[%d] value is %T, want an IA5String RawValue", i, name.ExtraNames[i].Value)
			continue
		}
		if raw.Tag != asn1.TagIA5String {
			t.Errorf("ExtraNames[%d] tag = %d, want IA5String (%d)", i, raw.Tag, asn1.TagIA5String)
		}
	}
	if _, isRaw := name.ExtraNames[3].Value.(asn1.RawValue); isRaw {
		t.Error("organizationIdentifier should be a plain string, not a pinned encoding")
	}
}

// TestPKIXNameStrictRejectsUnknownAttributes is the behaviour difference that
// matters between the two mappers: a CA whose DN is not the one that was asked
// for is worse than a failed request, so the strict form refuses rather than
// silently dropping.
func TestPKIXNameStrictRejectsUnknownAttributes(t *testing.T) {
	for _, bad := range []models.CASubjectAttribute{
		{Type: "notAnAttribute", Value: "v"},
		{Type: "", Value: "v"},
		{Type: "7", Value: "v"}, // a single-arc "OID"
		{Type: "CN", Value: " "},
	} {
		subj := models.CASubject{CommonName: "x", ExtraNames: []models.CASubjectAttribute{bad}}
		if _, err := PKIXNameStrict(subj); err == nil {
			t.Errorf("PKIXNameStrict accepted %+v", bad)
		}
		// The lenient mapper drops it and keeps going, which is what its
		// many literal-subject call sites need.
		if got := PKIXName(subj); got.CommonName != "x" || len(got.ExtraNames) != 0 {
			t.Errorf("PKIXName(%+v) = %+v, want the attribute dropped", bad, got)
		}
	}
}

func TestNormalizeCertAlgorithm(t *testing.T) {
	for in, want := range map[string]CertAlgorithm{
		"": AlgClassical, "classical": AlgClassical, "ECDSA": AlgClassical,
		"pqc": AlgPQC, "ML-DSA": AlgPQC, "post-quantum": AlgPQC,
		"hybrid": AlgHybrid, "catalyst": AlgHybrid, " Composite ": AlgHybrid,
	} {
		got, err := NormalizeCertAlgorithm(in)
		if err != nil {
			t.Errorf("NormalizeCertAlgorithm(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeCertAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NormalizeCertAlgorithm("quantum-ish"); err == nil {
		t.Error("expected an error for an unknown algorithm")
	}
}

// TestApplyCAExtensionsMerges checks the one place the three extension sources
// meet: the caller's pre-seeded extensions (rotation and cross-signing carry
// some forward), the name-constraint/policy packages, and internal/caext.
func TestApplyCAExtensionsMerges(t *testing.T) {
	notBefore := time.Now().Truncate(time.Second)
	req := pki.CACertRequest{
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(365 * 24 * time.Hour),
		// A pre-seeded extension, as the rotation path supplies.
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: []byte{0x05, 0x00}}},
		// A pinned SKI, as cross-signing supplies.
		SubjectKeyID: []byte{1, 2, 3},
	}
	nc, err := nameconstraints.Config{Permitted: nameconstraints.SubtreeConfig{DNS: []string{"example.test"}}}.Build()
	if err != nil {
		t.Fatalf("building name constraints: %v", err)
	}
	pol, err := certpolicy.PolicyConfig{OIDs: []string{"1.3.6.1.4.1.99999.1.1"}}.Build()
	if err != nil {
		t.Fatalf("building policies: %v", err)
	}
	cfg := &caext.Config{
		KeyUsages:             []string{"certSign", "crlSign"},
		OCSPServers:           []string{"http://ocsp.example.test/"},
		MustStaple:            true,
		PrivateKeyUsagePeriod: &caext.PrivateKeyUsagePeriodConfig{Fraction: 0.5},
		SubjectKeyID:          "aabb",
	}
	if err := applyCAExtensions(&req, nc, pol, cfg); err != nil {
		t.Fatalf("applyCAExtensions: %v", err)
	}

	if req.KeyUsage == 0 {
		t.Error("key usage was not applied")
	}
	if len(req.OCSPServer) != 1 {
		t.Errorf("OCSPServer = %v", req.OCSPServer)
	}
	// A caller-pinned SKI wins: cross-signing has to reproduce the original.
	if string(req.SubjectKeyID) != "\x01\x02\x03" {
		t.Errorf("subject key id = %x, want the caller's", req.SubjectKeyID)
	}
	present := map[string]bool{}
	for _, e := range req.ExtraExtensions {
		present[e.Id.String()] = true
	}
	for _, oid := range []string{
		"1.3.6.1.4.1.99999.1",                 // the caller's
		"2.5.29.30",                           // name constraints
		"2.5.29.32",                           // certificate policies
		"1.3.6.1.5.5.7.1.24",                  // tlsfeature, from caext
		pki.OIDPrivateKeyUsagePeriod.String(), // resolved against the validity
	} {
		if !present[oid] {
			t.Errorf("merged extensions are missing %s", oid)
		}
	}

	// A configured extension that duplicates one the caller pre-seeded is an
	// error rather than a second copy, which RFC 5280 §4.2 forbids.
	dup := pki.CACertRequest{
		NotBefore:       notBefore,
		NotAfter:        notBefore.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: pki.OIDTLSFeature, Value: []byte{0x05, 0x00}}},
	}
	err = applyCAExtensions(&dup, nameconstraints.Constraints{}, certpolicy.Policies{}, &caext.Config{MustStaple: true})
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate extension error = %v, want one naming the collision", err)
	}

	// A nil configuration is the untouched path and must change nothing but the
	// default key usage.
	plain := pki.CACertRequest{NotBefore: notBefore, NotAfter: notBefore.Add(time.Hour)}
	if err := applyCAExtensions(&plain, nameconstraints.Constraints{}, certpolicy.Policies{}, nil); err != nil {
		t.Fatalf("applyCAExtensions(nil): %v", err)
	}
	if len(plain.ExtraExtensions) != 0 {
		t.Errorf("a nil configuration produced %d extension(s)", len(plain.ExtraExtensions))
	}
}

// TestCACSRExtensionsOmitsTheUsagePeriod pins the one deliberate difference
// between the certificate and the CSR paths: a private-key usage period is
// relative to a validity window only the external parent chooses, so it is not
// requested.
func TestCACSRExtensionsOmitsTheUsagePeriod(t *testing.T) {
	nc, _ := nameconstraints.Config{Permitted: nameconstraints.SubtreeConfig{DNS: []string{"example.test"}}}.Build()
	got, err := caCSRExtensions(nc, certpolicy.Policies{}, &caext.Config{
		ExtKeyUsages:          []string{"serverAuth"},
		CARepositories:        []string{"http://pki.example.test/certs/"},
		PrivateKeyUsagePeriod: &caext.PrivateKeyUsagePeriodConfig{Duration: "180d"},
	})
	if err != nil {
		t.Fatalf("caCSRExtensions: %v", err)
	}
	present := map[string]bool{}
	for _, e := range got.ExtraExtensions {
		present[e.Id.String()] = true
	}
	for _, oid := range []string{"2.5.29.37", "1.3.6.1.5.5.7.1.11", "2.5.29.30"} {
		if !present[oid] {
			t.Errorf("CSR extensions are missing %s", oid)
		}
	}
	if present[pki.OIDPrivateKeyUsagePeriod.String()] {
		t.Error("the CSR should not request a privateKeyUsagePeriod")
	}
	if got.KeyUsage == 0 {
		t.Error("the CSR request carries no key usage")
	}

	if _, err := caCSRExtensions(nameconstraints.Constraints{}, certpolicy.Policies{},
		&caext.Config{KeyUsages: []string{"digitalSignature"}}); err == nil {
		t.Error("expected an error for a CA key usage set without certSign")
	}
}
